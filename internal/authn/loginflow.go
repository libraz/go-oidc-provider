package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/risk"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// LoginFlowSpec is the public-API LoginFlow shape the compiler
// consumes. The internal package cannot import op/, so the wiring
// layer (op/op.go:buildOrchestrator) re-projects the public op.LoginFlow
// onto this struct before invoking [CompileLoginFlow].
//
// LoginFlowSpec is intentionally a pure data carrier: it carries no
// behaviour of its own. The compiler walks the slice, validates the
// declared [LoginFlowStep] entries, and produces a [CompiledLoginFlow]
// the orchestrator drives at runtime.
type LoginFlowSpec struct {
	// Primary is the first step the orchestrator runs. MUST be non-nil
	// (the compiler rejects a nil Primary).
	Primary LoginFlowStep

	// Rules is the ordered list of conditional follow-up steps.
	Rules []LoginFlowRule

	// Decider, when non-nil, is consulted on every evaluation pass.
	Decider LoginFlowDecider

	// Risk, when non-nil, is invoked once at chain start and the score
	// is cached on the orchestrator's [State.RiskScoreCached].
	Risk RiskAssessor
}

// LoginFlowStep is the minimum surface the orchestrator needs from a
// public [op.Step] value to drive it. The wiring layer projects the
// concrete public types (PrimaryPassword, ExternalStep, …) onto this
// shape so internal/authn does not import op/.
type LoginFlowStep struct {
	// Kind is the stable identifier the public StepKind exposes. Used
	// for dedup against [State.CompletedStepKinds].
	Kind string

	// Authenticator is the resolved [Authenticator] the orchestrator
	// drives at runtime. The compiler synthesises this for built-in
	// Steps (deferred — see notes on [ErrBuiltinStepNotWired]) and
	// extracts it verbatim from an [op.ExternalStep] for the user-
	// defined path. MUST be non-nil after a successful compile.
	Authenticator Authenticator

	// IsCaptcha distinguishes the captcha [op.Step] from factor-shaped
	// Steps. Captcha events do NOT enter [State.Factors] — captcha is
	// out-of-band from the brute-force / amr-history feed.
	IsCaptcha bool
}

// LoginFlowRule is the projection of a public [op.Rule] for the
// compiler. The When predicate operates on [LoginFlowContext] (the
// projection of [op.LoginContext]).
type LoginFlowRule struct {
	When func(ctx LoginFlowContext) bool
	Then LoginFlowStep
}

// LoginFlowDecider is the projection of [op.Decider]. The compiler
// keeps the value verbatim; the orchestrator dispatches on the
// [LoginFlowDecision] sealed sum returned by Decide.
type LoginFlowDecider interface {
	Decide(ctx context.Context, lc LoginFlowContext) LoginFlowDecision
}

// LoginFlowDecision is the sealed sum the public [op.Decision] surface
// projects onto. The four constructors below mirror the four exported
// decision types in op/.
type LoginFlowDecision interface {
	isLoginFlowDecision()
}

// LoginFlowAllow short-circuits the loop with a successful login.
type LoginFlowAllow struct{}

func (LoginFlowAllow) isLoginFlowDecision() {}

// LoginFlowPass defers to the rule list.
type LoginFlowPass struct{}

func (LoginFlowPass) isLoginFlowDecision() {}

// LoginFlowRequire short-circuits the loop with a step the orchestrator
// MUST run before the next pass.
type LoginFlowRequire struct {
	Step LoginFlowStep
}

func (LoginFlowRequire) isLoginFlowDecision() {}

// LoginFlowDeny short-circuits the loop with a failed login. The
// orchestrator translates the result to [ErrRiskDenied] (the existing
// access_denied path) and records Reason in the audit log.
type LoginFlowDeny struct {
	Reason string
}

func (LoginFlowDeny) isLoginFlowDecision() {}

// LoginFlowContext is the projection of [op.LoginContext] every rule
// predicate / decider sees. The orchestrator rebuilds the value on
// every evaluation pass so a rule that fires advances
// CompletedStepKinds before the next predicate runs.
type LoginFlowContext struct {
	Subject         string
	ClientID        string
	RequestedScopes []string
	FailedAttempts  int
	RiskScore       RiskScore
	NewDevice       bool
	CompletedKinds  []string
	ACRValues       []string
	RemoteIP        string
	UserAgent       string
	AcceptLanguage  string
}

// CompiledLoginFlow is the orchestrator's runtime view of an
// [op.LoginFlow]. The compiler rejects malformed flows at op.New time
// (nil Primary, duplicate Rule.Then.Kind(), Steps that wrap nil
// Authenticator, built-in Steps whose underlying primitive is not yet
// wired) so misconfigurations cannot reach the first request.
//
// Once compiled the structure is immutable; the orchestrator reads it
// concurrently across requests without locking.
type CompiledLoginFlow struct {
	primary  compiledStep
	rules    []compiledRule
	decider  LoginFlowDecider
	risk     RiskAssessor
	byKind   map[string]compiledStep
	byFactor map[FactorType]compiledStep
}

// compiledStep is the orchestrator-side view of a LoginFlowStep with
// the kind cached for fast dedup lookups.
type compiledStep struct {
	kind string
	auth Authenticator
	// factor is auth.Type() resolved once at compile time. It is the
	// join key between a [RiskOutcome.RequiredFactors] entry (a
	// FactorType) and the Step that can satisfy it — StepKind and
	// FactorType are separate namespaces, so the risk directive can
	// only be honoured through the authenticator's own type.
	factor    FactorType
	isCaptcha bool
}

// compiledRule pairs a predicate with the step the orchestrator runs
// when the predicate fires.
type compiledRule struct {
	when func(LoginFlowContext) bool
	then compiledStep
}

// ErrBuiltinStepNotWired is returned by [CompileLoginFlow] when a
// LoginFlow declares a built-in [op.Step] (PrimaryPassword,
// PrimaryPasskey, StepTOTP, StepEmailOTP, StepRecoveryCode,
// StepCaptcha) without the construction-time wiring those Steps
// require. The dependencies (TOTP encryption codec, passkey RP origin,
// hash adapter, …) are supplied by follow-up public-API options;
// until those land, embedders adopt the LoginFlow seam through
// [op.ExternalStep], which wraps an already-constructed
// [Authenticator].
var ErrBuiltinStepNotWired = errors.New("authn: built-in Step requires construction-time wiring not yet exposed; wrap your Authenticator in op.ExternalStep")

// CompileLoginFlow validates spec and returns the runtime structure
// the orchestrator drives. Validation order:
//
//  1. Primary != zero (its Authenticator non-nil after projection).
//  2. Every Rule.Then has a non-nil Authenticator.
//  3. No two rules share Then.Kind (dedup unit invariant).
//  4. Primary.Kind does not collide with any Rule.Then.Kind.
//  5. Captcha-shaped Steps (IsCaptcha) are NOT placed at Primary
//     (captcha is a challenge, not a primary credential).
//
// On success the compiler returns a *CompiledLoginFlow whose byKind
// index maps every declared StepKind to its [compiledStep]; the
// orchestrator's Decider.Require lookup uses it for O(1) routing. The
// parallel byFactor index maps each non-captcha step's [FactorType] to
// the same value so a [RiskOutcome.RequiredFactors] entry can be routed
// to the Step that satisfies it. Declaration order wins on a collision
// (two Steps wrapping the same factor type), matching the "first
// candidate wins" rule the legacy chain path applies.
func CompileLoginFlow(spec LoginFlowSpec) (*CompiledLoginFlow, error) {
	if spec.Primary.Authenticator == nil {
		return nil, errors.New("authn: LoginFlow.Primary is nil")
	}
	if spec.Primary.IsCaptcha {
		return nil, errors.New("authn: LoginFlow.Primary must not be a captcha step")
	}
	if spec.Primary.Kind == "" {
		return nil, errors.New("authn: LoginFlow.Primary.Kind is empty")
	}
	primary := compiledStep{
		kind:      spec.Primary.Kind,
		auth:      spec.Primary.Authenticator,
		factor:    spec.Primary.Authenticator.Type(),
		isCaptcha: spec.Primary.IsCaptcha,
	}
	byKind := map[string]compiledStep{primary.kind: primary}
	byFactor := map[FactorType]compiledStep{}
	indexFactor(byFactor, primary)
	rules := make([]compiledRule, 0, len(spec.Rules))
	for i, r := range spec.Rules {
		if r.Then.Authenticator == nil {
			return nil, fmt.Errorf("authn: LoginFlow.Rules[%d].Then is nil", i)
		}
		if r.Then.Kind == "" {
			return nil, fmt.Errorf("authn: LoginFlow.Rules[%d].Then.Kind is empty", i)
		}
		if _, dup := byKind[r.Then.Kind]; dup {
			return nil, fmt.Errorf("authn: LoginFlow duplicate StepKind %q", r.Then.Kind)
		}
		step := compiledStep{
			kind:      r.Then.Kind,
			auth:      r.Then.Authenticator,
			factor:    r.Then.Authenticator.Type(),
			isCaptcha: r.Then.IsCaptcha,
		}
		byKind[step.kind] = step
		indexFactor(byFactor, step)
		when := r.When
		if when == nil {
			when = func(LoginFlowContext) bool { return false }
		}
		rules = append(rules, compiledRule{when: when, then: step})
	}
	return &CompiledLoginFlow{
		primary:  primary,
		rules:    rules,
		decider:  spec.Decider,
		risk:     spec.Risk,
		byKind:   byKind,
		byFactor: byFactor,
	}, nil
}

// indexFactor records step under its [FactorType] unless the slot is
// already taken (first declaration wins) or the step is captcha-shaped.
// A captcha clears a bot challenge; it contributes no [Factor] and
// therefore can never satisfy a risk-required factor set.
func indexFactor(byFactor map[FactorType]compiledStep, step compiledStep) {
	if step.isCaptcha || step.factor == "" {
		return
	}
	if _, taken := byFactor[step.factor]; taken {
		return
	}
	byFactor[step.factor] = step
}

// containsString reports whether v is in haystack. Used by the
// orchestrator's CompletedStepKinds dedup; the typed wrapper exists
// solely to avoid importing slices for a one-line predicate.
func containsString(haystack []string, v string) bool {
	for _, s := range haystack {
		if s == v {
			return true
		}
	}
	return false
}

// recoverPredicate runs pred(lc) under a recover() so a panicking
// embedder predicate cannot crash the OP. A panic is logged at error
// with idx (the rule's position in the LoginFlow) and the predicate is
// treated as no-match. This mirrors the panic-recovery posture used
// for [LoginAttemptObserver] fan-out.
func recoverPredicate(logger *slog.Logger, idx int, pred func(LoginFlowContext) bool, lc LoginFlowContext) (matched bool) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("authn: rule predicate panicked",
				slog.Int("rule_index", idx),
				slog.Any("recovered", r),
			)
			matched = false
		}
	}()
	return pred(lc)
}

// recoverDecider runs decider.Decide(ctx, lc) under a recover() so a
// panicking embedder decider cannot crash the OP. A panic is logged at
// error and the call is treated as [LoginFlowPass] so the rule list
// drives the chain. Returning Pass on panic (rather than Deny) is the
// minimum-surprise default: a failed adaptive-auth lookup should fall
// through to declarative rules instead of denying every login.
func recoverDecider(ctx context.Context, logger *slog.Logger, decider LoginFlowDecider, lc LoginFlowContext) (decision LoginFlowDecision) { //nolint:ireturn,nolintlint // sealed-sum LoginFlowDecision is the contract; concrete dispatch happens at the call site.
	defer func() {
		if r := recover(); r != nil {
			logger.Error("authn: decider panicked",
				slog.Any("recovered", r),
			)
			decision = LoginFlowPass{}
		}
	}()
	return decider.Decide(ctx, lc)
}

// loginFlowContext rebuilds a [LoginFlowContext] from the orchestrator
// State plus the cached risk score. The function is deterministic on
// State, so a Tick that re-enters the loop after a sub-step completion
// sees the same lc shape — modulo the freshly-appended CompletedKind
// from the previous step.
//
// Every field the public [op.LoginContext] exposes is populated here.
// The same public value is also assembled by the ACR resolver from the
// terminal request, and a rule predicate cannot tell which face built
// the context it is reading, so a field left empty on one side is a
// predicate that silently behaves differently depending on where in the
// chain it runs.
func (o *Orchestrator) loginFlowContext(st State) LoginFlowContext {
	completed := append([]string(nil), st.CompletedStepKinds...)
	scopes := append([]string(nil), st.RequestedScopes...)
	acrValues := append([]string(nil), st.ACRValues...)
	return LoginFlowContext{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		RequestedScopes: scopes,
		FailedAttempts:  st.LastFailures,
		RiskScore:       st.RiskScoreCached,
		NewDevice:       st.NewDeviceCached,
		CompletedKinds:  completed,
		ACRValues:       acrValues,
		RemoteIP:        st.RemoteIPString(),
		UserAgent:       st.UserAgent,
		AcceptLanguage:  st.AcceptLanguage,
	}
}

// runRiskOnceForLoginFlow consults Risk at chain start when no step has
// completed yet, caches the score on st.RiskScoreCached and the
// required-factor set on st.RiskRequiredFactors, and returns whether the
// chain is denied. Subsequent calls during the same chain are no-ops;
// this is the §3.1 budget invariant ("Risk.Assess at most once per
// chain").
//
// A [RiskRequire] outcome that names factors is recorded rather than
// acted on here: the consult happens before Primary has even run, so the
// obligation has to survive until the chain would otherwise grant. See
// [Orchestrator.transitionToAfterAuthn] for where it is discharged.
//
// The mapping from [RiskOutcome] onto [State.RiskScoreCached]:
//
//   - [RiskOutcome.Score] non-zero — used verbatim. This is the path
//     an assessor takes to surface [RiskScoreMedium], which the
//     Decision-only fallback cannot reach.
//   - Score zero, Decision = [RiskAllow] — cached as [RiskScoreLow]
//     (a signal was observed but nothing actionable).
//   - Score zero, Decision = [RiskRequire] — cached as
//     [RiskScoreHigh] (the assessor recommends a stronger factor).
//   - Decision = [RiskDeny] — handled separately; the orchestrator
//     returns [ErrRiskDenied] without caching.
//
// Rule predicates `score >= threshold` see the cached value
// uniformly regardless of which path produced it.
func (o *Orchestrator) runRiskOnceForLoginFlow(ctx context.Context, st State, flow *CompiledLoginFlow) (State, bool, error) {
	if flow.risk == nil {
		return st, false, nil
	}
	if st.RiskScoreCached != RiskScoreNone {
		return st, false, nil
	}
	in := buildRiskInput(st, "")
	in.AuthTime = st.AuthTime
	res, err := risk.RunOnceForLoginFlow(ctx, wrapRiskAssessor(flow.risk), in)
	if err != nil {
		return st, false, err
	}
	if res.Denied {
		return st, true, nil
	}
	if res.Score != risk.ScoreNone {
		st.RiskScoreCached = riskScoreFromPkg(res.Score)
	}
	st.RiskRequiredFactors = factorTypesFromStrings(res.Required)
	st.NewDeviceCached = res.NewDevice
	return st, false, nil
}

// describeStepKind formats a step kind for log messages. Centralising
// the formatting keeps the audit shape consistent across rule /
// decider / dedup paths.
func describeStepKind(kind string) string {
	if kind == "" {
		return "<unknown>"
	}
	if strings.ContainsRune(kind, ' ') {
		return fmt.Sprintf("%q", kind)
	}
	return kind
}

// advanceLoginFlow drives the [Config.LoginFlow] path for one
// orchestrator pass. The function is the LoginFlow analogue of
// [advanceAuthn]: it picks the next step (Primary, Decider verdict, or
// rule match), emits the step's Begin Prompt with a freshly-issued
// StateRef tagged with the step's Kind, and returns. Subsequent
// submissions route back through [handleLoginFlowSubmission].
//
// State machine, in order:
//
//  1. Reject if Subject is unbound and CompletedStepKinds is empty —
//     means run Primary's Begin (subject-binding factor).
//  2. Run Risk once at chain start (cached on st.RiskScoreCached).
//  3. Captcha threshold gate: if [State.LastFailures] >= the legacy
//     [captchaFailureThreshold] AND a [Config.Captcha] verifier is
//     wired AND the user has not already cleared the challenge, emit
//     the captcha prompt before any factor runs. This path is
//     independent of [StepCaptcha]: a [LoginFlow] with no StepCaptcha
//     in its rules still gets the legacy after-N-failures captcha if a
//     CaptchaVerifier is configured.
//  4. Decider consult (when wired): Allow → grant, Deny → ErrRiskDenied,
//     Require{Step} → drive Step (looked up by kind), Pass → fall
//     through to rules.
//  5. Rules iteration (declaration order): first When → true && kind
//     not in CompletedStepKinds wins.
//  6. No rule matches → grant (transition to PhaseAfterAuthn), which
//     first discharges any pending risk step-up obligation.
func (o *Orchestrator) advanceLoginFlow(ctx context.Context, st State, now time.Time) (State, interaction.Step, error) {
	flow := o.cfg.LoginFlow
	if flow == nil {
		return st, interaction.Step{}, ErrInvalidStep
	}

	// Risk evaluation is one-shot per chain. We invoke it before
	// anything else so even Primary sees a populated RiskScoreCached.
	next, denied, err := o.runRiskOnceForLoginFlow(ctx, st, flow)
	if err != nil {
		return st, interaction.Step{}, err
	}
	if denied {
		return st, interaction.Step{}, ErrRiskDenied
	}
	st = next

	// Primary runs first (subject binding). The captcha threshold
	// gate fires before Primary the same way it fires before any
	// other factor — an after-N-failures captcha is independent of
	// the LoginFlow seam. We key the pre-Primary phase off
	// st.Subject (Primary populates it via appendFactor) rather
	// than CompletedStepKinds so a pre-Primary captcha that has
	// already cleared does not flip the chain into the post-Primary
	// rules pass before the credential factor has bound a subject.
	//
	// A Subject the chain did not bind itself is only allowed to
	// stand in for Primary when the request may be served from the
	// existing session. When [State.ReauthRequired] is set the HTTP
	// layer has already established that it may not (prompt=login,
	// max_age expiry, unsatisfied acr_values), so the decision falls
	// back to "has Primary actually completed during this attempt".
	if st.Subject == "" || (st.ReauthRequired && !containsString(st.CompletedStepKinds, flow.primary.kind)) {
		if o.captchaRequired(st) {
			return o.emitCaptchaPrompt(st, now)
		}
		if handled, ns, step, err := o.evalLoginFlowCaptchaRulesPrePrimary(ctx, st, flow, now); handled {
			return ns, step, err
		}
		return o.runLoginFlowStep(ctx, st, flow.primary, now)
	}

	// After Primary completes, build the LoginFlowContext fresh so
	// the predicates / decider see the latest CompletedStepKinds.
	lc := o.loginFlowContext(st)

	if flow.decider != nil {
		handled, ns, step, err := o.evalLoginFlowDecider(ctx, st, flow, lc, now)
		if handled {
			return ns, step, err
		}
		st = ns
	}

	if handled, ns, step, err := o.evalLoginFlowRules(ctx, st, flow, lc, now); handled {
		return ns, step, err
	}

	// No rule matched and Decider did not short-circuit → grant.
	return o.transitionToAfterAuthn(ctx, st, flow, now)
}

// evalLoginFlowDecider consults the Decider once and dispatches the
// returned [LoginFlowDecision]. The bool return reports whether the
// dispatcher loop should stop here: Allow / Deny / Require all stop;
// Pass (and Require for an already-completed kind) defer to rules.
// Split out so [advanceLoginFlow] stays under the gocognit ceiling.
func (o *Orchestrator) evalLoginFlowDecider(ctx context.Context, st State, flow *CompiledLoginFlow, lc LoginFlowContext, now time.Time) (bool, State, interaction.Step, error) {
	decision := recoverDecider(ctx, o.logger, flow.decider, lc)
	switch d := decision.(type) {
	case LoginFlowAllow:
		ns, step, err := o.transitionToAfterAuthn(ctx, st, flow, now)
		return true, ns, step, err
	case LoginFlowDeny:
		o.logger.Info("authn: LoginFlow denied",
			slog.String("reason", d.Reason),
			slog.String("subject", st.Subject),
			slog.String("client_id", st.ClientID),
		)
		return true, st, interaction.Step{}, ErrRiskDenied
	case LoginFlowRequire:
		step, ok := flow.byKind[d.Step.Kind]
		if !ok {
			o.logger.Error("authn: LoginFlow Decider.Require references unknown StepKind",
				slog.String("step_kind", describeStepKind(d.Step.Kind)),
			)
			return true, st, interaction.Step{}, ErrInvalidStep
		}
		if containsString(st.CompletedStepKinds, step.kind) {
			// Decider asked for a step already completed — fall
			// through to rules rather than spin on the same step.
			return false, st, interaction.Step{}, nil
		}
		if o.captchaRequired(st) && !step.isCaptcha {
			ns, sstep, err := o.emitCaptchaPrompt(st, now)
			return true, ns, sstep, err
		}
		ns, sstep, err := o.runLoginFlowStep(ctx, st, step, now)
		return true, ns, sstep, err
	case LoginFlowPass:
		return false, st, interaction.Step{}, nil
	default:
		return false, st, interaction.Step{}, nil
	}
}

// evalLoginFlowCaptchaRulesPrePrimary walks the rule list before
// Primary runs and fires the first not-yet-completed captcha-shaped
// rule whose predicate matches. This gives [RuleAfterFailedAttempts]
// (and other captcha-typed rules) a chance to interpose between a
// failed credential attempt and the next prompt — without it, a rule
// whose Then is a captcha Step never gets a chance to fire because
// rules are otherwise consulted only after Primary completes, which
// soft credential failures never reach.
//
// Only captcha-shaped Steps are eligible here. Factor-shaped rules
// must wait for Primary to complete (subject binding) before they can
// run, so the pre-Primary scan deliberately ignores them.
func (o *Orchestrator) evalLoginFlowCaptchaRulesPrePrimary(ctx context.Context, st State, flow *CompiledLoginFlow, now time.Time) (bool, State, interaction.Step, error) {
	lc := o.loginFlowContext(st)
	for i, r := range flow.rules {
		if !r.then.isCaptcha {
			continue
		}
		if containsString(st.CompletedStepKinds, r.then.kind) {
			continue
		}
		if !recoverPredicate(o.logger, i, r.when, lc) {
			continue
		}
		ns, step, err := o.runLoginFlowStep(ctx, st, r.then, now)
		return true, ns, step, err
	}
	return false, st, interaction.Step{}, nil
}

// loginFlowCaptchaPending reports whether a captcha challenge would
// interpose before the next factor prompt right now. It mirrors the
// captcha decision [advanceLoginFlow] makes — the built-in failure
// threshold ([captchaRequired]) plus any not-yet-completed captcha-shaped
// rule whose predicate currently matches — so the wrong-code retry
// shortcut in [handleLoginFlowSubmission] does not re-emit a factor's
// verify prompt when a challenge is due. When it returns true the caller
// falls through to the dispatcher, which emits the captcha.
func (o *Orchestrator) loginFlowCaptchaPending(st State, flow *CompiledLoginFlow) bool {
	if o.captchaRequired(st) {
		return true
	}
	lc := o.loginFlowContext(st)
	for i, r := range flow.rules {
		if !r.then.isCaptcha {
			continue
		}
		if containsString(st.CompletedStepKinds, r.then.kind) {
			continue
		}
		if recoverPredicate(o.logger, i, r.when, lc) {
			return true
		}
	}
	return false
}

// evalLoginFlowRules walks the compiled rule list in declaration
// order and dispatches the first matching, not-yet-completed step.
// A panic in an embedder-supplied predicate is recovered and treated
// as "does not match" so one bad rule cannot take down the flow.
func (o *Orchestrator) evalLoginFlowRules(ctx context.Context, st State, flow *CompiledLoginFlow, lc LoginFlowContext, now time.Time) (bool, State, interaction.Step, error) {
	for i, r := range flow.rules {
		if containsString(st.CompletedStepKinds, r.then.kind) {
			continue
		}
		if !recoverPredicate(o.logger, i, r.when, lc) {
			continue
		}
		if o.captchaRequired(st) && !r.then.isCaptcha {
			ns, step, err := o.emitCaptchaPrompt(st, now)
			return true, ns, step, err
		}
		ns, step, err := o.runLoginFlowStep(ctx, st, r.then, now)
		return true, ns, step, err
	}
	return false, st, interaction.Step{}, nil
}

// transitionToAfterAuthn moves the chain to PhaseAfterAuthn so the
// existing post-authn interaction queue (consent, KYC) runs. Returning
// a zero interaction.Step keeps the dispatcher loop driving forward.
//
// It is also the single choke point for the pending risk step-up
// obligation: every LoginFlow exit that grants authentication — the
// no-rule-matched fall-through and the Decider's Allow verdict alike —
// routes through here, so a [RiskRequire] outcome that named factors
// cannot be bypassed by an embedder policy that answers Allow first.
func (o *Orchestrator) transitionToAfterAuthn(ctx context.Context, st State, flow *CompiledLoginFlow, now time.Time) (State, interaction.Step, error) {
	if handled, ns, step, err := o.enforceRiskStepUp(ctx, st, flow, now); handled {
		return ns, step, err
	}
	st.Phase = PhaseAfterAuthn
	st.ActiveStepKind = ""
	return st, interaction.Step{}, nil
}

// enforceRiskStepUp discharges [State.RiskRequiredFactors] before the
// chain is allowed to leave PhaseAuthn. The bool return reports whether
// the caller must stop and return the triple: true when a step-up factor
// was interposed (or a captcha has to clear first), and true with an
// error when the demand cannot be met.
//
// Three outcomes:
//
//   - No demand, or a completed [Factor] already carries one of the
//     demanded types — not handled; the caller grants.
//   - A declared Step wraps an [Authenticator] of a demanded type and
//     has not run yet — that Step is driven, exactly as a matching
//     [LoginFlowRule] would have driven it.
//   - No declared Step can satisfy the demand —
//     [ErrNoEligibleAuthenticator], the same fail-closed sentinel the
//     legacy chain path returns when its risk-filtered candidate set
//     comes back empty. Granting instead would hand out a session at
//     the assurance the assessor just refused.
func (o *Orchestrator) enforceRiskStepUp(ctx context.Context, st State, flow *CompiledLoginFlow, now time.Time) (bool, State, interaction.Step, error) {
	if len(st.RiskRequiredFactors) == 0 || riskStepUpSatisfied(st) {
		return false, st, interaction.Step{}, nil
	}
	for _, want := range st.RiskRequiredFactors {
		step, ok := flow.byFactor[want]
		if !ok || containsString(st.CompletedStepKinds, step.kind) {
			continue
		}
		if o.captchaRequired(st) {
			ns, sstep, err := o.emitCaptchaPrompt(st, now)
			return true, ns, sstep, err
		}
		ns, sstep, err := o.runLoginFlowStep(ctx, st, step, now)
		return true, ns, sstep, err
	}
	o.logger.Error("authn: risk-required factor is not reachable in this LoginFlow",
		slog.String("required_factors", strings.Join(factorTypesToStrings(st.RiskRequiredFactors), " ")),
		slog.String("subject", st.Subject),
		slog.String("client_id", st.ClientID),
	)
	return true, st, interaction.Step{}, ErrNoEligibleAuthenticator
}

// riskStepUpSatisfied reports whether any factor recorded during this
// attempt carries one of the risk-demanded types. The set has OR
// semantics ([RiskOutcome.RequiredFactors]), so one match discharges the
// whole obligation.
func riskStepUpSatisfied(st State) bool {
	for _, f := range st.Factors {
		if containsFactor(st.RiskRequiredFactors, f.Type) {
			return true
		}
	}
	return false
}

// runLoginFlowStep drives step.auth.Begin for the supplied compiledStep
// and emits the prompt with a StateRef tagged tagLoginFlowPrefix +
// step.kind. The step's Authenticator may complete immediately (Result
// in Begin) — the function records that path through [appendFactor]
// and re-enters the dispatcher so the chain advances to the next
// pass.
func (o *Orchestrator) runLoginFlowStep(ctx context.Context, st State, step compiledStep, now time.Time) (State, interaction.Step, error) {
	begin, err := step.auth.Begin(ctx, BeginInput{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		AuthTime:        now,
		RequestedScopes: st.RequestedScopes,
		Client:          st.Client,
	})
	if err != nil {
		return st, interaction.Step{}, err
	}
	if begin.Prompt != nil {
		st.ActiveStepKind = step.kind
		st.FactorScratch = begin.Scratch
		next, emitted, perr := o.emitLoginFlowPrompt(st, step.kind, *begin.Prompt, now)
		if perr != nil {
			return st, interaction.Step{}, perr
		}
		return next, emitted, nil
	}
	if begin.Result == nil {
		return st, interaction.Step{}, ErrInvalidStep
	}
	if !step.isCaptcha {
		if rerr := guardAAL3RequiresUV(step.auth, *begin.Result); rerr != nil {
			return st, interaction.Step{}, rerr
		}
	}
	// Begin completed immediately — record and re-enter the
	// LoginFlow loop so the dispatcher sees the next pass without
	// dropping back through advanceOnce's transition guard.
	st = o.recordLoginFlowResult(ctx, st, step, *begin.Result, now)
	return o.advanceLoginFlow(ctx, st, now)
}

// emitLoginFlowPrompt issues a fresh StateRef tagged with the step's
// kind and returns the prompt for the SPA. The kind is appended
// verbatim so two distinct steps emit distinguishable signed payloads
// — a StateRef issued for one step can never be replayed into another.
func (o *Orchestrator) emitLoginFlowPrompt(st State, kind string, prompt interaction.Prompt, now time.Time) (State, interaction.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagLoginFlowPrefix+kind, st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, interaction.Step{}, err
	}
	prompt.StateRef = ref
	st = stampActiveInputs(st, prompt.Inputs)
	return st, interaction.Step{Prompt: &prompt}, nil
}

// recordLoginFlowResult folds a step's [interaction.Result] into st:
// for factor-shaped steps it appends a [Factor] (so [Aggregate]
// observes the AAL contribution and amr value), for captcha-shaped
// steps it flips [State.CaptchaPassed] without entering [State.Factors]
// — a captcha is a bot check, not an authentication factor, so it must
// not contribute to the AAL aggregate or the amr claim.
//
// In all cases the step's kind is appended to CompletedStepKinds for
// dedup, ActiveStepKind is cleared, and the FactorScratch slot is
// reset so a subsequent step does not inherit the previous step's
// scratch payload.
func (o *Orchestrator) recordLoginFlowResult(ctx context.Context, st State, step compiledStep, res interaction.Result, now time.Time) State {
	if step.isCaptcha {
		st.CaptchaPassed = true
		st.LastFailures = 0
	} else {
		st = o.appendFactor(st, step.auth, res)
		o.observeSuccess(ctx, st, now, step.auth.Type())
	}
	st.CompletedStepKinds = append(st.CompletedStepKinds, step.kind)
	st.ActiveStepKind = ""
	st.FactorScratch = nil
	return st
}

// handleLoginFlowSubmission dispatches a submission against the active
// LoginFlow step. The kind argument is the StateRef tag suffix the
// signer parsed off the inbound token; it MUST match
// [State.ActiveStepKind] or the submission is rejected as
// [ErrInvalidStateRef] (a stale token from an earlier step cannot
// drive the current one).
//
//nolint:gocognit,cyclop // submission dispatcher enumerates step / AAL / factor branches in flat shape; refactor would obscure flow ordering.
func (o *Orchestrator) handleLoginFlowSubmission(ctx context.Context, st State, in Input, kind string) (State, interaction.Step, error) {
	flow := o.cfg.LoginFlow
	if flow == nil || st.ActiveStepKind == "" || st.ActiveStepKind != kind {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	step, ok := flow.byKind[kind]
	if !ok {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	cont, err := step.auth.Continue(ctx, ContinueInput{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		AuthTime:        st.AuthTime,
		Submission:      *in.Submission,
		Scratch:         st.FactorScratch,
		RequestedScopes: st.RequestedScopes,
		RemoteIP:        st.RemoteIP,
	})
	if err != nil {
		// The same classification decides what is recorded and where the
		// chain goes, exactly as on the legacy-chain path. Captcha steps
		// record nothing either way — a bot check is out-of-band from
		// the credential feed — but they still follow the retry branch.
		verdict := classifyFactorError(err)
		if !step.isCaptcha {
			o.recordFactorFailure(ctx, st, in.Now, step.auth.Type(), verdict, err)
		}
		// Soft failures (wrong password, etc.) advance the failure
		// counter and re-emit the same factor's prompt so the SPA
		// can let the user retry. Hard failures (store outage,
		// codec misconfiguration) skip this branch and surface to
		// the HTTP layer as 5xx / 4xx unchanged.
		if verdict == credentialRejected {
			if !step.isCaptcha {
				st.LastFailures++
			}
			// A multi-step factor (e.g. email-OTP on its verify screen)
			// returns the sub-prompt to re-show alongside ErrFactorRetry.
			// Preserve its scratch and re-emit that prompt so a wrong-code
			// retry stays on the verify screen instead of restarting the
			// factor at its send screen (which would discard a usable code
			// and burn the resend budget). This shortcut is taken only when
			// no captcha needs to interpose; otherwise we fall through to
			// the dispatcher so the challenge runs first.
			if cont.Prompt != nil && !step.isCaptcha && !o.loginFlowCaptchaPending(st, flow) {
				st.FactorScratch = cont.Scratch
				next, emitted, perr := o.emitLoginFlowPrompt(st, kind, *cont.Prompt, in.Now)
				if perr != nil {
					return st, interaction.Step{}, perr
				}
				return next, emitted, nil
			}
			// Re-enter the dispatcher so a captcha-shaped rule whose
			// predicate just became true (e.g., RuleAfterFailedAttempts
			// crossing its threshold) can interpose. When no rule fires
			// the dispatcher falls through to Primary and re-emits the
			// same factor's prompt.
			st.FactorScratch = nil
			st.ActiveStepKind = ""
			return o.advanceLoginFlow(ctx, st, in.Now)
		}
		st = retireActiveFactorToken(st)
		return st, interaction.Step{}, err
	}
	if cont.Prompt != nil {
		// Multi-screen step: re-issue the prompt under the same
		// kind tag. StepCounter increments so the previous token
		// cannot replay.
		st.FactorScratch = cont.Scratch
		next, emitted, perr := o.emitLoginFlowPrompt(st, kind, *cont.Prompt, in.Now)
		if perr != nil {
			return st, interaction.Step{}, perr
		}
		return next, emitted, nil
	}
	if cont.Result == nil {
		return st, interaction.Step{}, ErrInvalidStep
	}
	if !step.isCaptcha {
		if rerr := guardAAL3RequiresUV(step.auth, *cont.Result); rerr != nil {
			return st, interaction.Step{}, rerr
		}
	}
	st = o.recordLoginFlowResult(ctx, st, step, *cont.Result, in.Now)
	return st, interaction.Step{}, nil
}
