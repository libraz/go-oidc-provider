package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// LoginFlowSpec is the public-API LoginFlow shape the compiler
// consumes. The internal package cannot import op/, so the wiring
// layer (op/loginflow_projection.go:compileLoginFlow) re-projects the public op.LoginFlow
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

	// Registration, when its Authenticator is set, is the step a
	// [State.Registration] chain runs in place of Primary. It must wrap
	// an Authenticator directly (no one-of, no captcha) under a kind no
	// other step uses. The zero value means no registration step.
	Registration LoginFlowStep

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
	// defined path. MUST be non-nil after a successful compile, except
	// on a one-of step.
	Authenticator Authenticator

	// IsCaptcha distinguishes the captcha [op.Step] from factor-shaped
	// Steps. Captcha events do NOT enter [State.Factors] — captcha is
	// out-of-band from the brute-force / amr-history feed.
	IsCaptcha bool

	// OneOf, when non-nil, makes this a one-of step: the user completes
	// exactly one of the listed steps. Authenticator is then nil. The
	// inner steps may not be captcha or one-of steps themselves.
	OneOf []LoginFlowStep

	// IfNoneEnrolled decides what a one-of step does when the bound
	// subject has none of its factors enrolled.
	IfNoneEnrolled UnenrolledPolicy

	// RequireUserVerification marks a passkey step that demands user
	// verification. It narrows the session amr that stands in for the
	// step on a reused session to the verified value.
	RequireUserVerification bool
}

// UnenrolledPolicy is what a one-of step does when the subject has none
// of its factors enrolled.
type UnenrolledPolicy int

const (
	// UnenrolledDeny ends the attempt with [ErrFactorNotEnrolled].
	UnenrolledDeny UnenrolledPolicy = iota

	// UnenrolledSkip passes over the step without completing it, so it
	// raises neither the level nor the amr.
	UnenrolledSkip
)

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

	// Level, Inherited, AMR and ACR mirror [AuthContext] at this pass.
	Level     AAL
	Inherited bool
	AMR       []string
	ACR       string

	// AuthTime is the inherited session's auth_time; zero while the
	// attempt authenticates afresh.
	AuthTime time.Time
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
	// parentOf maps each one-of inner step kind to its one-of step kind.
	parentOf map[string]string

	// registration is the [LoginFlowSpec.Registration] step; its kind is
	// "" when the flow declares none. It is in byKind but not byFactor.
	registration compiledStep

	// binders is the set of kinds that bind the subject: Primary, its
	// one-of inner steps, and Registration. See bindsSubject.
	binders map[string]struct{}
}

// bindsSubject reports whether the step of the given kind is one that
// identifies the user — Primary (or a step of a one-of Primary) or
// Registration — rather than one that runs for a subject already bound.
func (f *CompiledLoginFlow) bindsSubject(kind string) bool {
	_, ok := f.binders[kind]
	return ok
}

// isRegistration reports whether kind is the flow's Registration step.
func (f *CompiledLoginFlow) isRegistration(kind string) bool {
	return f.registration.kind != "" && kind == f.registration.kind
}

// requirable resolves the step a Decider Require names. Registration is
// not requirable: it runs only in a [State.Registration] chain.
func (f *CompiledLoginFlow) requirable(kind string) (compiledStep, bool) {
	if f.isRegistration(kind) {
		return compiledStep{}, false
	}
	step, ok := f.byKind[kind]
	return step, ok
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
	requireUV bool
	// oneOf is non-empty for a one-of step, whose auth is nil.
	oneOf      []compiledStep
	unenrolled UnenrolledPolicy
}

// innerStep returns the one-of inner step whose kind is kind.
func (s compiledStep) innerStep(kind string) (compiledStep, bool) {
	for _, inner := range s.oneOf {
		if inner.kind == kind {
			return inner, true
		}
	}
	return compiledStep{}, false
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
//  1. Primary != zero (its Authenticator, or its OneOf, non-nil after
//     projection).
//  2. Every Rule.Then has a non-nil Authenticator or OneOf.
//  3. No two steps share a kind anywhere in the flow, one-of inner
//     steps included (dedup unit invariant).
//  4. Captcha-shaped Steps (IsCaptcha) are NOT placed at Primary
//     (captcha is a challenge, not a primary credential).
//  5. A one-of step lists at least one step, none of them captcha or
//     one-of, and its IfNoneEnrolled is a declared policy.
//  6. Registration, when declared, wraps an Authenticator directly and
//     shares its kind with no other step.
//
// On success the compiler returns a *CompiledLoginFlow whose byKind
// index maps every declared StepKind — each one-of step and each of its
// inner steps included — to its [compiledStep]; the orchestrator's
// Decider.Require lookup uses it for O(1) routing. The parallel byFactor
// index maps each non-captcha factor step's [FactorType] to the same
// value so a [RiskOutcome.RequiredFactors] entry can be routed to the
// Step that satisfies it. Declaration order wins on a collision (two
// Steps wrapping the same factor type).
func CompileLoginFlow(spec LoginFlowSpec) (*CompiledLoginFlow, error) {
	if spec.Primary.Authenticator == nil && spec.Primary.OneOf == nil {
		return nil, errors.New("authn: LoginFlow.Primary is nil")
	}
	if spec.Primary.IsCaptcha {
		return nil, errors.New("authn: LoginFlow.Primary must not be a captcha step")
	}
	if spec.Primary.Kind == "" {
		return nil, errors.New("authn: LoginFlow.Primary.Kind is empty")
	}
	c := &loginFlowCompiler{
		byKind:   map[string]compiledStep{},
		byFactor: map[FactorType]compiledStep{},
		parentOf: map[string]string{},
	}
	primary, err := c.step("LoginFlow.Primary", spec.Primary)
	if err != nil {
		return nil, err
	}
	registration, err := c.registration(spec.Registration)
	if err != nil {
		return nil, err
	}
	binders := binderKinds(primary, registration)
	rules, err := c.rules(spec.Rules)
	if err != nil {
		return nil, err
	}
	return &CompiledLoginFlow{
		primary:      primary,
		rules:        rules,
		decider:      spec.Decider,
		risk:         spec.Risk,
		byKind:       c.byKind,
		byFactor:     c.byFactor,
		parentOf:     c.parentOf,
		registration: registration,
		binders:      binders,
	}, nil
}

// rules compiles the declared Rules in order.
func (c *loginFlowCompiler) rules(specs []LoginFlowRule) ([]compiledRule, error) {
	rules := make([]compiledRule, 0, len(specs))
	for i, r := range specs {
		if r.Then.Authenticator == nil && r.Then.OneOf == nil {
			return nil, fmt.Errorf("authn: LoginFlow.Rules[%d].Then is nil", i)
		}
		if r.Then.Kind == "" {
			return nil, fmt.Errorf("authn: LoginFlow.Rules[%d].Then.Kind is empty", i)
		}
		then, err := c.step(fmt.Sprintf("LoginFlow.Rules[%d].Then", i), r.Then)
		if err != nil {
			return nil, err
		}
		when := r.When
		if when == nil {
			when = func(LoginFlowContext) bool { return false }
		}
		rules = append(rules, compiledRule{when: when, then: then})
	}
	return rules, nil
}

// binderKinds collects the kinds that may bind a login: the Primary step,
// its one-of inner steps, and the Registration step when declared.
func binderKinds(primary, registration compiledStep) map[string]struct{} {
	binders := map[string]struct{}{primary.kind: {}}
	for _, inner := range primary.oneOf {
		binders[inner.kind] = struct{}{}
	}
	if registration.kind != "" {
		binders[registration.kind] = struct{}{}
	}
	return binders
}

// registration compiles [LoginFlowSpec.Registration]. A zero step yields
// a zero compiledStep (no registration). The step is registered by kind,
// so a Rule naming it is refused as a duplicate, but not by factor: a
// risk step-up must never reach it.
func (c *loginFlowCompiler) registration(s LoginFlowStep) (compiledStep, error) {
	if s.Authenticator == nil && s.OneOf == nil && s.Kind == "" && !s.IsCaptcha {
		return compiledStep{}, nil
	}
	switch {
	case s.OneOf != nil:
		return compiledStep{}, errors.New("authn: LoginFlow.Registration must not be a one-of step")
	case s.IsCaptcha:
		return compiledStep{}, errors.New("authn: LoginFlow.Registration must not be a captcha step")
	case s.Authenticator == nil:
		return compiledStep{}, errors.New("authn: LoginFlow.Registration is nil")
	case s.Kind == "":
		return compiledStep{}, errors.New("authn: LoginFlow.Registration.Kind is empty")
	}
	step := compiledStep{
		kind:      s.Kind,
		auth:      s.Authenticator,
		factor:    s.Authenticator.Type(),
		requireUV: s.RequireUserVerification,
	}
	if err := c.register(step); err != nil {
		return compiledStep{}, err
	}
	return step, nil
}

// loginFlowCompiler accumulates the indexes [CompileLoginFlow] builds.
type loginFlowCompiler struct {
	byKind   map[string]compiledStep
	byFactor map[FactorType]compiledStep
	parentOf map[string]string
}

// step compiles s, registering it (and a one-of step's inner steps)
// under their kinds. where names s in error messages.
func (c *loginFlowCompiler) step(where string, s LoginFlowStep) (compiledStep, error) {
	if s.IfNoneEnrolled != UnenrolledDeny && s.IfNoneEnrolled != UnenrolledSkip {
		return compiledStep{}, fmt.Errorf("authn: %s.IfNoneEnrolled %d is not a declared policy", where, s.IfNoneEnrolled)
	}
	if s.OneOf == nil {
		return c.leaf(s)
	}
	switch {
	case s.Authenticator != nil:
		return compiledStep{}, fmt.Errorf("authn: %s sets both OneOf and Authenticator", where)
	case s.IsCaptcha:
		return compiledStep{}, fmt.Errorf("authn: %s one-of step must not be a captcha step", where)
	case len(s.OneOf) == 0:
		return compiledStep{}, fmt.Errorf("authn: %s.OneOf is empty", where)
	}
	if err := c.register(compiledStep{kind: s.Kind}); err != nil {
		return compiledStep{}, err
	}
	inner := make([]compiledStep, 0, len(s.OneOf))
	for j, in := range s.OneOf {
		innerWhere := fmt.Sprintf("%s.OneOf[%d]", where, j)
		switch {
		case in.OneOf != nil:
			return compiledStep{}, fmt.Errorf("authn: %s must not be a one-of step", innerWhere)
		case in.IsCaptcha:
			return compiledStep{}, fmt.Errorf("authn: %s must not be a captcha step", innerWhere)
		case in.Authenticator == nil:
			return compiledStep{}, fmt.Errorf("authn: %s is nil", innerWhere)
		case in.Kind == "":
			return compiledStep{}, fmt.Errorf("authn: %s.Kind is empty", innerWhere)
		}
		leaf, err := c.leaf(in)
		if err != nil {
			return compiledStep{}, err
		}
		c.parentOf[leaf.kind] = s.Kind
		inner = append(inner, leaf)
	}
	step := compiledStep{kind: s.Kind, oneOf: inner, unenrolled: s.IfNoneEnrolled}
	c.byKind[step.kind] = step
	return step, nil
}

// leaf compiles and registers a step that wraps an Authenticator.
func (c *loginFlowCompiler) leaf(s LoginFlowStep) (compiledStep, error) {
	step := compiledStep{
		kind:      s.Kind,
		auth:      s.Authenticator,
		factor:    s.Authenticator.Type(),
		isCaptcha: s.IsCaptcha,
		requireUV: s.RequireUserVerification,
	}
	if err := c.register(step); err != nil {
		return compiledStep{}, err
	}
	indexFactor(c.byFactor, step)
	return step, nil
}

// register indexes step by kind, refusing a kind already declared.
func (c *loginFlowCompiler) register(step compiledStep) error {
	if _, dup := c.byKind[step.kind]; dup {
		return fmt.Errorf("authn: LoginFlow duplicate StepKind %q", step.kind)
	}
	c.byKind[step.kind] = step
	return nil
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

// recoverPredicate runs pred(lc) under a recover() so a panicking
// embedder predicate cannot crash the OP. A panic is logged at error
// with idx (the rule's position in the LoginFlow) and the predicate is
// treated as a match: a rule that could not be evaluated still demands
// its step, so a faulty predicate never authenticates with fewer
// factors than the declared policy.
func recoverPredicate(logger *slog.Logger, idx int, pred func(LoginFlowContext) bool, lc LoginFlowContext) (matched bool) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("authn: rule predicate panicked",
				slog.Int("rule_index", idx),
				slog.Any("recovered", r),
			)
			matched = true
		}
	}()
	return pred(lc)
}

// recoverDecider runs decider.Decide(ctx, lc) under a recover() so a
// panicking embedder decider cannot crash the OP. A panic is logged at
// error and the call is treated as [LoginFlowDeny]: a Decider that could
// not reach a verdict may have been about to deny, so the login fails
// closed rather than falling through to the rule list.
func recoverDecider(ctx context.Context, logger *slog.Logger, decider LoginFlowDecider, lc LoginFlowContext) (decision LoginFlowDecision) { //nolint:ireturn,nolintlint // sealed-sum LoginFlowDecision is the contract; concrete dispatch happens at the call site.
	defer func() {
		if r := recover(); r != nil {
			logger.Error("authn: decider panicked",
				slog.Any("recovered", r),
			)
			decision = LoginFlowDeny{Reason: "decider panicked"}
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
	ac := o.AuthContext(st)
	scopes := append([]string(nil), st.RequestedScopes...)
	acrValues := append([]string(nil), st.ACRValues...)
	var authTime time.Time
	if ac.Inherited {
		authTime = st.EntryAuthn.AuthTime
	}
	return LoginFlowContext{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		RequestedScopes: scopes,
		FailedAttempts:  st.LastFailures,
		RiskScore:       st.RiskScoreCached,
		NewDevice:       st.NewDeviceCached,
		CompletedKinds:  ac.CompletedKinds,
		ACRValues:       acrValues,
		RemoteIP:        st.RemoteIPString(),
		UserAgent:       st.UserAgent,
		AcceptLanguage:  st.AcceptLanguage,
		Level:           ac.Level,
		Inherited:       ac.Inherited,
		AMR:             ac.AMR,
		ACR:             ac.ACR,
		AuthTime:        authTime,
	}
}

// stepSettled reports whether kind needs no run in this attempt: it is
// completed (or the entry session stands in for it), or it was skipped
// as unenrolled.
func stepSettled(st State, lc LoginFlowContext, kind string) bool {
	return slices.Contains(lc.CompletedKinds, kind) || slices.Contains(st.SkippedStepKinds, kind)
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
// orchestrator pass: it picks the next step (Primary, Decider verdict,
// or rule match), emits the step's Begin Prompt with a freshly-issued
// StateRef tagged with the step's Kind, and returns. Subsequent
// submissions route back through [handleLoginFlowSubmission].
//
// State machine, in order:
//
//  1. Run Risk once at chain start (cached on st.RiskScoreCached).
//  2. Subject unbound (or reauth required and Primary not yet run) —
//     fire the first matching captcha rule, otherwise run Primary's
//     Begin (subject-binding factor), or Registration's in a
//     [State.Registration] chain (see subjectBindingStep). Captcha is a
//     [LoginFlowRule] whose Then is a captcha step; there is no other
//     captcha path.
//  3. Decider consult (when wired): Allow → grant, Deny → ErrRiskDenied,
//     Require{Step} → drive Step (looked up by kind), Pass → fall
//     through to rules.
//  4. Rules iteration: captcha rules first, then factor rules, each
//     group in declaration order; the first rule whose When is true
//     and whose kind is not in CompletedStepKinds wins.
//  5. No rule matches → grant (transition to PhaseAfterAuthn), which
//     first discharges any pending risk step-up obligation.
//
// A due captcha rule also interposes before the factor step a Decider
// Require or a risk step-up is about to run, so the challenge comes
// first wherever the next factor is chosen.
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

	// Primary runs first (subject binding). A captcha rule may fire
	// before Primary the same way it fires before any other factor.
	// We key the pre-Primary phase off st.Subject (Primary populates
	// it via appendFactor) rather than CompletedStepKinds so a
	// pre-Primary captcha that has already cleared does not flip the
	// chain into the post-Primary rules pass before the credential
	// factor has bound a subject.
	//
	// A Subject the chain did not bind itself is only allowed to
	// stand in for Primary when the request may be served from the
	// existing session. When [State.ReauthRequired] is set the HTTP
	// layer has already established that it may not (prompt=login,
	// max_age expiry, unsatisfied acr_values), so the decision falls
	// back to "has Primary actually completed during this attempt".
	bind, due, err := subjectBindingStep(st, flow)
	if err != nil {
		return st, interaction.Step{}, err
	}
	if due {
		if handled, ns, step, err := o.evalLoginFlowCaptchaRules(ctx, st, flow, now); handled {
			return ns, step, err
		}
		return o.runLoginFlowStep(ctx, st, bind, now)
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

// subjectBindingStep returns the step that binds the subject — Primary,
// or Registration for a [State.Registration] chain — and whether it is
// still due. A Registration chain runs Registration until Registration
// itself completes, whatever Subject holds, so no subject the chain did
// not bind stands in for the new account. A Registration chain on a flow
// that declares no Registration ends with [ErrInvalidStep] rather than
// falling back to a login.
func subjectBindingStep(st State, flow *CompiledLoginFlow) (compiledStep, bool, error) {
	if st.Registration {
		if flow.registration.kind == "" {
			return compiledStep{}, false, ErrInvalidStep
		}
		return flow.registration, !slices.Contains(st.CompletedStepKinds, flow.registration.kind), nil
	}
	due := st.Subject == "" || (st.ReauthRequired && !slices.Contains(st.CompletedStepKinds, flow.primary.kind))
	return flow.primary, due, nil
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
		step, ok := flow.requirable(d.Step.Kind)
		if !ok {
			o.logger.Error("authn: LoginFlow Decider.Require references unknown StepKind",
				slog.String("step_kind", describeStepKind(d.Step.Kind)),
			)
			return true, st, interaction.Step{}, ErrInvalidStep
		}
		if stepSettled(st, lc, step.kind) {
			// Decider asked for a step already completed or skipped —
			// fall through to rules rather than spin on the same step.
			return false, st, interaction.Step{}, nil
		}
		if !step.isCaptcha {
			if handled, ns, sstep, err := o.evalLoginFlowCaptchaRules(ctx, st, flow, now); handled {
				return true, ns, sstep, err
			}
		}
		ns, sstep, err := o.runLoginFlowStep(ctx, st, step, now)
		return true, ns, sstep, err
	case LoginFlowPass:
		return false, st, interaction.Step{}, nil
	default:
		return false, st, interaction.Step{}, nil
	}
}

// evalLoginFlowCaptchaRules fires the first not-yet-completed
// captcha-shaped rule whose predicate matches, ahead of a factor step
// that is about to run outside the rule pass: Primary, a Decider-required
// step, or a risk step-up. This gives [RuleAfterFailedAttempts] (and
// other captcha-typed rules) a chance to interpose between a failed
// credential attempt and the next prompt — before Primary, a rule whose
// Then is a captcha Step would otherwise never fire, because rules are
// consulted only after Primary completes, which soft credential
// failures never reach.
//
// Only captcha-shaped Steps are eligible here. Factor-shaped rules
// must wait for Primary to complete (subject binding) before they can
// run, so this scan deliberately ignores them.
func (o *Orchestrator) evalLoginFlowCaptchaRules(ctx context.Context, st State, flow *CompiledLoginFlow, now time.Time) (bool, State, interaction.Step, error) {
	return o.evalLoginFlowRuleGroup(ctx, st, flow, o.loginFlowContext(st), now, true)
}

// loginFlowCaptchaPending reports whether a captcha challenge would
// interpose before the next factor prompt right now. It mirrors the
// captcha decision [advanceLoginFlow] makes — any not-yet-completed
// captcha-shaped rule whose predicate currently matches — so the
// wrong-code retry shortcut in [handleLoginFlowSubmission] does not
// re-emit a factor's verify prompt when a challenge is due. When it
// returns true the caller falls through to the dispatcher, which emits
// the captcha.
func (o *Orchestrator) loginFlowCaptchaPending(st State, flow *CompiledLoginFlow) bool {
	lc := o.loginFlowContext(st)
	for i, r := range flow.rules {
		if !r.then.isCaptcha {
			continue
		}
		if slices.Contains(st.CompletedStepKinds, r.then.kind) {
			continue
		}
		if recoverPredicate(o.logger, i, r.when, lc) {
			return true
		}
	}
	return false
}

// LoginFlowRequiresStep reports whether the LoginFlow would demand a
// factor step for st if the chain ran on the session's authentication:
// the Decider asks for one (Require) or refuses (Deny), or a
// factor-shaped rule matches. The HTTP layer calls it before serving an
// authorization from an existing session, so a rule guarding a client
// or scope is not skipped just because no credential ceremony was due.
// The steps the session stands in for ([Orchestrator.InheritedCompletedKinds])
// count as completed, matching a chain started from the session. A
// one-of step under [UnenrolledSkip] is probed for the session subject
// and not demanded when none of its factors is enrolled; a probe error
// keeps it demanded. Risk is not consulted here; risk-driven rules fire
// only inside the chain.
func (o *Orchestrator) LoginFlowRequiresStep(ctx context.Context, st State) bool {
	flow := o.cfg.LoginFlow
	if flow == nil {
		return false
	}
	lc := o.loginFlowContext(st)
	if decided, required := o.deciderRequiresStep(ctx, st, flow, lc); decided {
		return required
	}
	for i, r := range flow.rules {
		if r.then.isCaptcha || stepSettled(st, lc, r.then.kind) {
			continue
		}
		if !recoverPredicate(o.logger, i, r.when, lc) {
			continue
		}
		if skipsUnenrolled(ctx, st.Subject, r.then) {
			continue
		}
		return true
	}
	return false
}

// deciderRequiresStep is the Decider half of [Orchestrator.LoginFlowRequiresStep].
// decided is false when the rules must still be consulted: no Decider, a
// Pass, or a Require for a step that is captcha-shaped, already settled,
// or skipped for want of enrollment.
func (o *Orchestrator) deciderRequiresStep(ctx context.Context, st State, flow *CompiledLoginFlow, lc LoginFlowContext) (decided, required bool) {
	if flow.decider == nil {
		return false, false
	}
	switch d := recoverDecider(ctx, o.logger, flow.decider, lc).(type) {
	case LoginFlowAllow:
		return true, false
	case LoginFlowDeny:
		return true, true
	case LoginFlowRequire:
		step, ok := flow.requirable(d.Step.Kind)
		if !ok {
			return true, true
		}
		if !step.isCaptcha && !stepSettled(st, lc, step.kind) && !skipsUnenrolled(ctx, st.Subject, step) {
			return true, true
		}
	}
	return false, false
}

// skipsUnenrolled reports whether step is a one-of step under
// [UnenrolledSkip] that subject has none of the factors of. A probe
// error answers false, so the step stays demanded.
func skipsUnenrolled(ctx context.Context, subject string, step compiledStep) bool {
	if len(step.oneOf) == 0 || step.unenrolled != UnenrolledSkip {
		return false
	}
	enrolled, err := enrolledSteps(ctx, subject, step.oneOf)
	return err == nil && len(enrolled) == 0
}

// enrolledSteps returns the steps subject is enrolled in, in declaration
// order. A step whose authenticator does not implement
// [EnrollmentProber] counts as enrolled; a probe error fails the whole
// call.
func enrolledSteps(ctx context.Context, subject string, steps []compiledStep) ([]compiledStep, error) {
	var out []compiledStep
	for _, s := range steps {
		prober, ok := s.auth.(EnrollmentProber)
		if !ok {
			out = append(out, s)
			continue
		}
		enrolled, err := prober.Enrolled(ctx, subject)
		if err != nil {
			return nil, fmt.Errorf("authn: enrollment probe for step %s: %w", describeStepKind(s.kind), err)
		}
		if enrolled {
			out = append(out, s)
		}
	}
	return out, nil
}

// evalLoginFlowRules dispatches the first matching, not-yet-completed
// rule step. Rules whose Then is a captcha step are evaluated before
// factor rules regardless of declaration order, so a due challenge
// interposes before the next factor however the flow lists it; within
// each group declaration order holds. A panic in an embedder-supplied
// predicate is recovered and treated as a match (see
// [recoverPredicate]).
func (o *Orchestrator) evalLoginFlowRules(ctx context.Context, st State, flow *CompiledLoginFlow, lc LoginFlowContext, now time.Time) (bool, State, interaction.Step, error) {
	if handled, ns, step, err := o.evalLoginFlowRuleGroup(ctx, st, flow, lc, now, true); handled {
		return true, ns, step, err
	}
	return o.evalLoginFlowRuleGroup(ctx, st, flow, lc, now, false)
}

// evalLoginFlowRuleGroup walks the rules whose Then is (captcha) or is
// not (!captcha) a captcha step, in declaration order, and runs the
// first matching, not-yet-completed one.
func (o *Orchestrator) evalLoginFlowRuleGroup(ctx context.Context, st State, flow *CompiledLoginFlow, lc LoginFlowContext, now time.Time, captcha bool) (bool, State, interaction.Step, error) {
	for i, r := range flow.rules {
		if r.then.isCaptcha != captcha {
			continue
		}
		if stepSettled(st, lc, r.then.kind) {
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
// was interposed (or a due captcha rule has to clear first), and true
// with an error when the demand cannot be met.
//
// Three outcomes:
//
//   - No demand, or a completed [Factor] already carries one of the
//     demanded types — not handled; the caller grants.
//   - A declared Step wraps an [Authenticator] of a demanded type and
//     has not run yet — that Step is driven, exactly as a matching
//     [LoginFlowRule] would have driven it.
//   - No declared Step can satisfy the demand —
//     [ErrNoEligibleAuthenticator], failing closed. Granting instead
//     would hand out a session at the assurance the assessor just
//     refused.
func (o *Orchestrator) enforceRiskStepUp(ctx context.Context, st State, flow *CompiledLoginFlow, now time.Time) (bool, State, interaction.Step, error) {
	if len(st.RiskRequiredFactors) == 0 || riskStepUpSatisfied(st) {
		return false, st, interaction.Step{}, nil
	}
	for _, want := range st.RiskRequiredFactors {
		step, ok := flow.byFactor[want]
		if !ok || slices.Contains(st.CompletedStepKinds, step.kind) {
			continue
		}
		if handled, ns, sstep, err := o.evalLoginFlowCaptchaRules(ctx, st, flow, now); handled {
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
		if slices.Contains(st.RiskRequiredFactors, f.Type) {
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
// pass. A one-of step is handed to [Orchestrator.runOneOfStep]. A Begin
// error is reported to the audit stream before it propagates.
func (o *Orchestrator) runLoginFlowStep(ctx context.Context, st State, step compiledStep, now time.Time) (State, interaction.Step, error) {
	if len(step.oneOf) > 0 {
		return o.runOneOfStep(ctx, st, step, now)
	}
	begin, err := step.auth.Begin(ctx, BeginInput{
		Subject:         o.stepSubject(st, step.kind),
		ClientID:        st.ClientID,
		AuthTime:        now,
		RequestedScopes: st.RequestedScopes,
		Client:          st.Client,
	})
	if err != nil {
		o.reportBeginFailure(ctx, st, step.kind, err)
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
		if rerr := o.guardStepResult(st, step, *begin.Result); rerr != nil {
			return retireActiveFactorToken(st), interaction.Step{}, rerr
		}
	}
	// Begin completed immediately — record and re-enter the
	// LoginFlow loop so the dispatcher sees the next pass without
	// dropping back through advanceOnce's transition guard.
	st = o.recordLoginFlowResult(ctx, st, step, *begin.Result, now)
	return o.advanceLoginFlow(ctx, st, now)
}

// stepSubject is the subject handed to the authenticator of the step of
// the given kind. A Primary step identifies the user, so a subject the
// chain did not bind itself — the one carried over from the entry session
// of a request that must re-authenticate — is withheld from it: Primary
// may authenticate a different account, and a passkey would otherwise
// run subject-bound instead of discoverable. A subject bound by the
// account chooser or by an earlier factor is passed through. Registration
// creates an account, so it is never handed a subject at all.
func (o *Orchestrator) stepSubject(st State, kind string) string {
	flow := o.cfg.LoginFlow
	if flow.isRegistration(kind) {
		return ""
	}
	if st.ChooserBoundSubject || len(st.Factors) > 0 {
		return st.Subject
	}
	if flow.bindsSubject(kind) {
		return ""
	}
	return st.Subject
}

// guardStepResult is [guardFactorResult] plus the subject-binding rule: a
// Primary completion that leaves no subject bound would send
// advanceLoginFlow straight back into Primary, so it ends the attempt
// with [ErrInvalidStep] instead. A Registration completion must name the
// subject itself; a subject the chain inherited does not stand in for it.
func (o *Orchestrator) guardStepResult(st State, step compiledStep, res interaction.Result) error {
	if err := guardFactorResult(st, step.auth, res); err != nil {
		return err
	}
	flow := o.cfg.LoginFlow
	if !flow.bindsSubject(step.kind) || res.Subject != "" {
		return nil
	}
	if flow.isRegistration(step.kind) || st.Subject == "" {
		return ErrInvalidStep
	}
	return nil
}

// runOneOfStep drives a one-of step. After Primary only the steps the
// subject is enrolled in are candidates; at Primary no subject is known
// yet and every step is. No candidate ends the attempt with
// [ErrFactorNotEnrolled] or, under [UnenrolledSkip], records the skip and
// moves on. One candidate is begun directly; more are offered through
// the factor-choice prompt, signed under the one-of kind. A factor
// already settled on in this attempt is resumed without probing again.
func (o *Orchestrator) runOneOfStep(ctx context.Context, st State, step compiledStep, now time.Time) (State, interaction.Step, error) {
	if st.PendingOneOfKind == step.kind && len(st.OfferedFactorKinds) == 1 {
		if inner, ok := step.innerStep(st.OfferedFactorKinds[0]); ok {
			return o.runLoginFlowStep(ctx, st, inner, now)
		}
	}
	candidates := step.oneOf
	if step.kind != o.cfg.LoginFlow.primary.kind {
		enrolled, err := enrolledSteps(ctx, st.Subject, step.oneOf)
		if err != nil {
			o.reportBeginFailure(ctx, st, step.kind, err)
			return st, interaction.Step{}, err
		}
		candidates = enrolled
	}
	switch len(candidates) {
	case 0:
		if step.unenrolled == UnenrolledSkip {
			st.SkippedStepKinds = append(st.SkippedStepKinds, step.kind)
			o.emitStepBeginFailed(ctx, st, step.kind, beginFailedNotEnrolledSkipped)
			return o.advanceLoginFlow(ctx, st, now)
		}
		o.reportBeginFailure(ctx, st, step.kind, ErrFactorNotEnrolled)
		return st, interaction.Step{}, ErrFactorNotEnrolled
	case 1:
		st.PendingOneOfKind = step.kind
		st.OfferedFactorKinds = []string{candidates[0].kind}
		return o.runLoginFlowStep(ctx, st, candidates[0], now)
	}
	options := make([]interaction.FactorOption, 0, len(candidates))
	offered := make([]string, 0, len(candidates))
	for _, c := range candidates {
		options = append(options, interaction.FactorOption{Kind: c.kind, Label: interaction.FactorLabelKey(c.kind)})
		offered = append(offered, c.kind)
	}
	next := st
	next.ActiveStepKind = step.kind
	next.FactorScratch = nil
	next.PendingOneOfKind = step.kind
	next.OfferedFactorKinds = offered
	next, emitted, err := o.emitLoginFlowPrompt(next, step.kind, interaction.Prompt{
		Type: interaction.PromptTypeChooseFactor,
		Data: interaction.FactorChoicePromptData{Options: options},
	}, now)
	if err != nil {
		return st, interaction.Step{}, err
	}
	return next, emitted, nil
}

// handleFactorChoice accepts the answer to a one-of step's choice
// prompt and begins the chosen step. Only a kind the prompt offered is
// accepted, checked against [State.OfferedFactorKinds] rather than a
// fresh enrollment probe; anything else is refused like a bad StateRef.
func (o *Orchestrator) handleFactorChoice(ctx context.Context, st State, in Input, step compiledStep) (State, interaction.Step, error) {
	choice := in.Submission.Values[interaction.FactorChoiceField]
	if st.PendingOneOfKind != step.kind || choice == "" || !slices.Contains(st.OfferedFactorKinds, choice) {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	inner, ok := step.innerStep(choice)
	if !ok {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	st.ActiveStepKind = ""
	st.OfferedFactorKinds = []string{choice}
	return o.runLoginFlowStep(ctx, st, inner, in.Now)
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

// withRejectedNotice returns step with a credentials-rejected notice on a
// copy of its Prompt; a step without a Prompt is returned unchanged.
func withRejectedNotice(step interaction.Step) interaction.Step {
	if step.Prompt == nil {
		return step
	}
	p := *step.Prompt
	p.Error = &interaction.PromptError{Code: interaction.PromptErrorCredentialsRejected}
	step.Prompt = &p
	return step
}

// recordLoginFlowResult folds a step's [interaction.Result] into st:
// for factor-shaped steps it appends a [Factor] (so [Aggregate]
// observes the AAL contribution and amr value), for captcha-shaped
// steps it resets the failure counters without entering
// [State.Factors] — a captcha is a bot check, not an authentication
// factor, so it must not contribute to the AAL aggregate or the amr
// claim.
//
// In all cases the step's kind is appended to CompletedStepKinds for
// dedup, followed by its one-of step's kind when it is an inner step,
// ActiveStepKind is cleared, and the FactorScratch slot is reset so a
// subsequent step does not inherit the previous step's scratch payload.
func (o *Orchestrator) recordLoginFlowResult(ctx context.Context, st State, step compiledStep, res interaction.Result, now time.Time) State {
	if step.isCaptcha {
		st.CaptchaFailures = 0
		st.LastFailures = 0
	} else {
		st = o.appendFactor(st, step.auth, res)
		o.observeSuccess(ctx, st, now, step.auth.Type())
	}
	st.CompletedStepKinds = append(st.CompletedStepKinds, step.kind)
	if parent, ok := o.cfg.LoginFlow.parentOf[step.kind]; ok {
		if !slices.Contains(st.CompletedStepKinds, parent) {
			st.CompletedStepKinds = append(st.CompletedStepKinds, parent)
		}
		if st.PendingOneOfKind == parent {
			st.PendingOneOfKind = ""
			st.OfferedFactorKinds = nil
		}
	}
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
	if len(step.oneOf) > 0 {
		return o.handleFactorChoice(ctx, st, in, step)
	}
	cont, err := step.auth.Continue(ctx, ContinueInput{
		Subject:         o.stepSubject(st, kind),
		ClientID:        st.ClientID,
		AuthTime:        st.AuthTime,
		Submission:      *in.Submission,
		Scratch:         st.FactorScratch,
		RequestedScopes: st.RequestedScopes,
		RemoteIP:        st.RemoteIP,
	})
	if err != nil {
		// One classification decides both what is recorded and where the
		// chain goes, so the two can never disagree. Captcha steps
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
			// A rejected captcha token spends a per-attempt budget, so a
			// rule that keeps re-firing the challenge cannot hold the
			// user in it forever.
			if step.isCaptcha {
				st.CaptchaFailures++
				if st.CaptchaFailures >= captchaMaxFailures {
					return retireActiveFactorToken(st), interaction.Step{}, ErrCaptchaExhausted
				}
			} else {
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
				return next, withRejectedNotice(emitted), nil
			}
			// Re-enter the dispatcher so a captcha-shaped rule whose
			// predicate just became true (e.g., RuleAfterFailedAttempts
			// crossing its threshold) can interpose. When no rule fires
			// the dispatcher falls through to Primary and re-emits the
			// same factor's prompt.
			st.FactorScratch = nil
			st.ActiveStepKind = ""
			next, emitted, aerr := o.advanceLoginFlow(ctx, st, in.Now)
			if aerr != nil {
				return next, emitted, aerr
			}
			return next, withRejectedNotice(emitted), nil
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
		if rerr := o.guardStepResult(st, step, *cont.Result); rerr != nil {
			return retireActiveFactorToken(st), interaction.Step{}, rerr
		}
	}
	st = o.recordLoginFlowResult(ctx, st, step, *cont.Result, in.Now)
	return st, interaction.Step{}, nil
}
