package authn

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	opaudit "github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn/audit"
	internallog "github.com/libraz/go-oidc-provider/internal/log"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// captchaMaxFailures bounds how many rejected tokens a single attempt
// may submit to a captcha step before the orchestrator abandons the
// chain with [ErrCaptchaExhausted]. The gate is a liveness bound, not a
// security one: without it a deployment whose verifier rejects
// everything (a misconfigured site key, an upstream outage) would
// re-emit the challenge indefinitely and no factor would ever become
// reachable.
const captchaMaxFailures = 5

// stateRefTTL is how long an issued [interaction.Prompt.StateRef] stays valid
// from the orchestrator's perspective. The default is short enough to
// rule out long-tail replay attacks but long enough to outlast a
// reasonable user pause on the SPA. Embedders that want a different
// value will get an option in a follow-up; the constant is internal
// to the orchestrator state machine.
const stateRefTTL = 10 * time.Minute

// Config is the [Orchestrator] construction payload. It mirrors the
// public-API options the [op.Provider] accumulates; the HTTP layer
// wires the two together. Fields with comments marked "optional"
// may be nil; the orchestrator handles the missing dependency by
// skipping the corresponding phase.
type Config struct {
	// Interactions is the registered interaction list. The
	// orchestrator inserts each entry per its
	// [InteractionTrigger]; intra-trigger ordering follows
	// registration order.
	Interactions []Interaction

	// Observers receives one [LoginAttempt] per factor outcome.
	// The slice is fanned out in registration order.
	Observers []LoginAttemptObserver

	// AuditEmitter is the OP-wide audit sink the same factor
	// outcomes are reported to, as the login.* / mfa.* names of the
	// shared event catalogue.
	//
	// It is a second feed rather than a replacement for [Observers]
	// because the two answer different questions. An observer is a
	// policy input: it runs inside the attempt so an embedder can
	// count failures and drive its own lockout. The audit stream is
	// a record: it is fanned out to logging / metrics / SOC sinks and
	// is the only one of the two that a Prometheus registry sees.
	// Nil means the outcomes are recorded nowhere, which is why
	// [New] substitutes a discard sink rather than leaving it nil.
	AuditEmitter opaudit.Emitter

	// StateRefSigner signs every [interaction.Prompt.StateRef]. Required.
	StateRefSigner *StateRefSigner

	// Logger is the structured logger the orchestrator writes
	// warning records to (e.g., when an [Authenticator.AMR]
	// return is dropped because it is not RFC 8176-registered).
	// Nil means "discard"; the orchestrator never panics on a nil
	// logger.
	Logger *slog.Logger

	// LoginFlow is the compiled flow the orchestrator drives through
	// [Orchestrator.advanceLoginFlow]. Required. Factor selection follows
	// its Primary, rules and decider; its risk assessor is consulted at
	// most once per chain (see [State.RiskScoreCached]); panic recovery
	// wraps every embedder predicate / decider.
	LoginFlow *CompiledLoginFlow
}

// Orchestrator runs the authenticator chain state machine. It is a
// pure value: every method is deterministic given its inputs, and the
// orchestrator owns no I/O of its own. The HTTP layer persists [State]
// between calls; the orchestrator returns updated state for the
// caller to write back.
type Orchestrator struct {
	cfg            Config
	logger         *slog.Logger
	auditObservers []audit.Observer
	auditEmitter   opaudit.Emitter
}

// New constructs an [Orchestrator] from cfg. It validates that a
// [CompiledLoginFlow] is supplied, that interactions have unique
// [Interaction.Name] values, and that the StateRef signer is non-nil.
// Errors here surface at [op.New] construction time so deployment
// misconfigurations cannot reach the first request.
func New(cfg Config) (*Orchestrator, error) {
	if err := validateChainShape(cfg); err != nil {
		return nil, err
	}
	if cfg.StateRefSigner == nil {
		return nil, errors.New("authn: StateRefSigner required")
	}
	seenName := make(map[string]struct{}, len(cfg.Interactions))
	deduped := make([]Interaction, 0, len(cfg.Interactions))
	for _, ix := range cfg.Interactions {
		if ix == nil {
			return nil, errors.New("authn: nil Interaction")
		}
		name := ix.Name()
		if name == "" {
			return nil, errors.New("authn: Interaction.Name must not be empty")
		}
		if _, dup := seenName[name]; dup {
			continue
		}
		seenName[name] = struct{}{}
		deduped = append(deduped, ix)
	}
	cfg.Interactions = deduped
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(internallog.DiscardHandler{})
	}
	emitter := cfg.AuditEmitter
	if emitter == nil {
		emitter = opaudit.Discard()
	}
	return &Orchestrator{
		cfg:            cfg,
		logger:         logger,
		auditObservers: wrapAuditObservers(cfg.Observers),
		auditEmitter:   emitter,
	}, nil
}

// HasInteractions reports whether any registered [Interaction] declares
// trigger. The HTTP layer consults it for [TriggerBeforeToken]: an exit
// that mints a code without driving the chain would otherwise skip
// those interactions.
func (o *Orchestrator) HasInteractions(trigger InteractionTrigger) bool {
	for _, ix := range o.cfg.Interactions {
		if ix.Trigger() == trigger {
			return true
		}
	}
	return false
}

// validateChainShape requires the compiled [Config.LoginFlow]: it is
// the only path the orchestrator drives factors through.
func validateChainShape(cfg Config) error {
	if cfg.LoginFlow == nil {
		return errors.New("authn: LoginFlow required")
	}
	return nil
}

// requireReauth returns st re-entered at [PhaseAuthn] with
// [State.ReauthRequired] set, for a chain whose account chooser bound a
// session that may not serve the request. The factor chain then runs
// for the subject the chooser bound, exactly as when the flag was set at
// chain start. Any prompt st had outstanding is withdrawn.
func requireReauth(st State) State {
	st.ReauthRequired = true
	st.EntryAuthn = nil
	st.Phase = PhaseAuthn
	st.ActiveInteractionName = ""
	st.ActiveInputs = nil
	st.FactorScratch = nil
	return st
}

// Tick advances st by one orchestrator step. The method is pure: no
// goroutines, no [time.Now()], no network. Tick returns the updated
// [State] (always — even on error, so the HTTP layer can persist
// counters that did update before the failure) and the [interaction.Step] the
// SPA should render next, if any.
// The state machine, in order:
//  1. Reject ticks against a completed chain ([ErrChainComplete]).
//  2. If a submission is present, route it to the entity that issued
//     the StateRef (active LoginFlow step or active interaction) and
//     advance.
//  3. Run the [PhaseBeforeAuthn] interaction queue.
//  4. Run [PhaseAuthn]: drive the [CompiledLoginFlow].
//  5. Run the [PhaseAfterAuthn] interaction queue (consent first).
//  6. Run the [PhaseBeforeToken] interaction queue.
//  7. Emit the terminal [interaction.Step] from [PhaseDone].
func (o *Orchestrator) Tick(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	if st.Phase == PhaseDone {
		return st, interaction.Step{}, ErrChainComplete
	}
	if st.InteractionsRun == nil {
		st.InteractionsRun = map[string]bool{}
	}

	if in.Submission != nil {
		next, step, err := o.consumeSubmission(ctx, st, in)
		if err != nil {
			return next, interaction.Step{}, err
		}
		if step.Prompt != nil || step.Result != nil {
			return next, step, nil
		}
		st = next
	}

	return o.advance(ctx, st, in)
}

// consumeSubmission routes a non-nil submission to whichever entity
// issued the StateRef, returning either an emitted Prompt (step
// continues or is re-emitted) or a zero Step that lets advance run the
// next phase from a clean state.
func (o *Orchestrator) consumeSubmission(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	payload, err := o.cfg.StateRefSigner.Verify(in.Submission.StateRef, st.InteractionUID, st.StepCounter, in.Now)
	if err != nil {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	// Every branch below hands FormSubmission.Values to an
	// Authenticator or an Interaction, so the field constraints the
	// outstanding prompt declared are enforced here, once, ahead of the
	// routing switch: a submission route added later cannot skip the
	// gate by construction. The check runs after the StateRef verifies
	// so an unauthenticated caller cannot spend the orchestrator's
	// pattern-matching budget.
	if verr := validateSubmission(st.ActiveInputs, in.Submission.Values); verr != nil {
		return st, interaction.Step{}, verr
	}
	switch {
	case strings.HasPrefix(payload.Tag, tagInteractionPrefix):
		return o.handleInteractionSubmission(ctx, st, in)
	case strings.HasPrefix(payload.Tag, tagLoginFlowPrefix):
		return o.handleLoginFlowSubmission(ctx, st, in, strings.TrimPrefix(payload.Tag, tagLoginFlowPrefix))
	default:
		return st, interaction.Step{}, ErrInvalidStateRef
	}
}

// retireActiveFactorToken invalidates everything the ceremony that just
// failed left behind: the scratch slot carrying the factor's in-flight
// challenge, and the StateRef that addressed it (the signer binds each
// token to [State.StepCounter], so advancing the counter retires the
// outstanding token). A single-use WebAuthn challenge that survived a
// rejected assertion would otherwise stay replayable for the whole
// StateRef TTL, and an authenticator that reports no signature counter
// — the common case for platform passkeys — has nothing left to catch
// the replay with.
//
// Callers MUST return the returned State to [Tick]'s caller even though
// the tick is failing: the invalidation only takes effect once the HTTP
// layer persists it.
func retireActiveFactorToken(st State) State {
	st.FactorScratch = nil
	st.StepCounter++
	return st
}

// handleInteractionSubmission dispatches to the active interaction;
// successful Result transitions to the next phase.
func (o *Orchestrator) handleInteractionSubmission(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	idx := o.findInteractionIndex(st.ActiveInteractionName)
	if idx < 0 {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	ix := o.cfg.Interactions[idx]
	step, err := ix.Continue(ctx, ContinueInput{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		AuthTime:        st.AuthTime,
		Submission:      *in.Submission,
		RequestedScopes: st.RequestedScopes,
		ChooserGroupID:  st.ChooserGroupID,
		RemoteIP:        st.RemoteIP,
	})
	if err != nil {
		return st, interaction.Step{}, err
	}
	if step.Prompt != nil {
		next, emitted, ferr := o.emitInteractionPrompt(st, ix, *step.Prompt, in.Now)
		if ferr != nil {
			return st, interaction.Step{}, ferr
		}
		return next, emitted, nil
	}
	if step.Result == nil {
		return st, interaction.Step{}, ErrInvalidStep
	}
	st = recordInteractionResult(st, ix.Name(), *step.Result)
	if ix.Name() == BuiltinChooserName {
		// Capture the picked SessionID so the HTTP layer can call
		// sessions.Manager.Switch at terminal-tick time instead of
		// issuing a fresh chooser group. The chooser interaction
		// has already validated the value belongs to the active
		// chooser group.
		if in.Submission != nil {
			st.ChooserSelectedSessionID = in.Submission.Values[ChooserSessionIDField]
		}
	}
	st.InteractionsRun[ix.Name()] = true
	st.ActiveInteractionName = ""
	return st, interaction.Step{}, nil
}

// recordInteractionResult folds a non-authn [interaction.Result] into
// [State]. The function exists so the Begin-completes-immediately path
// (advanceInteractions) and the Continue-completes path
// (handleInteractionSubmission) record the same fields.
// Today two fields are folded: Result.Scope (consent) and
// Result.Subject (the singular built-in chooser exception).
// User-extension interactions MUST leave Subject empty; the
// orchestrator gates Subject propagation on the reserved chooser
// name to enforce this in code.
func recordInteractionResult(st State, name string, res interaction.Result) State {
	// A scope decision is recorded whenever a consent-shaped
	// Interaction answers — including an answer of "nothing". Keying
	// on len(res.Scope) > 0 instead would collapse "the user approved
	// none of the presented scopes" into "no ceremony ran", and the
	// HTTP layer's fallback for the latter is the full requested set:
	// an empty approval would silently become a total one.
	if res.Scope != nil || name == BuiltinConsentName {
		st.ApprovedScopes = append([]string(nil), res.Scope...)
		st.ScopeApprovalRecorded = true
	}
	if res.Subject != "" && name == BuiltinChooserName {
		st.Subject = res.Subject
		st.ChooserBoundSubject = true
	}
	return st
}

// BuiltinChooserName is the [Interaction.Name] reserved for the
// built-in account chooser. The orchestrator references the name
// to gate Subject propagation in [recordInteractionResult] and to
// short-circuit the factor chain in [Orchestrator.advanceOnce]
// when the chooser binds a subject. The constant lives in this
// package (rather than internal/authn/chooser) so the orchestrator
// can reference it without an import cycle.
const BuiltinChooserName = "chooser"

// BuiltinConsentName is the [Interaction.Name] the built-in consent
// screen registers under. The orchestrator references it so a consent
// answer is recognised as a scope decision even when the approved
// subset is empty. The constant is duplicated here (rather than
// imported from internal/authn/consent) for the same reason as
// [BuiltinChooserName]: the consent package imports this one.
const BuiltinConsentName = "consent"

// ChooserSessionIDField is the [interaction.FormSubmission] field name
// the chooser screen submits the picked SessionID under. The orchestrator
// reads it directly so the HTTP layer can drive a session-cookie rebind
// at terminal-tick time without depending on the chooser package.
const ChooserSessionIDField = "session_id"

// ChooserPromptType is the [interaction.Prompt.Type] the built-in
// chooser emits. SPA dispatchers route on it to render the chooser
// screen.
const ChooserPromptType = "interaction.chooser"

// guardAAL3RequiresUV enforces the rule that an authenticator
// reporting [AAL3] MUST have completed user verification (the
// [interaction.Result.UserVerified] bit is true). NIST SP 800-63B
// AAL3 requires UV; a passkey assertion that did not perform UV
// cannot satisfy AAL3, and trusting the chain to "round up" through
// orchestrator policy would silently mint a session at a higher
// assurance level than the factor actually achieved.
//
// The gate fires only on authenticators that report AAL3. AAL2 and
// below pass unconditionally; foreign / out-of-range AAL values pass
// (the aggregator will treat them defensively). The check runs before
// [appendFactor] so a factor that fails the gate never lands in
// [State.Factors] and the chain-fatal error surfaces to the HTTP
// layer for an explicit reject.
func guardAAL3RequiresUV(auth Authenticator, result interaction.Result) error {
	if auth == nil || auth.AAL() != AAL3 {
		return nil
	}
	if result.UserVerified {
		return nil
	}
	return ErrAAL3RequiresUV
}

// guardSubjectBinding refuses a factor result that names a subject
// other than the one this chain already bound, through an earlier
// factor, the account chooser, or an entry session standing in for
// Primary. A subject carried without that session's authentication is
// not chain-bound: the first factor may authenticate a different
// account.
func guardSubjectBinding(st State, result interaction.Result) error {
	bound := len(st.Factors) > 0 || st.ChooserBoundSubject || entryStandsIn(st)
	if bound && result.Subject != "" && result.Subject != st.Subject {
		return ErrSubjectMismatch
	}
	return nil
}

// guardFactorResult runs every check a factor result must pass before
// [appendFactor] records it, so each completion path applies the same
// set. Every caller retires the factor's token on a rejection, so the
// refused ceremony cannot be resubmitted.
func guardFactorResult(st State, auth Authenticator, result interaction.Result) error {
	if err := guardAAL3RequiresUV(auth, result); err != nil {
		return err
	}
	return guardSubjectBinding(st, result)
}

// appendFactor is the single point where the orchestrator records a
// successful authenticator run. It enforces the invariant that only
// RFC 8176-registered AMR values reach the session: an unregistered
// return is logged and dropped, and a registered one is kept on the
// Factor for [Factor.AMRValue].
func (o *Orchestrator) appendFactor(st State, auth Authenticator, result interaction.Result) State {
	amr := auth.AMR()
	if amr != "" && !IsRegisteredAMR(amr) {
		o.logger.Warn("authn: dropping unregistered AMR value",
			slog.String("authenticator_type", string(auth.Type())),
			slog.String("amr", amr),
		)
		amr = ""
	}
	uv := false
	if auth.Type() == FactorPasskey {
		uv = resolvePasskeyUV(auth, result)
	}
	st.Factors = append(st.Factors, Factor{
		Type:           auth.Type(),
		AssuranceLevel: auth.AAL(),
		UserVerified:   uv,
		AMR:            amr,
	})
	if result.Subject != "" {
		st.Subject = result.Subject
	}
	if !result.AuthTime.IsZero() {
		st.AuthTime = result.AuthTime
	}
	return st
}

// resolvePasskeyUV picks the UV bit to stamp on [Factor.UserVerified]
// using the precedence chain documented at [appendFactor]:
//
//  1. [interaction.Result.UserVerified] (request-scoped, replica-safe;
//     the built-in passkey adapter populates it).
//  2. The deprecated [UserVerificationReporter] interface (legacy
//     embedder-supplied adapters that have not migrated; the
//     orchestrator consults the hook only when the Result is silent).
//  3. Conservative default: false. The orchestrator deliberately
//     does NOT consult [Authenticator.AMR] here — the built-in
//     adapter returns "hwk" unconditionally, so a static AMR fall-
//     back would over-report UV when an assertion's real flag is
//     false. Legacy adapters that need to surface UV=false MUST
//     implement [UserVerificationReporter]; adapters that wire
//     neither path produce UV=false and the AMR derivation in
//     [Factor.AMRValue] picks "swk" (presence-only).
//
// Step 2 takes the reporter's verdict verbatim — including a "false"
// — so an embedder that explicitly downgrades a presence-only
// assertion through the reporter is honoured.
func resolvePasskeyUV(auth Authenticator, result interaction.Result) bool {
	if result.UserVerified {
		return true
	}
	if reporter, ok := auth.(UserVerificationReporter); ok {
		return reporter.LastUserVerified(result.Subject)
	}
	return false
}

// StateRef tag prefixes. The orchestrator inspects the prefix to
// route a submission to the correct verifier; the strings are part of
// the signed payload, so tampering is detected by the HMAC.
const (
	tagInteractionPrefix = "interaction:"
	// tagLoginFlowPrefix carries the active LoginFlow [StepKind] so
	// a submission against a LoginFlow-driven step routes back to the
	// per-step Authenticator. The kind is appended verbatim so two
	// Steps with different kinds emit distinguishable StateRef
	// payloads — the security invariant the per-Step tagging upholds.
	tagLoginFlowPrefix = "loginflow:"
)
