package op

import "context"

// AuditDenyReasonKey is the slog attribute key under which the
// orchestrator writes [Deny.Reason] when it emits the deny audit
// event. The constant is the contract between the orchestrator's
// audit emitter and the redaction handler installed by [WithLogger]
// / [WithAuditLogger]: the redact substring matcher MUST keep this
// key on its allow-list so a misbehaving [Decider] that puts a
// credential or PII fragment into [Deny.Reason] cannot leak it
// through the audit sink.
//
// External code SHOULD NOT depend on this constant for log
// scraping — the audit envelope itself is authoritative — but
// embedders writing integration tests can use it to assert the
// emitted record carries the expected field.
const AuditDenyReasonKey = "audit.deny.reason"

// Decider is the imperative complement to [LoginFlow.Rules]. The
// orchestrator consults the Decider on every evaluation pass before
// it iterates the rule list; a non-[Pass] [Decision] short-circuits
// further rule evaluation. The interface exists so policies that
// cannot be expressed declaratively (an external policy engine,
// stateful adaptive authentication, custom feature flags) have a
// single seam rather than forcing a custom [Authenticator].
//
// Implementations MUST be safe for concurrent use by multiple
// goroutines and SHOULD bound the work the Decide method performs:
// the orchestrator invokes the method on every evaluation pass, so a
// slow Decider is paid for on every step transition.
type Decider interface {
	// Decide returns the [Decision] for the supplied [LoginContext].
	// The orchestrator threads ctx through from the request handler so
	// implementations can honour deadline cancellation.
	Decide(ctx context.Context, lc LoginContext) Decision
}

// Decision is the sealed sum type [Decider.Decide] returns. The four
// concrete shapes — [Allow], [Pass], [Require], [Deny] — exhaust the
// set the orchestrator's evaluation loop recognises; the unexported
// [Decision.isDecision] method prevents foreign packages from adding
// new cases, so the orchestrator's switch is total by construction.
type Decision interface {
	isDecision()
}

// Allow short-circuits the evaluation loop with a successful login.
// The orchestrator skips remaining [LoginFlow.Rules] and proceeds to
// grant. Use Allow when an external policy engine has already
// determined the user is approved without further factors.
type Allow struct{}

// isDecision implements [Decision].
func (Allow) isDecision() {}

// Pass defers the decision to the [LoginFlow.Rules] table. Returning
// Pass from a [Decider] is the common case: the imperative seam
// inspects the context, finds nothing actionable, and lets the
// declarative rules drive the rest of the flow. A [LoginFlow] with
// neither rules nor a non-Pass Decider grants on every pass.
type Pass struct{}

// isDecision implements [Decision].
func (Pass) isDecision() {}

// Require short-circuits the evaluation loop with a step the
// orchestrator MUST run before the next pass. The orchestrator
// appends [Step.Kind] to [LoginContext.CompletedSteps] after the step
// completes and re-enters the loop, so a Decider can drive arbitrary
// step-up chains by returning Require repeatedly.
//
// Step MUST be non-nil; the orchestrator rejects a Require with a nil
// Step.
type Require struct {
	// Step is the next [Step] to run.
	Step Step
}

// isDecision implements [Decision].
func (Require) isDecision() {}

// Deny short-circuits the evaluation loop with a failed login. The
// orchestrator translates the result to the OAuth `access_denied`
// error per RFC 6749 §4.1.2.1 and redirects the user-agent back to
// the client's redirect URI with the request `state` preserved.
//
// Reason is recorded in the audit log; it is NOT surfaced to the
// user-agent, which always sees the standard `access_denied` error
// description.
type Deny struct {
	// Reason is the operator-facing explanation written to the audit
	// stream. The orchestrator emits it under the slog attribute key
	// "audit.deny.reason" so operators can grep for the field
	// directly.
	//
	// The string is treated as untrusted by the redaction handler the
	// library wraps around every operational and audit logger (see
	// internal/redact / [WithLogger] / [WithAuditLogger]): the
	// "audit.deny.reason" key is on the redaction allow-list so a
	// misbehaving [Decider] that copies a credential or PII fragment
	// into Reason cannot leak it through the audit sink. Implementers
	// SHOULD still keep Reason free of raw inputs, tokens, and PII —
	// the redaction is defence-in-depth, not a sanitisation hook —
	// but the library guarantees the field is masked when a
	// regression slips through.
	//
	// The wire-side `error_description` returned to the user-agent is
	// always the static OAuth string ("access_denied"); Reason is
	// invisible to the relying party regardless of redaction.
	Reason string
}

// isDecision implements [Decision].
func (Deny) isDecision() {}
