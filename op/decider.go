package op

import "context"

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
	// log. It MUST NOT contain sensitive material (raw inputs, tokens).
	Reason string
}

// isDecision implements [Decision].
func (Deny) isDecision() {}
