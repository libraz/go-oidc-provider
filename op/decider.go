package op

import "context"

// AuditDenyReasonKey is a slog attribute key reserved for [Deny.Reason].
//
// Deprecated: no code path emits this key. A denied login is recorded on
// the operational logger installed by [WithLogger] under the plain
// "reason" attribute, so an assertion that matches AuditDenyReasonKey
// never fires; match "reason" instead. The constant is retained so
// existing references keep compiling and its value will not change.
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
// orchestrator MUST run before the next pass. The orchestrator appends
// the kind to [LoginContext.CompletedSteps] once the step completes and
// re-enters the loop, so a Decider can drive a step-up chain by
// returning Require repeatedly.
//
// Require selects a step; it does not introduce one. The named kind MUST
// already be declared on the flow, as [LoginFlow.Primary] or as some
// [Rule]'s Then — a Decider cannot conjure a factor that reading the
// [LoginFlow] would not reveal, which is what keeps the set of factors a
// login can ever demand enumerable from the construction site alone. A
// step the Decider is the only one to ask for is still declared as a
// rule; give it a predicate that never fires, and the Decider decides
// when it runs:
//
//	Rules: []op.Rule{
//	    op.RuleWhen(func(op.LoginContext) bool { return false }, recovery),
//	    op.RuleAlways(emailOTP),
//	},
//	Decider: myDecider{}, // returns Require{Kind: op.StepKindRecoveryCode}
//
// A Kind that is not declared is a configuration error the orchestrator
// can only discover on the request that hits it: the login fails and the
// reason is logged. An empty Kind is read as [Pass].
//
// Requiring a kind that has already completed is not an error — the
// orchestrator falls through to the rules rather than running it twice.
// A Decider whose condition still holds after the step completes will
// therefore keep passing to the rules, so it has to say what happens
// next itself, usually by returning [Allow].
type Require struct {
	// Kind names the declared [Step] to run next.
	Kind StepKind
}

// isDecision implements [Decision].
func (Require) isDecision() {}

// Deny short-circuits the evaluation loop with a failed login. The
// orchestrator translates the result to the OAuth `access_denied`
// error per RFC 6749 §4.1.2.1 and redirects the user-agent back to
// the client's redirect URI with the request `state` preserved.
//
// Reason is written to the operational log; it is NOT surfaced to the
// user-agent, which always sees the standard `access_denied` error
// description.
type Deny struct {
	// Reason is the operator-facing explanation of the denial. The
	// orchestrator writes it to the operational logger installed by
	// [WithLogger], at info level, under the slog attribute "reason"
	// alongside the subject and client_id of the attempt.
	//
	// The value is logged verbatim. No masking is applied to it: the
	// redaction handler the library wraps around every operational
	// and audit logger matches a closed catalogue of
	// credential-bearing attribute keys, and "reason" is not one of
	// them. Whatever a [Decider] puts in Reason — an email address,
	// an account identifier, an internal case reference, a raw
	// request input — reaches the configured log sink in the clear.
	// Implementers MUST therefore keep Reason to a stable
	// non-identifying code such as "policy.geo" or
	// "anomaly.velocity", and carry any identifier through their own
	// pipeline instead.
	//
	// The wire-side `error_description` returned to the user-agent is
	// always the static OAuth string ("access_denied"); Reason is
	// invisible to the relying party.
	Reason string
}

// isDecision implements [Decision].
func (Deny) isDecision() {}
