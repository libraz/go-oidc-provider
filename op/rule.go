package op

// Rule pairs a predicate against a [LoginContext] with the [Step] the
// orchestrator runs when the predicate fires. Rules are the
// declarative half of [LoginFlow] orchestration: when the predicate
// is a pure function of [LoginContext], the rule table-tests cleanly
// and the orchestrator can short-circuit on completion.
//
// The orchestrator iterates [LoginFlow.Rules] in declaration order on
// each evaluation pass, runs the first rule whose [Rule.When] returns
// true and whose [Rule.Then.Kind] is not in
// [LoginContext.CompletedSteps], then re-enters the loop. When no
// rule matches the flow grants. See
// docs/plans/005-login-and-ui-shell.md §3.1 for the full evaluation
// pseudocode.
//
// A nil When is treated as the constant-true predicate. A nil Then is
// rejected at construction time.
type Rule struct {
	// When is the predicate the orchestrator evaluates on every pass.
	// MUST be a pure function of [LoginContext]; the orchestrator
	// recovers from a panic in When and treats the rule as not
	// matching, but a programming error in the predicate still costs
	// a log entry and a wasted evaluation pass.
	When func(LoginContext) bool

	// Then is the [Step] the orchestrator runs when [Rule.When]
	// returns true. MUST be non-nil.
	Then Step
}

// RuleAlways returns a [Rule] that matches on every evaluation pass.
// Combined with [LoginFlow.Rules]'s deduplication via
// [LoginContext.CompletedSteps], the rule effectively runs `then`
// exactly once per attempt — the canonical "always require this
// factor" expression.
func RuleAlways(then Step) Rule {
	return Rule{
		When: func(LoginContext) bool { return true },
		Then: then,
	}
}

// RuleAfterFailedAttempts returns a [Rule] that matches when
// [LoginContext.FailedAttempts] is greater than or equal to n. The
// boundary is inclusive: a rule built with `RuleAfterFailedAttempts(3,
// ...)` fires for the third and every subsequent failure in the same
// attempt, matching the natural English reading of "after three
// failures".
func RuleAfterFailedAttempts(n int, then Step) Rule {
	return Rule{
		When: func(lc LoginContext) bool { return lc.FailedAttempts >= n },
		Then: then,
	}
}

// RuleRisk returns a [Rule] that matches when
// [LoginContext.RiskScore] is greater than or equal to threshold.
// Embedders typically pair the rule with a stronger second factor:
// `RuleRisk(RiskScoreHigh, StepTOTP{...})` requests TOTP only when
// the configured [RiskAssessor] reports the highest level.
//
// When [LoginFlow.Risk] is nil the orchestrator does not invoke an
// assessor and [LoginContext.RiskScore] stays at [RiskScoreNone]; in
// that case a [RuleRisk] with a non-zero threshold silently never
// fires.
func RuleRisk(threshold RiskScore, then Step) Rule {
	return Rule{
		When: func(lc LoginContext) bool { return lc.RiskScore >= threshold },
		Then: then,
	}
}

// RuleNewDevice returns a [Rule] that matches when
// [LoginContext.NewDevice] is true. The orchestrator marks a device
// as new when no device-trust cookie is present or the cookie does
// not bind to a known fingerprint; embedders typically chain the rule
// to a stronger factor on first sign-in from a fresh browser.
func RuleNewDevice(then Step) Rule {
	return Rule{
		When: func(lc LoginContext) bool { return lc.NewDevice },
		Then: then,
	}
}

// RuleClient returns a [Rule] that matches when
// [LoginContext.ClientID] equals clientID. Use it to scope a step-up
// to a single relying party — for instance, requiring TOTP only when
// the request came from an internal admin client.
func RuleClient(clientID string, then Step) Rule {
	return Rule{
		When: func(lc LoginContext) bool { return lc.ClientID == clientID },
		Then: then,
	}
}

// RuleScope returns a [Rule] that matches when scope is present in
// [LoginContext.RequestedScopes]. The comparison is case-sensitive
// per RFC 6749 §3.3. Use it to gate sensitive scopes ("write:billing",
// "admin") behind a stronger factor.
func RuleScope(scope string, then Step) Rule {
	return Rule{
		When: func(lc LoginContext) bool { return lc.RequestedScopes.Has(ScopeName(scope)) },
		Then: then,
	}
}

// RuleACR returns a [Rule] that matches when acr is present in
// [LoginContext.ACRValues]. The list is the parsed RFC 9470
// `acr_values` request parameter, so the rule lets an embedder
// implement OIDC step-up: re-authenticate when the relying party asks
// for a stronger ACR than the current session asserts.
func RuleACR(acr string, then Step) Rule {
	return Rule{
		When: func(lc LoginContext) bool {
			for _, v := range lc.ACRValues {
				if v == acr {
					return true
				}
			}
			return false
		},
		Then: then,
	}
}

// RuleWhen returns a [Rule] whose predicate is the caller-supplied
// pred. Use it to express conditions the typed helpers do not cover —
// for example, geo-fencing through a custom [LoginContext.Remote]
// inspection. The predicate MUST be a pure function of
// [LoginContext]; the orchestrator does not promise to invoke it
// exactly once per pass.
//
// A nil pred is treated as the constant-false predicate.
func RuleWhen(pred func(LoginContext) bool, then Step) Rule {
	if pred == nil {
		pred = func(LoginContext) bool { return false }
	}
	return Rule{When: pred, Then: then}
}
