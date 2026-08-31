package op

// Rule pairs a predicate against a [LoginContext] with the [Step] the
// orchestrator runs when the predicate fires. Rules are the
// declarative half of [LoginFlow] orchestration: when the predicate
// is a pure function of [LoginContext], the rule table-tests cleanly
// and the orchestrator can short-circuit on completion.
// The orchestrator iterates [LoginFlow.Rules] in declaration order on
// each evaluation pass, runs the first rule whose [Rule.When] returns
// true and whose [Rule.Then.Kind] is not in
// [LoginContext.CompletedSteps], then re-enters the loop. When no
// rule matches the flow grants.
// A nil When is treated as the constant-true predicate, so the rule
// behaves exactly as if it had been built with [RuleAlways]. A nil Then
// is rejected at construction time.
type Rule struct {
	// When is the predicate the orchestrator evaluates on every pass.
	// MUST be a pure function of [LoginContext]; the orchestrator
	// recovers from a panic in When and treats the rule as not
	// matching, but a programming error in the predicate still costs
	// a log entry and a wasted evaluation pass.
	//
	// A nil predicate matches every pass. The alternative — treating an
	// unset field as "never fires" — would let a struct literal that
	// declares a second factor compile, construct, and then authenticate
	// every user on the primary factor alone.
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
// [LoginContext.NewDevice] is true — typically chained to a stronger
// factor on first sign-in from a fresh browser.
//
// The signal comes from the configured [RiskAssessor], which sets
// [RiskOutcome.NewDevice] on the once-per-chain consult; the library
// keeps no device-trust cookie and no fingerprint store of its own, so
// there is nothing else that could answer the question. Like [RuleRisk],
// the rule therefore never fires when no assessor is wired, or when the
// wired assessor leaves the field alone — a deployment that wants this
// step-up supplies the signal from whatever device history it already
// keeps.
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
// [LoginContext.ACRValues]. The list is the parsed OIDC Core 1.0
// §3.1.2.1 `acr_values` request parameter, so the rule lets an
// embedder implement OIDC step-up: re-authenticate when the relying
// party asks for a stronger ACR than the current session asserts. The
// satisfaction predicate (which acr counts as "good enough") is the
// embedder's responsibility. RFC 9470 reuses the parameter name in
// the orthogonal RS→AS challenge direction, which the library does
// not implement.
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
// A nil pred is treated as the constant-true predicate, matching the
// [Rule.When] contract: the helper and the struct literal are two
// spellings of one rule, so they cannot disagree on what an absent
// predicate means.
func RuleWhen(pred func(LoginContext) bool, then Step) Rule {
	if pred == nil {
		pred = func(LoginContext) bool { return true }
	}
	return Rule{When: pred, Then: then}
}
