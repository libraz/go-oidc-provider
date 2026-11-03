package op

import (
	"reflect"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/store"
)

// effectiveUserStore resolves where the OP reads end-user claims from, in
// order: a [WithUserStore] value given explicitly; the Store of the login
// flow's primary [PrimaryPassword] (see inferredUserStore); a
// [WithUserStore] value that arrived through [WithDefaults]. It returns
// nil when none is set.
//
// A defaulted value ranks last so a harness that supplies a baseline user
// store (the testkit does) does not override the store a login flow
// authenticates against.
//
// The login-flow inference exists so the records a login resolves a
// subject from and the records claims are read from need not be wired
// twice; a deployment that wants them apart says so with
// [WithUserStore].
func (c *config) effectiveUserStore() store.UserStore { //nolint:ireturn,nolintlint // store.UserStore is the substore contract.
	if !nilcheck.IsNil(c.userStore) && !c.userStoreDefaulted() {
		return c.userStore
	}
	if inferred := c.inferredUserStore(); inferred != nil {
		return inferred
	}
	if !nilcheck.IsNil(c.userStore) {
		return c.userStore
	}
	return nil
}

// userStoreDefaulted reports whether the [WithUserStore] value came from
// [WithDefaults] rather than an explicit option.
func (c *config) userStoreDefaulted() bool {
	return c.claimed["WithUserStore"].fallback
}

// inferredUserStore returns the Store of the login flow's primary
// [PrimaryPassword], or of the first [PrimaryPassword] inside a primary
// [StepOneOf]. It returns nil when no login flow is set or no such step
// carries a usable Store.
func (c *config) inferredUserStore() store.UserStore { //nolint:ireturn,nolintlint // store.UserStore is the substore contract.
	if !c.loginFlowSet {
		return nil
	}
	candidates := []Step{c.loginFlow.Primary}
	if oneOf, ok := c.loginFlow.Primary.(StepOneOf); ok {
		candidates = oneOf.Steps
	}
	for _, s := range candidates {
		pw, ok := s.(PrimaryPassword)
		if !ok || nilcheck.IsNil(pw.Store) {
			continue
		}
		return pw.Store
	}
	return nil
}

// warnUserStoreMismatch reports a login flow that authenticates against
// different user records than the ones the OP serves claims from.
//
// The two wirings are separate on purpose — a [Step] owns its own store
// so a deployment can authenticate against something that is not the
// claim source at all — but the ordinary case is that they are the same
// records, and when they accidentally diverge nothing fails: the login
// succeeds, a subject is resolved, and the ID Token is then assembled
// from a row that belongs to a different table. That is a
// misconfiguration only a warning can surface.
//
// Values that cannot be compared (a store whose dynamic type is not
// comparable) are left alone rather than guessed at: reporting a
// mismatch that may not exist would train the reader to ignore the
// line.
//
// The resolved claim source itself is always reported at INFO, since it
// is the answer to "which records does the ID Token come from".
func (c *config) warnUserStoreMismatch() {
	claims := c.effectiveUserStore()
	if nilcheck.IsNil(claims) {
		return
	}
	c.infoClaimSource()
	for _, step := range c.loginFlowSteps() {
		authn, field := stepUserStore(step)
		if nilcheck.IsNil(authn) || !comparableStores(authn, claims) {
			continue
		}
		if any(authn) == any(claims) {
			continue
		}
		c.startupLog().Warn(
			"the login flow authenticates against a different user store than "+
				"the one claims are read from; a login will resolve a subject "+
				"from one set of records and then serve the ID Token and "+
				"/userinfo from another",
			"step", string(step.Kind()),
			"step_field", field,
			"claim_source", claimSourceOption(c),
		)
	}
}

// infoClaimSource logs the resolved claim source once at construction,
// because the resolution order is not visible from the option list.
func (c *config) infoClaimSource() {
	c.startupLog().Info("resolved the source of ID Token and /userinfo claims", "claim_source", claimSourceOption(c))
}

// loginFlowSteps returns every [Step] the configured flow can run, in
// declaration order, with each [StepOneOf] followed by its inner steps.
// Rules are included because a second factor may carry its own user
// store.
func (c *config) loginFlowSteps() []Step {
	if !c.loginFlowSet {
		return nil
	}
	steps := make([]Step, 0, 1+len(c.loginFlow.Rules))
	add := func(s Step) {
		if s == nil {
			return
		}
		steps = append(steps, s)
		if oneOf, ok := s.(StepOneOf); ok {
			steps = append(steps, oneOf.Steps...)
		}
	}
	add(c.loginFlow.Primary)
	for _, rule := range c.loginFlow.Rules {
		add(rule.Then)
	}
	return steps
}

// stepUserStore returns the user-record store a built-in step reads,
// plus the field name to name in a warning. Steps that carry no user
// store — and embedder-supplied steps, whose internals the library
// cannot inspect — return nil.
func stepUserStore(s Step) (store.UserStore, string) { //nolint:ireturn,nolintlint // store.UserStore is the substore contract.
	switch step := s.(type) {
	case PrimaryPassword:
		return step.Store, "Store"
	case StepEmailOTP:
		return step.Users, "Users"
	default:
		return nil, ""
	}
}

// comparableStores reports whether the two values may be compared with
// ==. Comparing non-comparable dynamic types panics, and a store is
// free to be a struct holding a map.
func comparableStores(a, b store.UserStore) bool {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	return av.IsValid() && bv.IsValid() && av.Comparable() && bv.Comparable()
}

// claimSourceOption names the option the claim side came from, so the
// warning points at the wiring to fix rather than at an address.
func claimSourceOption(c *config) string {
	if !nilcheck.IsNil(c.userStore) && (!c.userStoreDefaulted() || c.inferredUserStore() == nil) {
		return "WithUserStore"
	}
	return "LoginFlow.Primary PrimaryPassword.Store"
}
