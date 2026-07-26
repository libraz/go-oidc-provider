package op

import (
	"reflect"

	"github.com/libraz/go-oidc-provider/op/store"
)

// effectiveUserStore resolves where the OP reads end-user claims from:
// the dedicated [WithUserStore] value when one was supplied, otherwise
// the Users() substore of the [WithStore] backend.
//
// Resolution rather than wrapping is the point of the option. A wrapper
// that shadows Users() has to be built out of the concrete backend type
// to keep the backend's optional capabilities visible to the type
// assertions [New] makes; building it out of the [store.Store]
// interface instead compiles cleanly and silently erases them. Choosing
// between two values here cannot lose anything, because the backend the
// rest of the library sees is the one the embedder passed.
func (c *config) effectiveUserStore() store.UserStore { //nolint:ireturn,nolintlint // store.UserStore is the substore contract.
	if !isNilLike(c.userStore) {
		return c.userStore
	}
	return c.store.Users()
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
func (c *config) warnUserStoreMismatch() {
	claims := c.effectiveUserStore()
	if isNilLike(claims) {
		return
	}
	for _, step := range c.loginFlowSteps() {
		authn, field := stepUserStore(step)
		if isNilLike(authn) || !comparableStores(authn, claims) {
			continue
		}
		if any(authn) == any(claims) {
			continue
		}
		c.logger.Warn(
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

// loginFlowSteps returns every [Step] the configured flow can run, in
// declaration order. Rules are included because a second factor may
// carry its own user store.
func (c *config) loginFlowSteps() []Step {
	if !c.loginFlowSet {
		return nil
	}
	steps := make([]Step, 0, 1+len(c.loginFlow.Rules))
	if c.loginFlow.Primary != nil {
		steps = append(steps, c.loginFlow.Primary)
	}
	for _, rule := range c.loginFlow.Rules {
		if rule.Then != nil {
			steps = append(steps, rule.Then)
		}
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
	if !isNilLike(c.userStore) {
		return "WithUserStore"
	}
	return "WithStore(...).Users()"
}
