package op

import (
	"reflect"

	"github.com/libraz/go-oidc-provider/op/store"
)

// effectiveUserStore resolves where the OP reads end-user claims from, in
// order: the dedicated [WithUserStore] value when one was supplied; the
// Store of the login flow's primary [PrimaryPassword] (see
// inferredUserStore); the Users() substore of the [WithStore] backend.
//
// Resolution rather than wrapping is the point of the option. A wrapper
// that shadows Users() has to be built out of the concrete backend type
// to keep the backend's optional capabilities visible to the type
// assertions [New] makes; building it out of the [store.Store]
// interface instead compiles cleanly and silently erases them. Choosing
// between values here cannot lose anything, because the backend the
// rest of the library sees is the one the embedder passed.
//
// The login-flow inference exists so the records a login resolves a
// subject from and the records claims are read from need not be wired
// twice; a deployment that wants them apart says so with
// [WithUserStore].
func (c *config) effectiveUserStore() store.UserStore { //nolint:ireturn,nolintlint // store.UserStore is the substore contract.
	if !isNilLike(c.userStore) {
		return c.userStore
	}
	if inferred := c.inferredUserStore(); inferred != nil {
		return inferred
	}
	return c.store.Users()
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
		if !ok || isNilLike(pw.Store) {
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
	if isNilLike(claims) {
		return
	}
	c.infoClaimSource(claims)
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

// infoClaimSource logs the resolved claim source once at construction,
// because the resolution order is not visible from the option list. When
// the source is not Store.Users() and that substore is a different value,
// the line also says Users() goes unread, so an empty oidc_users table
// does not read as missing data.
func (c *config) infoClaimSource(claims store.UserStore) {
	attrs := []any{"claim_source", claimSourceOption(c)}
	if backend := c.store.Users(); !isNilLike(backend) && comparableStores(claims, backend) && any(claims) != any(backend) {
		attrs = append(attrs, "store_users", "not read")
	}
	c.logger.Info("ID Token and /userinfo claims are read from claim_source", attrs...)
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
	if !isNilLike(c.userStore) {
		return "WithUserStore"
	}
	if c.inferredUserStore() != nil {
		return "LoginFlow.Primary PrimaryPassword.Store"
	}
	return "WithStore(...).Users()"
}
