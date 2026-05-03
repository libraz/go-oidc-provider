package op

// builtinGrantTypeWires is the closed list of grant_type strings the
// token endpoint routes natively. [WithCustomGrant] rejects any
// handler whose [CustomGrantHandler.Name] equals one of these so a
// misconfigured registration cannot shadow built-in security
// invariants (PKCE, refresh-token rotation, device-code polling).
//
//nolint:gochecknoglobals // closed catalog; immutable.
var builtinGrantTypeWires = map[string]struct{}{
	"authorization_code": {},
	"refresh_token":      {},
	"client_credentials": {},
	"urn:ietf:params:oauth:grant-type:device_code": {},
}

// secretLikeFormParameters is the closed list of token-endpoint
// parameter names that MUST NOT appear in [ParamPolicy.DupesAllowed].
// Each name is a credential or PKCE / refresh-token surface where a
// silent multi-value handling would let a misconfigured handler
// downgrade authentication or proof-of-possession to the weakest
// presented value.
//
//nolint:gochecknoglobals // closed catalog; immutable.
var secretLikeFormParameters = map[string]struct{}{
	"grant_type":            {},
	"client_id":             {},
	"client_secret":         {},
	"code":                  {},
	"code_verifier":         {},
	"refresh_token":         {},
	"subject_token":         {},
	"actor_token":           {},
	"password":              {},
	"client_assertion":      {},
	"client_assertion_type": {},
}

// WithCustomGrant registers an embedder-defined grant_type at the
// token endpoint. The handler runs after client authentication and
// before token issuance, with parameters parsed according to the
// supplied [ParamPolicy]. Multiple invocations register multiple
// handlers; collisions with the built-in grant_type strings or with
// a previously registered custom name are rejected at construction
// time, as is a [ParamPolicy.DupesAllowed] entry that names a
// security-sensitive parameter.
//
// The dispatch order matches the registration order, but the order
// is observable only when a single handler claims multiple Names
// (which the API forbids). The OP does not interpret the response
// values cryptographically; access-token / refresh-token / id_token
// shaping, scope intersection, and TTL bounds are all OP-side.
//
// Stable since v0.9.1.
func WithCustomGrant(g CustomGrantHandler) Option {
	return optionFunc(func(c *config) error {
		name, err := validateCustomGrantIdentity(g)
		if err != nil {
			return err
		}
		if err := validateCustomGrantAgainstConfig(c, g, name); err != nil {
			return err
		}
		c.customGrants = append(c.customGrants, g)
		return nil
	})
}

// validateCustomGrantIdentity asserts the handler is non-nil, has a
// non-empty Name, and does not collide with a built-in grant_type
// wire. The returned name is the one the dispatcher will index by.
func validateCustomGrantIdentity(g CustomGrantHandler) (string, error) {
	if g == nil {
		return "", ErrCustomGrantNil
	}
	name := g.Name()
	if name == "" {
		return "", ErrCustomGrantNameEmpty
	}
	if _, builtin := builtinGrantTypeWires[name]; builtin {
		return "", ErrCustomGrantBuiltinCollision
	}
	return name, nil
}

// validateCustomGrantAgainstConfig asserts the supplied handler does
// not duplicate a previously registered Name and that its ParamPolicy
// does not list a security-sensitive parameter under DupesAllowed.
// The check runs against the live config so registration order is
// observable in the error path.
func validateCustomGrantAgainstConfig(c *config, g CustomGrantHandler, name string) error {
	for _, prior := range c.customGrants {
		if prior.Name() == name {
			return ErrCustomGrantDuplicate
		}
	}
	for _, dup := range g.ParamPolicy().DupesAllowed {
		if _, secret := secretLikeFormParameters[dup]; secret {
			return ErrCustomGrantSecretLikeExempt
		}
	}
	return nil
}

// customGrantHandlers returns the registered handlers in registration
// order. The internal dispatcher and the discovery builder both
// consult this; exposing it as a method (rather than a public
// accessor) keeps the slice read-only outside the option layer.
func (c *config) customGrantHandlers() []CustomGrantHandler {
	if len(c.customGrants) == 0 {
		return nil
	}
	out := make([]CustomGrantHandler, len(c.customGrants))
	copy(out, c.customGrants)
	return out
}
