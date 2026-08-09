package op

import (
	"math"

	"github.com/libraz/go-oidc-provider/op/grant"
)

// builtinGrantTypeWires is the set of grant_type strings the OP serves
// with its own implementation. [WithCustomGrant] rejects any handler
// whose [CustomGrantHandler.Name] equals one of these so a
// misconfigured registration cannot displace an in-tree grant and the
// security invariants that ride with it: PKCE, refresh-token rotation,
// device-code polling, CIBA request binding, and the token-exchange
// audience narrowing / scope intersection / cnf re-binding pass.
//
// The set is derived rather than transcribed. A hand-maintained list
// disables a security control the moment it falls behind the grants
// the OP actually implements, and the drift is silent — the colliding
// registration is simply accepted. Every [grant.Type] the enumeration
// recognises therefore contributes its wire form automatically, so
// adding a grant to the enum needs no second edit here.
//
//nolint:gochecknoglobals // derived catalog; immutable after package init.
var builtinGrantTypeWires = builtinGrantTypeWireSet()

// builtinGrantTypeWireSet indexes [builtinGrantTypeWireList] for the
// membership tests the option layer runs per registration.
func builtinGrantTypeWireSet() map[string]struct{} {
	list := builtinGrantTypeWireList()
	out := make(map[string]struct{}, len(list))
	for _, wire := range list {
		out[wire] = struct{}{}
	}
	return out
}

// builtinGrantTypeWireList enumerates the grant_type wires the OP
// implements itself, in a stable order: the [grant.Type] constants by
// ordinal, then the extension grants. Callers that surface the values
// (rather than testing membership) depend on that determinism, so the
// list — not the set — is the primitive.
//
// The walk covers the whole [grant.Type] value space, the bound being
// the enum's underlying width, rather than naming constants one by
// one, so a constant added anywhere in the enum is picked up even if
// it is not appended at the end.
//
// Token exchange is the one wire with no [grant.Type] constant: it is
// enabled through [RegisterTokenExchange] rather than [WithGrants] and
// its handler rides the extension dispatcher, where a same-named
// custom registration would win the lookup outright. It is added by
// name, and a test pins the result against every extension grant the
// OP advertises so a future addition of that shape cannot slip
// through.
func builtinGrantTypeWireList() []string {
	out := make([]string, 0, 8)
	for ordinal := grant.Type(0); ; ordinal++ {
		if wire := ordinal.String(); ordinal.IsValid() && wire != "" {
			out = append(out, wire)
		}
		if ordinal == math.MaxUint8 {
			break
		}
	}
	return append(out, TokenExchangeGrantType)
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
// Stable since v1.0.
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
	if isNilLike(g) {
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

// RegisterTokenExchange enables the RFC 8693 token-exchange grant_type
// at the token endpoint, gated by the supplied [TokenExchangePolicy].
// The provider verifies subject_token / actor_token, normalises the
// requested audience, intersects the requested scope with the
// subject_token's scope and the calling client's allowed set, builds
// the act-claim chain (mandatory whenever the actor differs from the
// subject), rebinds the issued token's cnf to the request's verified
// DPoP / mTLS credential, and applies the TTL ceiling before invoking
// the policy. The policy decides whether to admit each exchange and
// MAY narrow the provider-computed defaults further.
//
// Construction-time errors:
//
//   - [ErrTokenExchangePolicyNil] — policy is nil. Token-exchange
//     requires an explicit deny-by-default hook.
//   - [ErrTokenExchangeDuplicate] — RegisterTokenExchange was already
//     invoked. The grant_type has a single canonical URN; a second
//     registration would shadow the first silently.
//
// Stable since v1.0.
func RegisterTokenExchange(policy TokenExchangePolicy) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(policy) {
			return ErrTokenExchangePolicyNil
		}
		if c.tokenExchangePolicy != nil {
			return ErrTokenExchangeDuplicate
		}
		c.tokenExchangePolicy = policy
		return nil
	})
}
