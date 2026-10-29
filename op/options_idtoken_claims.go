package op

import (
	"slices"

	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// WithIDTokenScopeClaims also writes the claims a scope releases at
// /userinfo into the ID Token. When a token response carries one of the
// listed scopes, the claims that scope releases are added to the ID Token
// of the authorization_code, refresh_token, device_code and CIBA grants.
// For refresh_token the scope is the one the request narrowed to. A claim
// the user record does not hold is omitted, and a claim the "claims"
// request parameter names is decided by that request's value constraints.
//
// This is a deliberate deviation from OIDC Core 1.0 §5.4, which returns
// the claims of scopes requested alongside an access token from /userinfo
// only. It lets a single-page application read the profile from the ID
// Token when its access token is audience-bound to a resource server and
// /userinfo therefore refuses it. Listing profile or address makes the ID
// Token noticeably larger.
//
// Each name MUST be profile, email, address or phone, or a custom [Scope]
// registered through [WithScope] with a non-empty Claims list. openid,
// offline_access, unregistered names and the empty string are rejected, as
// is a custom scope whose Claims contain a claim name the ID Token
// reserves (iss, sub, aud, iat, exp, auth_time, nonce, acr, amr, azp,
// at_hash, c_hash, sid). Duplicates collapse. An empty argument list is
// rejected too: "explicitly none" has no meaning here, so omit the option
// instead. Calling WithIDTokenScopeClaims more than once is rejected.
// Custom grants are unaffected; their handlers own the ID Token body.
//
// Stable since v1.5.
func WithIDTokenScopeClaims(scopes ...string) Option {
	return optionFunc(func(c *config) error {
		if c.idTokenScopeClaimsSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithIDTokenScopeClaims may be called at most once",
			}
		}
		if len(scopes) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithIDTokenScopeClaims requires at least one scope",
			}
		}
		out := make([]string, 0, len(scopes))
		for _, s := range scopes {
			switch s {
			case "":
				return &Error{
					Code:        codeConfiguration,
					Description: "WithIDTokenScopeClaims: scope name must not be empty",
				}
			case oidcscope.ScopeOpenID, "offline_access":
				return &Error{
					Code:        codeConfiguration,
					Description: "WithIDTokenScopeClaims: scope " + s + " releases no claims",
				}
			}
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
		c.idTokenScopeClaims = out
		c.idTokenScopeClaimsSet = true
		return nil
	})
}

// validateIDTokenScopeClaims checks the names against the final scope
// registry, which exists only after every option has run.
func (c *config) validateIDTokenScopeClaims() error {
	if !c.idTokenScopeClaimsSet {
		return nil
	}
	reserved := tokens.IDTokenReservedClaims()
	for _, name := range c.idTokenScopeClaims {
		s := c.scopeIndex[name]
		if len(s.Claims) == 0 {
			switch name {
			case oidcscope.ScopeProfile, oidcscope.ScopeEmail, oidcscope.ScopeAddress, oidcscope.ScopePhone:
				continue
			}
			return &Error{
				Code:        codeConfiguration,
				Description: "WithIDTokenScopeClaims: scope " + name + " is not a standard claim scope or a registered scope with Claims",
			}
		}
		for _, claim := range s.Claims {
			if _, isReserved := reserved[claim]; isReserved {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithIDTokenScopeClaims: scope " + name + " releases reserved ID Token claim " + claim,
				}
			}
		}
	}
	return nil
}
