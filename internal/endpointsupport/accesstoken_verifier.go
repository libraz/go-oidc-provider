package endpointsupport

import (
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// NewAccessTokenVerifier builds the [tokens.AccessTokenVerifier] the
// bearer-consuming endpoints share. A nil clock leaves the verifier's
// own default (the system clock) and a non-positive leeway resolves to
// [tokens.DefaultLeeway]; RequireJTI follows the configured revocation
// strategy.
func NewAccessTokenVerifier(
	set *keys.Set,
	issuer string,
	clock tokens.Clock,
	leeway time.Duration,
	strategy store.AccessTokenRevocationStrategy,
) *tokens.AccessTokenVerifier {
	if leeway <= 0 {
		leeway = tokens.DefaultLeeway
	}
	return &tokens.AccessTokenVerifier{
		Keys:       set,
		Issuer:     issuer,
		Clock:      clock,
		Leeway:     leeway,
		RequireJTI: revocation.RequireJTIFor(strategy),
	}
}

// OrderTokenBranches returns the resolver branches to try for a
// presented token: the JWT branch only when the token is JWS-shaped,
// and the opaque branch first when the caller's token_type_hint named a
// refresh token. An unrecognised or absent hint prefers JWT first, per
// the RFC 7662 §2.1 / RFC 7009 §2.1 fallthrough rule.
func OrderTokenBranches[F any](refreshHinted, jwtShaped bool, jwt, opaque F) []F {
	switch {
	case !jwtShaped:
		return []F{opaque}
	case refreshHinted:
		return []F{opaque, jwt}
	default:
		return []F{jwt, opaque}
	}
}
