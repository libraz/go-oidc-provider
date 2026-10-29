package rs

import (
	"context"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// Token is a verified access token.
//
// Stable since v1.5.
type Token struct {
	// Subject is the "sub" claim. For a client_credentials token it is the
	// client's own identifier.
	Subject string

	// ClientID is the "client_id" claim: the client the token was issued to.
	ClientID string

	// Scopes is the "scope" claim split on spaces.
	Scopes []string

	// ACR is the "acr" claim, empty when absent.
	ACR string

	// AMR is the "amr" claim, nil when absent.
	AMR []string

	// AuthTime is the "auth_time" claim, zero when absent.
	AuthTime time.Time

	// ExpiresAt is the "exp" claim, zero when an introspection response
	// omitted it.
	ExpiresAt time.Time

	// Binding is the sender constraint the token carried and the request
	// satisfied.
	Binding Binding

	// Claims holds every member of the JWT payload or introspection
	// response, decoded by encoding/json (numbers are float64).
	Claims map[string]any

	scheme     authScheme
	verifiedAt time.Time
}

// Binding is the sender constraint of a [Token], from its "cnf" claim.
// Both fields are empty for a bearer token.
//
// Stable since v1.5.
type Binding struct {
	// JKT is cnf.jkt, the RFC 7638 thumbprint of the DPoP key
	// (RFC 9449 §6).
	JKT string

	// CertThumbprint is cnf.x5t#S256, the SHA-256 thumbprint of the
	// client certificate (RFC 8705 §3.1).
	CertThumbprint string
}

// tokenKey is the context key [Verifier.Middleware] stores the token under.
type tokenKey struct{}

// FromContext returns the token [Verifier.Middleware] verified for the
// request whose context ctx is.
//
// Stable since v1.5.
func FromContext(ctx context.Context) (*Token, bool) {
	tok, ok := ctx.Value(tokenKey{}).(*Token)
	return tok, ok && tok != nil
}

func newToken(c *tokens.AccessTokenClaims, all map[string]any, b Binding, scheme authScheme, now time.Time) *Token {
	tok := &Token{
		Subject:    c.Subject,
		ClientID:   c.ClientID,
		Scopes:     slices.Clone(c.Scope),
		ACR:        c.ACR,
		AMR:        slices.Clone(c.AMR),
		Binding:    b,
		Claims:     all,
		scheme:     scheme,
		verifiedAt: now,
	}
	if c.AuthTime > 0 {
		tok.AuthTime = time.Unix(c.AuthTime, 0).UTC()
	}
	if c.ExpiresAt > 0 {
		tok.ExpiresAt = time.Unix(c.ExpiresAt, 0).UTC()
	}
	return tok
}
