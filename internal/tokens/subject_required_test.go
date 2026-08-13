package tokens_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// TestSignIDToken_EmptySubjectRejected pins the signing precondition:
// OIDC Core 1.0 §2 makes "sub" REQUIRED, and a signed id_token asserting
// the empty subject is worse than no token at all — a relying party that
// checks only the signature, issuer, and audience accepts it and maps
// every such token onto the same empty-string account key. The package
// refuses to produce one no matter which caller assembled the claims.
func TestSignIDToken_EmptySubjectRejected(t *testing.T) {
	t.Parallel()
	key := newTestSigner(t)

	jws, err := tokens.SignIDToken(key, tokens.IDTokenClaims{
		Issuer:    "https://op.example",
		Audience:  []string{"client-1"},
		IssuedAt:  1700000000,
		ExpiresAt: 1700003600,
	})
	if !errors.Is(err, tokens.ErrSubjectMissing) {
		t.Fatalf("err = %v, want ErrSubjectMissing", err)
	}
	if jws != "" {
		t.Errorf("token returned alongside the error: %q", jws)
	}
}

// TestSignAccessToken_EmptySubjectRejected pins the same precondition on
// the RFC 9068 §2.2 access token: a resource server authorising on "sub"
// would otherwise read the empty string as a principal.
func TestSignAccessToken_EmptySubjectRejected(t *testing.T) {
	t.Parallel()
	key := newTestSigner(t)

	jws, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer:    "https://op.example",
		Audience:  []string{"https://rs.example"},
		ClientID:  "client-1",
		IssuedAt:  1700000000,
		ExpiresAt: 1700003600,
		JTI:       "jti-1",
		Scope:     []string{"openid"},
	})
	if !errors.Is(err, tokens.ErrSubjectMissing) {
		t.Fatalf("err = %v, want ErrSubjectMissing", err)
	}
	if jws != "" {
		t.Errorf("token returned alongside the error: %q", jws)
	}
}
