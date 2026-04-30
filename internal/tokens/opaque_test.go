package tokens_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// TestMintOpaqueAccessToken_Length pins the wire length: 32 bytes
// encoded with base64.RawURLEncoding yields exactly 43 characters
// (RFC 4648 §5; ceil(32 * 4 / 3) = 43, padding stripped). RFC 6750
// §2.1 b64token ABNF accepts the alphabet and length verbatim.
func TestMintOpaqueAccessToken_Length(t *testing.T) {
	t.Parallel()

	got, err := tokens.MintOpaqueAccessToken()
	if err != nil {
		t.Fatalf("MintOpaqueAccessToken: %v", err)
	}
	if len(got) != 43 {
		t.Fatalf("len=%d want 43 (32 bytes base64url no-pad)", len(got))
	}
}

// TestMintOpaqueAccessToken_Alphabet verifies every character is in the
// base64url-without-padding alphabet [A-Za-z0-9_-]. A stray '+' / '/' /
// '=' would mean the encoder regressed to the standard alphabet, which
// would silently break URL-safe placement of the wire token.
func TestMintOpaqueAccessToken_Alphabet(t *testing.T) {
	t.Parallel()

	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := range 1000 {
		got, err := tokens.MintOpaqueAccessToken()
		if err != nil {
			t.Fatalf("iteration %d: MintOpaqueAccessToken: %v", i, err)
		}
		for _, r := range got {
			if !strings.ContainsRune(allowed, r) {
				t.Fatalf("iteration %d: rune %q outside RawURLEncoding alphabet (token=%q)", i, r, got)
			}
		}
	}
}

// TestMintOpaqueAccessToken_NoCollisions checks 10000 mints yield no
// collisions. 256-bit entropy has a birthday probability well below
// 1e-30 for this sample size; a collision would mean the random
// source regressed to a deterministic / low-entropy generator.
func TestMintOpaqueAccessToken_NoCollisions(t *testing.T) {
	t.Parallel()

	const iterations = 10000
	seen := make(map[string]struct{}, iterations)
	for i := range iterations {
		got, err := tokens.MintOpaqueAccessToken()
		if err != nil {
			t.Fatalf("iteration %d: MintOpaqueAccessToken: %v", i, err)
		}
		if _, dup := seen[got]; dup {
			t.Fatalf("iteration %d: collision on %q", i, got)
		}
		seen[got] = struct{}{}
	}
}

// TestMintOpaqueAccessToken_NotJWSShaped guarantees the wire token never
// looks like a JWS Compact Serialisation. RFC 7515 §3 requires JWS to
// carry exactly two '.' separators; an opaque token never carries any.
// The introspection-side dispatch (resolveOpaque / looksLikeJWT) relies
// on this invariant to choose between the JWT and opaque branches
// without consulting state.
func TestMintOpaqueAccessToken_NotJWSShaped(t *testing.T) {
	t.Parallel()

	for i := range 100 {
		got, err := tokens.MintOpaqueAccessToken()
		if err != nil {
			t.Fatalf("iteration %d: MintOpaqueAccessToken: %v", i, err)
		}
		if strings.Contains(got, ".") {
			t.Fatalf("iteration %d: token %q contains '.', would shadow a JWS dispatch", i, got)
		}
	}
}
