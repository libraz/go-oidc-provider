package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestParseSigned_RejectsUnsupportedRegisteredAlg_NoFailOpen pins that a
// cryptographically valid JWS whose "alg" is a registered JOSE algorithm
// the library deliberately does not enable (ES384 / RS384 / PS384) is
// rejected outright — never accepted by falling through an
// unrecognised-algorithm branch. The closed allow-list
// {RS256, PS256, ES256, EdDSA} is enforced at two layers (the underlying
// parser's permitted-algorithm list and this package's ParseAlgorithm),
// so an out-of-list alg can only surface as ErrMalformed or
// ErrAlgorithmNotAllowed, never a nil-error pass.
//
// Unlike the "none" / HMAC case-variant tokens (which carry empty
// signatures and could be rejected purely on structure), these tokens
// carry real signatures over a sibling algorithm — the only reason to
// reject them is the algorithm policy itself.
//
// Tracks: CVE-2026-28498 (Authlib at_hash / c_hash hash-binding
// verifier) — the verifier returned success when handed an unknown /
// unsupported algorithm instead of rejecting, a fail-open on the
// algorithm dimension. The structural property pinned here is the
// inverse: an algorithm outside the allow-list is a hard reject at the
// parse boundary, with no path that silently treats "unsupported" as
// "valid".
func TestParseSigned_RejectsUnsupportedRegisteredAlg_NoFailOpen(t *testing.T) {
	t.Parallel()

	const payload = `{"sub":"alice"}`

	sign := func(alg josev4.SignatureAlgorithm, key any) string {
		t.Helper()
		signer, err := josev4.NewSigner(
			josev4.SigningKey{Algorithm: alg, Key: key},
			(&josev4.SignerOptions{}).WithType("JWT"),
		)
		if err != nil {
			t.Fatalf("NewSigner(%s): %v", alg, err)
		}
		obj, err := signer.Sign([]byte(payload))
		if err != nil {
			t.Fatalf("Sign(%s): %v", alg, err)
		}
		tok, err := obj.CompactSerialize()
		if err != nil {
			t.Fatalf("CompactSerialize(%s): %v", alg, err)
		}
		return tok
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa P-384: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	cases := []struct {
		name string
		tok  string
	}{
		{"ES384", sign(josev4.ES384, ecKey)},
		{"RS384", sign(josev4.RS384, rsaKey)},
		{"PS384", sign(josev4.PS384, rsaKey)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := jose.ParseSigned(tc.tok); err == nil {
				t.Fatalf("ParseSigned accepted a valid %s JWS; an unsupported alg must be rejected", tc.name)
			} else if !errors.Is(err, jose.ErrAlgorithmNotAllowed) && !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("ParseSigned(%s) err = %v; want ErrAlgorithmNotAllowed or ErrMalformed", tc.name, err)
			}
		})
	}
}
