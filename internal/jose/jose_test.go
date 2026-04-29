package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// signWithCrit returns a compact-serialised JWS whose protected header
// declares the supplied "crit" extension list. The extras map populates
// the protected header members named in crit so the produced JWS is
// well-formed JSON; signature validity is irrelevant because
// [jose.ParseSigned] runs before any signature work.
func signWithCrit(t testing.TB, crit []string, extras map[josev4.HeaderKey]any) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	opts := (&josev4.SignerOptions{}).WithCritical(crit...)
	for k, v := range extras {
		opts = opts.WithHeader(k, v)
	}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		opts,
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(map[string]any{"sub": "u-1"}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

func TestParseSigned_AcceptsTokenWithoutCrit(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		(&josev4.SignerOptions{}).WithHeader("kid", "test-1"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(map[string]any{"sub": "u-1"}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if _, _, err := jose.ParseSigned(tok); err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
}

// TestParseSigned_RejectsCritB64Smuggling pins the exact RFC 8725 §3.5
// scenario the audit flagged: a JWS protected header carrying
// `{"crit":["b64"],"b64":false}` is a JWS Unencoded Payload Option
// smuggle attempt that, on a verifier ignoring "crit", would let the
// payload bytes appear unencoded between the dots and bypass the
// integrity check the JWS structure was supposed to provide.
func TestParseSigned_RejectsCritB64Smuggling(t *testing.T) {
	t.Parallel()

	tok := signWithCrit(t, []string{"b64"}, map[josev4.HeaderKey]any{
		josev4.HeaderKey("b64"): false,
	})
	_, _, err := jose.ParseSigned(tok)
	if !errors.Is(err, jose.ErrCriticalHeader) {
		t.Fatalf("ParseSigned err = %v; want ErrCriticalHeader", err)
	}
}

func TestParseSigned_RejectsArbitraryCritValues(t *testing.T) {
	t.Parallel()

	// "b64" is covered by TestParseSigned_RejectsCritB64Smuggling above —
	// go-jose's serializer rejects non-boolean "b64" values during signing,
	// so the smuggle test exercises that name with the spec-shaped value.
	for _, name := range []string{"nested", "x-myorg.bypass", "exp"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tok := signWithCrit(t, []string{name}, map[josev4.HeaderKey]any{
				josev4.HeaderKey(name): "any",
			})
			_, _, err := jose.ParseSigned(tok)
			if !errors.Is(err, jose.ErrCriticalHeader) {
				t.Fatalf("ParseSigned err = %v; want ErrCriticalHeader", err)
			}
		})
	}
}

func TestParseSigned_RejectsCritWithMultipleEntries(t *testing.T) {
	t.Parallel()

	tok := signWithCrit(t, []string{"b64", "x-foo"}, map[josev4.HeaderKey]any{
		josev4.HeaderKey("b64"):   false,
		josev4.HeaderKey("x-foo"): "x",
	})
	_, _, err := jose.ParseSigned(tok)
	if !errors.Is(err, jose.ErrCriticalHeader) {
		t.Fatalf("ParseSigned err = %v; want ErrCriticalHeader", err)
	}
}
