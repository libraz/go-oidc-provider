package jose_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

func TestSignCompact_RoundTrip(t *testing.T) {
	t.Parallel()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name string
		alg  jose.Algorithm
		run  func() (string, any, error)
	}{
		{"ES256", jose.AlgES256, func() (string, any, error) {
			s, err := jose.SignCompact(ec, jose.AlgES256, "k1", map[string]any{"sub": "c"})
			return s, ec.Public(), err
		}},
		{"PS256", jose.AlgPS256, func() (string, any, error) {
			s, err := jose.SignCompact(rsaKey, jose.AlgPS256, "k1", map[string]any{"sub": "c"})
			return s, rsaKey.Public(), err
		}},
		{"EdDSA", jose.AlgEdDSA, func() (string, any, error) {
			s, err := jose.SignCompact(ed, jose.AlgEdDSA, "k1", map[string]any{"sub": "c"})
			return s, ed.Public(), err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, pub, err := tc.run()
			if err != nil {
				t.Fatalf("SignCompact: %v", err)
			}
			obj, err := josev4.ParseSignedCompact(raw, []josev4.SignatureAlgorithm{josev4.SignatureAlgorithm(tc.alg)})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if kid := obj.Signatures[0].Header.KeyID; kid != "k1" {
				t.Fatalf("kid = %q, want k1", kid)
			}
			payload, err := obj.Verify(pub)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil || claims["sub"] != "c" {
				t.Fatalf("claims = %v (%v)", claims, err)
			}
		})
	}
}

func TestSignCompact_RejectsMismatchedKey(t *testing.T) {
	t.Parallel()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := jose.SignCompact(ec, jose.AlgPS256, "k1", map[string]any{}); !errors.Is(err, jose.ErrUnsupportedKeyShape) {
		t.Fatalf("err = %v, want ErrUnsupportedKeyShape", err)
	}
	if _, err := jose.SignCompact(ec, jose.Algorithm("none"), "k1", map[string]any{}); err == nil {
		t.Fatal("alg none accepted")
	}
}
