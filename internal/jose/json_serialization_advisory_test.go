package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestParseSigned_RejectsJSONSerialisationShapes pins that ParseSigned is
// compact-only: a correctly signed flattened single-signature JSON JWS and a
// signature-less JSON object both fail as malformed, so no payload is ever
// surfaced from a non-compact serialisation.
//
// Tracks: CVE-2026-96760 (Authlib — JSON-serialised JWS with no signature
// returned its payload as verified)
func TestParseSigned_RejectsJSONSerialisationShapes(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.ES256, Key: key}, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	obj, err := signer.Sign([]byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	flattened := obj.FullSerialize()
	if !strings.Contains(flattened, `"signature"`) {
		t.Fatalf("unexpected serialisation: %s", flattened)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	cases := []struct {
		name string
		raw  string
	}{
		{"flattened signed", flattened},
		{"flattened hand-built", `{"payload":"eyJzdWIiOiJhbGljZSJ9",` +
			`"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"AAAA"}`},
		{"payload only", `{"payload":"eyJzdWIiOiJhbGljZSJ9"}`},
		{"empty signatures", `{"payload":"eyJzdWIiOiJhbGljZSJ9","signatures":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jws, _, err := jose.ParseSigned(tc.raw)
			if err == nil || jws != nil {
				t.Fatalf("accepted non-compact JWS: jws=%v err=%v", jws, err)
			}
			if !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("err=%v want ErrMalformed", err)
			}
		})
	}

	// Control: the compact form of the same signed object parses.
	if _, _, err := jose.ParseSigned(compact); err != nil {
		t.Fatalf("compact control rejected: %v", err)
	}
}
