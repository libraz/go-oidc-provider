package jar_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestNewVerifier_IsolatedFromCallerConfig pins that NewVerifier snapshots
// its config: appending to or overwriting the caller's AllowedAlgs and
// flipping other fields after construction leaves the verifier's behaviour
// unchanged.
//
// Tracks: CVE-2026-103001 (PyJWT — decode() mutated a caller-supplied options
// dict, silently disabling claim verification on reuse)
func TestNewVerifier_IsolatedFromCallerConfig(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv, keys := jtiKey(t, testKID)

	claims := func(jti string) map[string]any {
		c := happyClaims(now)
		c["nbf"] = now.Unix()
		if jti != "" {
			c["jti"] = jti
		}
		return c
	}
	es256 := signClaims(t, priv, testKID, claims("iso-1"), josev4.ES256)
	noJTI := signClaims(t, priv, testKID, claims(""), josev4.ES256)

	t.Run("allow-list narrower than token alg stays narrow", func(t *testing.T) {
		t.Parallel()
		cfg := jar.VerifierConfig{
			Issuer:      testIssuer,
			Resolver:    &staticResolver{keys: keys},
			Clock:       fakeClock{now: now},
			AllowedAlgs: []jose.Algorithm{jose.AlgPS256},
			JTIs:        inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs(),
		}
		v, err := jar.NewVerifier(cfg)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		// In-place overwrite and append on the caller's slice.
		cfg.AllowedAlgs[0] = jose.AlgES256
		cfg.AllowedAlgs = append(cfg.AllowedAlgs, jose.Algorithm("HS256"), jose.Algorithm("none"))
		cfg.Issuer = "https://attacker.example.com"
		cfg.AllowMissingJTI = true
		cfg.JTIs = nil

		_, err = v.Verify(context.Background(), es256, testClientID, newClient())
		if !errors.Is(err, jar.ErrAlgNotAllowed) {
			t.Fatalf("err=%v want ErrAlgNotAllowed", err)
		}
	})

	t.Run("allow-list containing token alg stays intact", func(t *testing.T) {
		t.Parallel()
		cfg := jar.VerifierConfig{
			Issuer:      testIssuer,
			Resolver:    &staticResolver{keys: keys},
			Clock:       fakeClock{now: now},
			AllowedAlgs: []jose.Algorithm{jose.AlgES256},
			JTIs:        inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs(),
		}
		v, err := jar.NewVerifier(cfg)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		cfg.AllowedAlgs[0] = jose.AlgPS256
		cfg.Issuer = "https://attacker.example.com"
		cfg.Clock = fakeClock{now: now.Add(24 * time.Hour)}
		cfg.MaxAge = time.Nanosecond

		if _, err := v.Verify(context.Background(), es256, testClientID, newClient()); err != nil {
			t.Fatalf("Verify after config mutation: %v", err)
		}
	})

	t.Run("jti requirement survives opt-out after construction", func(t *testing.T) {
		t.Parallel()
		cfg := jar.VerifierConfig{
			Issuer:   testIssuer,
			Resolver: &staticResolver{keys: keys},
			Clock:    fakeClock{now: now},
			JTIs:     inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs(),
		}
		v, err := jar.NewVerifier(cfg)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		cfg.AllowMissingJTI = true
		cfg.AllowMissingNbf = true
		cfg.JTIs = nil

		_, err = v.Verify(context.Background(), noJTI, testClientID, newClient())
		if !errors.Is(err, jar.ErrJTIMissing) {
			t.Fatalf("err=%v want ErrJTIMissing", err)
		}
	})
}

// TestVerify_RejectsNonObjectPayloads pins that a correctly signed request
// object whose payload is not a JSON object is rejected as malformed.
//
// Tracks: CVE-2026-107723 (fast-jwt — claim validation silently skipped when
// the payload was a JSON array)
func TestVerify_RejectsNonObjectPayloads(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: testKID, Algorithm: string(josev4.ES256), Use: "sig",
	}}}
	v := newTestVerifier(t, now, keys)

	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: josev4.JSONWebKey{Key: priv, KeyID: testKID}},
		(&josev4.SignerOptions{}).WithType("oauth-authz-req+jwt"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	for name, tc := range map[string]struct {
		payload any
		want    error
	}{
		"array": {[]any{}, jar.ErrParse},
		// null decodes to an empty claim bag and is stopped by the first required-claim check.
		"null":   {nil, jar.ErrIssMismatch},
		"string": {"s", jar.ErrParse},
		"number": {1, jar.ErrParse},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			obj, err := signer.Sign(body)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			raw, err := obj.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize: %v", err)
			}
			got, err := v.Verify(context.Background(), raw, testClientID, newClient())
			if err == nil || got != nil {
				t.Fatalf("accepted payload %s: %+v err=%v", name, got, err)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}
}
