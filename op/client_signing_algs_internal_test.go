package op

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestClientSigningAlgs_ReachEveryVerifier pins that the profile's
// client-signing alg set is the one both JAR verifiers (/authorize and
// /par, and /bc-authorize) and every endpoint's
// private_key_jwt verifier enforce, and that no profile leaves both on
// the library allow-list.
func TestClientSigningAlgs_ReachEveryVerifier(t *testing.T) {
	t.Parallel()

	fapi := []jose.Algorithm{jose.AlgPS256, jose.AlgES256, jose.AlgEdDSA}
	cases := []struct {
		name     string
		profiles []profile.Profile
		wantJAR  []jose.Algorithm
		wantPKJ  []jose.Algorithm
	}{
		{"fapi2-baseline", []profile.Profile{profile.FAPI2Baseline}, fapi, fapi},
		{"fapi2-message-signing", []profile.Profile{profile.FAPI2MessageSigning}, fapi, fapi},
		{"fapi-ciba", []profile.Profile{profile.FAPICIBA}, fapi, fapi},
		{"baseline", []profile.Profile{profile.Baseline}, []jose.Algorithm{jose.AlgRS256, jose.AlgPS256, jose.AlgES256, jose.AlgEdDSA}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config{
				issuer:   "https://op.test",
				clock:    timex.SystemClock,
				store:    inmem.New(),
				features: []feature.Flag{feature.JAR},
				profiles: tc.profiles,
			}
			jv, err := buildJARVerifiers(cfg, nil)
			if err != nil {
				t.Fatalf("buildJARVerifiers: %v", err)
			}
			for name, v := range map[string]*jar.Verifier{"authorize": jv.Authorize, "ciba": jv.CIBA} {
				if got := v.AllowedAlgs(); !slices.Equal(got, tc.wantJAR) {
					t.Errorf("%s JAR verifier algs = %v, want %v", name, got, tc.wantJAR)
				}
			}
			verifiers, err := buildAssertionVerifiers(cfg)
			if err != nil {
				t.Fatalf("buildAssertionVerifiers: %v", err)
			}
			for name, pkj := range map[string][]jose.Algorithm{
				"token":       verifiers.Token.AllowedAlgs,
				"par":         verifiers.PAR.AllowedAlgs,
				"introspect":  verifiers.Introspect.AllowedAlgs,
				"revoke":      verifiers.Revoke.AllowedAlgs,
				"device":      verifiers.Device.AllowedAlgs,
				"backchannel": verifiers.Backchannel.AllowedAlgs,
			} {
				if !slices.Equal(pkj, tc.wantPKJ) {
					t.Errorf("%s assertion verifier algs = %v, want %v", name, pkj, tc.wantPKJ)
				}
			}
		})
	}
}

// TestJARVerifiers_CIBAMustsStayOnBackchannel pins that FAPI-CIBA's
// jti / iat MUSTs on signed authentication requests reach the
// /bc-authorize verifier only: with FAPI 2.0 Message Signing also active,
// the /authorize and /par verifier keeps admitting the jti-less request
// objects that profile permits.
func TestJARVerifiers_CIBAMustsStayOnBackchannel(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-ciba-scope"
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: kid, Algorithm: string(josev4.ES256), Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	client := &store.Client{ID: "rp-ciba-scope", JWKs: jwks}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cfg := &config{
		issuer:   "https://op.test",
		clock:    fixedTestClock{t: now},
		store:    inmem.New(),
		features: []feature.Flag{feature.JAR},
		profiles: []profile.Profile{profile.FAPI2MessageSigning, profile.FAPICIBA},
	}
	jv, err := buildJARVerifiers(cfg, nil)
	if err != nil {
		t.Fatalf("buildJARVerifiers: %v", err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		(&josev4.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": client.ID, "aud": cfg.issuer, "client_id": client.ID,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"scope": "openid", "login_hint": "alice",
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	if _, err := jv.Authorize.Verify(context.Background(), raw, client.ID, client); err != nil {
		t.Errorf("jti-less request object at /authorize and /par: %v, want accepted", err)
	}
	if _, err := jv.CIBA.VerifyCIBA(context.Background(), raw, client.ID, client); !errors.Is(err, jar.ErrJTIMissing) {
		t.Errorf("jti-less request object at /bc-authorize: err=%v, want ErrJTIMissing", err)
	}
}
