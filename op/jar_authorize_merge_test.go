package op_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestAuthorize_RequestObjectOuterParameters pins which parameter set
// /authorize uses beside a signed request object. Plain OIDC keeps the
// Core §6.3.3 overlay, so an outer-only prompt=none still applies and an
// unauthenticated request comes back login_required. Under a FAPI profile
// RFC 9101 §6.3 applies: the outer prompt is dropped and the request
// proceeds to login.
func TestAuthorize_RequestObjectOuterParameters(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		opts          []op.Option
		wantLoginReqd bool
	}{
		{
			name:          "plain-oidc-overlays",
			opts:          []op.Option{op.WithFeature(feature.JAR)},
			wantLoginReqd: true,
		},
		{
			name: "fapi-object-only",
			opts: []op.Option{
				op.WithGrants(grant.AuthorizationCode, grant.RefreshToken),
				op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
				op.WithProfile(profile.FAPICIBA),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
			},
			wantLoginReqd: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
			tk := testkit.NewProvider(t, testkit.WithClock(fakeClock{now: now}), testkit.WithOptions(tc.opts...))
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			const kid = "rp-merge-kid"
			jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
				Key: &priv.PublicKey, KeyID: kid, Algorithm: string(josev4.ES256), Use: "sig",
			}}})
			if err != nil {
				t.Fatalf("marshal JWKS: %v", err)
			}
			const redirect = "https://rp.test.invalid/callback"
			rp := tk.RegisterClient(t, testkit.ClientFixture{
				ID:           "rp-merge",
				PublicClient: true,
				RedirectURIs: []string{redirect},
				Scopes:       []string{"openid"},
				JWKs:         jwks,
			})

			payload, err := json.Marshal(map[string]any{
				"iss": rp.ID, "aud": tk.Issuer, "client_id": rp.ID,
				"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
				"jti":           "merge-" + tc.name,
				"response_type": "code", "redirect_uri": redirect, "scope": "openid",
				"state": "s", "nonce": "n",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			})
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
				(&josev4.SignerOptions{}).WithHeader("kid", kid))
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			jws, err := signer.Sign(payload)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			raw, err := jws.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize: %v", err)
			}

			q := url.Values{
				"client_id":     {rp.ID},
				"response_type": {"code"},
				"scope":         {"openid"},
				"request":       {raw},
				"prompt":        {"none"}, // outer-only
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				tk.Server.URL+"/oidc/auth?"+q.Encode(), http.NoBody)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			resp, err := tk.HTTPClient(nil).Do(req)
			if err != nil {
				t.Fatalf("GET /authorize: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode < 300 || resp.StatusCode >= 400 {
				t.Fatalf("status=%d want a redirect", resp.StatusCode)
			}
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			gotLoginReqd := loc.Query().Get("error") == "login_required"
			if gotLoginReqd != tc.wantLoginReqd {
				t.Errorf("Location=%s: login_required=%v, want %v", loc, gotLoginReqd, tc.wantLoginReqd)
			}
			if !tc.wantLoginReqd && loc.Query().Get("error") != "" {
				t.Errorf("Location=%s carries an error; the request object alone is a valid request", loc)
			}
		})
	}
}
