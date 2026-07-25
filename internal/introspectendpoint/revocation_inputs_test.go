package introspectendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_ActiveHonoursEveryRevocationInput pins that the
// introspection endpoint's active verdict is the conjunction of every
// revocation input the deployment configured, not whichever one the code
// happens to consult first.
//
// A JWT access token can be withdrawn two ways here: the token alone can
// be denylisted by its identifier, or the whole grant it descends from
// can be tombstoned, which retires every token minted at or before the
// cascade. The two are independent — a single-token revocation leaves the
// grant alive, and a grant cascade does not enumerate the tokens it kills
// — so an implementation that returns as soon as one input answers "not
// revoked" reports a withdrawn token as active. Resource servers that
// trust introspection would then keep honouring it for the rest of its
// lifetime, which is exactly the window revocation exists to close.
//
// Tracks: CVE-2026-8922 (Keycloak) — introspection consulted the
// client-level not-before and ignored the realm-level one, so a token
// inside the revoked window still introspected as active.
func TestEndToEnd_ActiveHonoursEveryRevocationInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// withdraw applies exactly one revocation input to the token.
		// A nil value is the control: nothing is withdrawn and the
		// token must introspect as active, which is what makes the
		// other rows meaningful rather than vacuously passing.
		withdraw func(t *testing.T, tk *testkit.Provider, grantID, jti string, iat time.Time)
		want     bool
	}{
		{
			name: "nothing withdrawn",
			want: true,
		},
		{
			name: "token denylisted by identifier",
			withdraw: func(t *testing.T, tk *testkit.Provider, grantID, jti string, iat time.Time) {
				t.Helper()
				if err := tk.Store.GrantRevocations().RevokeJTI(context.Background(), store.RevokedJTI{
					JTI:       jti,
					GrantID:   grantID,
					ExpiresAt: iat.Add(24 * time.Hour),
				}); err != nil {
					t.Fatalf("RevokeJTI: %v", err)
				}
			},
			want: false,
		},
		{
			name: "originating grant tombstoned",
			withdraw: func(t *testing.T, tk *testkit.Provider, grantID, _ string, iat time.Time) {
				t.Helper()
				if err := tk.Store.GrantRevocations().RevokeGrant(context.Background(), store.GrantTombstone{
					GrantID: grantID,
					// The tombstone retires every token whose iat is at
					// or before the cascade, so it must land no earlier
					// than the token under test.
					RevokedAt: iat.Add(time.Second),
					ExpiresAt: iat.Add(24 * time.Hour),
					Reason:    "operator",
				}); err != nil {
					t.Fatalf("RevokeGrant: %v", err)
				}
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
			tk := testkit.NewProvider(t,
				testkit.WithClock(clock),
				testkit.WithOptions(op.WithFeature(feature.Introspect)),
			)
			const secret = "rp-revocation-inputs-secret" //nolint:gosec // G101: test fixture credential
			hasher := clientauth.Argon2id{}
			hash, err := hasher.Hash(secret)
			if err != nil {
				t.Fatalf("Argon2id.Hash: %v", err)
			}
			rp := tk.RegisterClient(t, testkit.ClientFixture{
				ID:                      "rp-introspect-revocation",
				SecretHash:              hash,
				TokenEndpointAuthMethod: "client_secret_basic",
			})

			const (
				grantID = "grant-revocation-inputs"
				jti     = "at-revocation-inputs"
			)
			iat := clock.now
			tok, err := tokens.SignAccessToken(
				tokens.SigningKey{KeyID: tk.SigningKey.KeyID, Signer: tk.SigningKey.Signer},
				tokens.AccessTokenClaims{
					Issuer:    tk.Issuer,
					Subject:   "user-revocation-inputs",
					Audience:  []string{tk.Issuer},
					ClientID:  rp.ID,
					GrantID:   grantID,
					IssuedAt:  iat.Unix(),
					ExpiresAt: iat.Add(time.Hour).Unix(),
					JTI:       jti,
					Scope:     []string{"openid"},
				})
			if err != nil {
				t.Fatalf("SignAccessToken: %v", err)
			}
			if tc.withdraw != nil {
				tc.withdraw(t, tk, grantID, jti, iat)
			}

			form := url.Values{"token": {tok}}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(rp.ID, secret)
			resp, err := tk.HTTPClient(nil).Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d want 200", resp.StatusCode)
			}
			body := decodeJSON(t, resp)
			got, _ := body["active"].(bool)
			if got != tc.want {
				t.Fatalf("active=%v want %v; body=%v", got, tc.want, body)
			}
			if !tc.want && len(body) != 1 {
				t.Errorf("inactive response has %d members, want exactly 1 per RFC 7662 §2.2; body=%v", len(body), body)
			}
		})
	}
}
