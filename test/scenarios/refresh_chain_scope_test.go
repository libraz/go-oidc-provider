package scenarios_test

// Spec:
//   - RFC 7009 §2.1 — revoking a refresh token invalidates the access
//     tokens of its grant, not the grant's other refresh tokens
//   - RFC 9700 §2.2.2 — refresh-token rotation

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestRefreshChainScope_RevokingOneChainKeepsSiblingRedeemable runs two
// sessions of one user on one client, which share a grant, and revokes the
// first session's refresh token. The second session must keep refreshing
// under every revocation strategy, and /introspect must agree with /token
// about both refresh tokens.
func TestRefreshChainScope_RevokingOneChainKeepsSiblingRedeemable(t *testing.T) {
	t.Parallel()

	for name, opts := range map[string][]op.Option{
		"grant tombstone": nil,
		"jti registry":    {op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tk, rp := newGTMProvider(t, opts...)
			first := runGTMCodeFlow(t, tk, rp)
			second := runGTMCodeFlow(t, tk, rp)
			requireSharedGrant(t, tk, first.RefreshToken, second.RefreshToken)

			if status := postRevoke(t, tk, first.RefreshToken, rp.ID, gtmClientSecret); status != http.StatusOK {
				t.Fatalf("/revoke status=%d want 200", status)
			}

			if introspectActive(t, tk, first.RefreshToken) {
				t.Error("/introspect reports the revoked refresh token active")
			}
			if !introspectActive(t, tk, second.RefreshToken) {
				t.Fatal("/introspect reports the sibling session's refresh token inactive")
			}
			if status := refreshStatus(t, tk, second.RefreshToken); status != http.StatusOK {
				t.Fatalf("sibling session refresh status=%d want 200: revoking one session ended the other", status)
			}
			if status := refreshStatus(t, tk, first.RefreshToken); status != http.StatusBadRequest {
				t.Fatalf("revoked refresh token status=%d want 400", status)
			}
		})
	}
}

// TestRefreshChainScope_RotationKeepsOtherSessionsOpaqueAccessToken runs
// two sessions of one user on one client with opaque access tokens and
// rotates the first session's refresh token. The rotation retires the
// first session's prior access token and leaves the second session's
// alone.
func TestRefreshChainScope_RotationKeepsOtherSessionsOpaqueAccessToken(t *testing.T) {
	t.Parallel()

	tk, rp := newGTMProvider(t, op.WithAccessTokenFormat(op.AccessTokenFormatOpaque))
	first := runGTMCodeFlow(t, tk, rp)
	second := runGTMCodeFlow(t, tk, rp)
	requireSharedGrant(t, tk, first.RefreshToken, second.RefreshToken)

	if status := refreshStatus(t, tk, first.RefreshToken); status != http.StatusOK {
		t.Fatalf("first session refresh status=%d want 200", status)
	}

	if introspectActive(t, tk, first.AccessToken) {
		t.Error("the rotated session's prior opaque access token is still active")
	}
	if !introspectActive(t, tk, second.AccessToken) {
		t.Fatal("rotating one session's refresh token revoked the other session's opaque access token")
	}
}

// requireSharedGrant pins the premise both tests rest on: the two sessions
// were issued under one grant.
func requireSharedGrant(t *testing.T, tk *testkit.Provider, a, b string) {
	t.Helper()
	ra, err := tk.Store.RefreshTokens().Find(context.Background(), a)
	if err != nil {
		t.Fatalf("Find first refresh token: %v", err)
	}
	rb, err := tk.Store.RefreshTokens().Find(context.Background(), b)
	if err != nil {
		t.Fatalf("Find second refresh token: %v", err)
	}
	if ra.GrantID == "" || ra.GrantID != rb.GrantID {
		t.Fatalf("sessions do not share a grant (%q vs %q); the test premise does not hold", ra.GrantID, rb.GrantID)
	}
	if ra.ChainID == rb.ChainID {
		t.Fatalf("sessions share chain %q; each code exchange must root its own chain", ra.ChainID)
	}
}

// refreshStatus presents refreshToken at /token and returns the status.
func refreshStatus(t *testing.T, tk *testkit.Provider, refreshToken string) int {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(gtmClientID, gtmClientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
