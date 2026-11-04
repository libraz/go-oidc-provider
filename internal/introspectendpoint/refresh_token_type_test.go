package introspectendpoint_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestHandler_RefreshToken_CarriesNoAccessTokenType pins that an active
// refresh token is never described with an access-token type: RFC 7662
// §2.2 defines token_type as the RFC 6749 §5.1 access-token type, so a
// "Bearer" tag on a refresh token would tell a resource server it may
// treat the value as an access token.
//
// Tracks: CVE-2025-7043 (another OP — a refresh token was accepted as an
// access token at protected resources).
func TestHandler_RefreshToken_CarriesNoAccessTokenType(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-type")
	rec := &store.RefreshToken{
		ID:        "rt-type-1",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now,
	}
	f.saveRefreshToken(t, rec)
	resp := f.post(t, url.Values{"token": {rec.ID}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
	if tt, ok := body["token_type"]; ok {
		t.Errorf("token_type=%v on a refresh token; want the member absent", tt)
	}
}
