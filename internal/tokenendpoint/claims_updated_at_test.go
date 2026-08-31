package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// getUserInfo reads /userinfo with the supplied access token and returns
// the decoded claim set, so a test can compare the two objects that
// answer the same OIDC Core 1.0 §5.5 claims request.
func getUserInfo(tb testing.TB, f *fixture, accessToken string) map[string]any {
	tb.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, f.prov.Server.URL+"/oidc/userinfo", nil,
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("GET /userinfo status=%d want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		tb.Fatalf("decode /userinfo body: %v", err)
	}
	return out
}

// TestClaimsRequest_UpdatedAtAgreesBetweenIDTokenAndUserInfo pins the
// claim-source invariant across the two objects that answer an OIDC
// Core 1.0 §5.5 claims request for the same (subject, grant).
//
// "updated_at" is the case that exposes a split source: the library
// synthesises it from [store.User.UpdatedAt] rather than reading it out
// of [store.User.Claims], and the public field documentation promises
// the copy without limiting it to one object. An RP that mirrors the
// profile locally and keys its cache invalidation on the id_token's
// updated_at sees the claim silently absent — no error, no refusal —
// and has to fall back to a /userinfo round trip it never planned.
func TestClaimsRequest_UpdatedAtAgreesBetweenIDTokenAndUserInfo(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-claims-updated-at"
	const subject = "user-claims-updated-at"
	const grantID = "grant-claims-updated-at"
	updatedAt := time.Date(2026, 4, 20, 8, 30, 0, 0, time.UTC)

	// The embedder records the profile's last-change instant on the
	// column, which is what the store contract asks for; "updated_at" is
	// deliberately absent from the Claims map.
	f.prov.Store.PutUser(context.Background(), &store.User{
		Subject:   subject,
		Claims:    map[string]any{"email": "user@example.com"},
		UpdatedAt: updatedAt,
	})
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "profile"},
		Claims: map[string]any{
			"request": map[string]any{
				"id_token": map[string]any{
					"updated_at": map[string]any{"essential": true},
				},
				"userinfo": map[string]any{
					"updated_at": map[string]any{"essential": true},
				},
			},
		},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "profile"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idToken, _ := body["id_token"].(string)
	accessToken, _ := body["access_token"].(string)
	if idToken == "" || accessToken == "" {
		t.Fatalf("token response is missing credentials: %v", body)
	}

	want := float64(updatedAt.Unix())
	idClaims := decodeIDTokenClaims(t, idToken)
	if got := idClaims["updated_at"]; got != want {
		t.Errorf("id_token.updated_at=%v want %v", got, want)
	}
	userInfo := getUserInfo(t, f, accessToken)
	if got := userInfo["updated_at"]; got != want {
		t.Errorf("userinfo.updated_at=%v want %v", got, want)
	}
	if idClaims["updated_at"] != userInfo["updated_at"] {
		t.Errorf("id_token.updated_at=%v and userinfo.updated_at=%v disagree",
			idClaims["updated_at"], userInfo["updated_at"])
	}
}
