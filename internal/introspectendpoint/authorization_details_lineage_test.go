package introspectendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// laterDetails is what a later authorization on the same (subject,
// client) grant added.
var laterDetails = []map[string]any{{"type": "payment", "amount": "900"}}

func saveGrantWithDetails(tb testing.TB, f *fixture, id, subject, clientID string) {
	tb.Helper()
	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID: id, Subject: subject, ClientID: clientID, Scope: []string{"openid"},
		AuthorizationDetails: laterDetails,
		CreatedAt:            f.clock.now, UpdatedAt: f.clock.now,
	}); err != nil {
		tb.Fatalf("Grants.Save: %v", err)
	}
}

func introspectDetails(tb testing.TB, f *fixture, token, clientID, secret string) (any, bool) {
	tb.Helper()
	resp := f.post(tb, url.Values{"token": {token}}, clientID, secret)
	defer resp.Body.Close()
	body := decodeJSON(tb, resp)
	if resp.StatusCode != http.StatusOK || body["active"] != true {
		tb.Fatalf("status=%d body=%v want an active token", resp.StatusCode, body)
	}
	got, ok := body["authorization_details"]
	return got, ok
}

// TestHandler_OpaqueAccessToken_DetailsComeFromTheToken introspects an
// opaque token issued without authorization_details after a later
// authorization added some to its grant.
func TestHandler_OpaqueAccessToken_DetailsComeFromTheToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-own-details")
	saveGrantWithDetails(t, f, "grant-opaque-own-details", "user-opaque-own-details", client.ID)
	f.saveOpaqueAccessToken(t, &store.OpaqueAccessToken{
		ID: "opaque-own-details", GrantID: "grant-opaque-own-details",
		Subject: "user-opaque-own-details", ClientID: client.ID, Scope: []string{"openid"},
		Audience: f.prov.Issuer, IssuedAt: f.clock.now, ExpiresAt: f.clock.now.Add(time.Hour),
		AuthorizationRecorded: true,
	})

	if got, ok := introspectDetails(t, f, "opaque-own-details", client.ID, secret); ok {
		t.Errorf("authorization_details=%v; the grant's later details leaked onto the token", got)
	}
}

// TestHandler_RefreshToken_DetailsComeFromTheChain introspects a refresh
// token whose chain recorded no authorization_details while its grant has
// since gained some.
func TestHandler_RefreshToken_DetailsComeFromTheChain(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-own-details")
	saveGrantWithDetails(t, f, "grant-rt-own-details", "user-rt-own-details", client.ID)
	f.saveRefreshToken(t, &store.RefreshToken{
		ID: "rt-own-details", ClientID: client.ID, Subject: "user-rt-own-details",
		GrantID: "grant-rt-own-details", Scope: []string{"openid"},
		ExpiresAt: f.clock.now.Add(time.Hour), CreatedAt: f.clock.now,
		AuthorizationRecorded: true,
	})

	if got, ok := introspectDetails(t, f, "rt-own-details", client.ID, secret); ok {
		t.Errorf("authorization_details=%v; the grant's later details leaked onto the chain", got)
	}
}

// TestHandler_ExchangeRootedRefreshToken_IgnoresInheritedGrant introspects
// a token-exchange refresh token, which inherits the subject_token's grant
// — another client's consent — written before chains recorded their state.
func TestHandler_ExchangeRootedRefreshToken_IgnoresInheritedGrant(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-exchange-rt")
	saveGrantWithDetails(t, f, "grant-subject-token", "user-exchange-rt", "client-subject-token")
	f.saveRefreshToken(t, &store.RefreshToken{
		ID: "rt-exchange", ClientID: client.ID, Subject: "user-exchange-rt",
		GrantID: "grant-subject-token", Scope: []string{"openid"},
		Origin:    store.RefreshOriginCustomGrant,
		ExpiresAt: f.clock.now.Add(time.Hour), CreatedAt: f.clock.now,
	})

	if got, ok := introspectDetails(t, f, "rt-exchange", client.ID, secret); ok {
		t.Errorf("authorization_details=%v; the subject_token client's grant leaked onto the exchange chain", got)
	}
}
