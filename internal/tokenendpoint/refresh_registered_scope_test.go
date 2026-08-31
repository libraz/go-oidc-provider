package tokenendpoint_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestRefresh_NarrowedClientScopesRejectWithoutConsumingTheChain pins the
// containment property a live refresh chain owes the registration behind
// it: the scope set an access token is issued against must be a subset of
// the client's CURRENT registered Scopes, not the set that was current
// when the chain was created.
//
// Narrowing a compromised client's registration already stops /authorize,
// /device_authorization and client_credentials. Without this check, the
// running refresh chains keep minting access tokens at the original scope
// for as long as the client keeps refreshing, and containment needs the
// coarser step of revoking the grants outright.
//
// The rejection MUST land before the exchanger consumes the presented
// token: the operator's next move is to widen the registration back or to
// revoke the grant, and a rejection that spent the token would have
// destroyed the chain either way.
func TestRefresh_NarrowedClientScopesRejectWithoutConsumingTheChain(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-narrowed-registration"
	const grantID = "grant-narrowed-registration"
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  grantID,
		Scope:    []string{"openid", "email"},
	})

	// Incident response: the client loses "email" while the chain is live.
	client.Scopes = []string{"openid"}
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer func() { _ = resp.Body.Close() }()
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, body)
	}
	if got := body["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}

	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Error("the rejected rotation consumed the presented refresh token")
	}
	if rec.Revoked {
		t.Error("the rejected rotation revoked the presented refresh token")
	}

	// Widening the registration back restores the chain, which is what makes
	// the rejection a containment step rather than a destructive one.
	client.Scopes = []string{"openid", "email"}
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	restored := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer func() { _ = restored.Body.Close() }()
	if restored.StatusCode != http.StatusOK {
		t.Fatalf("restored status=%d want 200, body=%v", restored.StatusCode, decodeJSON(t, restored))
	}
}
