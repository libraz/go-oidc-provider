package tokenendpoint_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestAuthCode_RegisteredScopesReappliedAtRedemption pins that narrowing
// a client's registered Scopes after an authorization code was issued
// stops the code from minting at the pre-narrowing scope, the same
// re-check the refresh, device-code and CIBA redemptions apply.
func TestAuthCode_RegisteredScopesReappliedAtRedemption(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const (
		codeID  = "code-narrowed-scope"
		grantID = "grant-narrowed-scope"
	)
	redirect := client.RedirectURIs[0]
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-narrowed-scope",
	})
	client.Scopes = []string{"openid"}
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}
	if _, ok := body["access_token"]; ok {
		t.Error("access_token issued at a scope the client is no longer registered for")
	}
}
