package tokenendpoint_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// The record-dependent gates of the authorization_code exchange (scope
// allowlist, registered scopes, public-client PKCE downgrade, dpop_jkt
// binding) run before the code is consumed. A request that fails them is
// refused without spending the code, so whoever presented it cannot burn
// the owner's redemption.

// assertCodeUnconsumed fails the test when code was consumed or removed.
func assertCodeUnconsumed(tb testing.TB, f *fixture, code string) {
	tb.Helper()
	stored, err := f.prov.Store.AuthorizationCodes().Find(context.Background(), code)
	if err != nil {
		tb.Fatalf("the refused exchange consumed or removed the code: %v", err)
	}
	if stored.ConsumedAt != nil {
		tb.Fatalf("code ConsumedAt=%v; a refused exchange must not consume the code", stored.ConsumedAt)
	}
}

// TestAuthCode_DPoPJKTMismatchLeavesCodeRedeemable presents a proof from a
// key other than the dpop_jkt commitment: the exchange is refused, the code
// stays unconsumed, and the committed key then redeems it.
func TestAuthCode_DPoPJKTMismatchLeavesCodeRedeemable(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	committed := newDPoPKey(t)
	other := newDPoPKey(t)
	const codeID = "code-dpop-jkt-gate"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: "grant-dpop-jkt-gate", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		GrantID:             "grant-dpop-jkt-gate",
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		DPoPJKT:             committed.jkt,
	})

	form := authCodeForm(codeID, redirect, verifier)
	wrong := makeDPoPProof(t, other, "POST", f.htu(), f.clock.now, "jti-jkt-gate-1", "")
	resp := postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, form, client.ID, secret, wrong)
	body := decodeJSON(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("mismatched proof: status=%d body=%v want 400 invalid_grant", resp.StatusCode, body)
	}
	assertCodeUnconsumed(t, f, codeID)

	right := makeDPoPProof(t, committed, "POST", f.htu(), f.clock.now, "jti-jkt-gate-2", "")
	resp = postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, form, client.ID, secret, right)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("committed key after a refused attempt: status=%d body=%v want 200", resp.StatusCode, decodeJSON(t, resp))
	}
}

// TestAuthCode_ScopeAllowlistRefusalLeavesCodeUnconsumed redeems a code
// carrying a scope restricted to another client.
func TestAuthCode_ScopeAllowlistRefusalLeavesCodeUnconsumed(t *testing.T) {
	t.Parallel()

	f := scopedFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-allowlist-gate"
	redirect := client.RedirectURIs[0]

	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		RedirectURI:         redirect,
		Scope:               []string{"openid", "billing:write"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if body := decodeJSON(t, resp); resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("status=%d body=%v want 400 invalid_scope", resp.StatusCode, body)
	}
	assertCodeUnconsumed(t, f, codeID)
}

// TestAuthCode_PublicClientNoPKCERefusalLeavesCodeUnconsumed redeems a
// public client's code that was issued without a PKCE challenge.
func TestAuthCode_PublicClientNoPKCERefusalLeavesCodeUnconsumed(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client := f.publicClientFixture(t)
	const codeID = "code-pkce-downgrade-gate"
	redirect := client.RedirectURIs[0]
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:          codeID,
		ClientID:    client.ID,
		Subject:     "user-1",
		RedirectURI: redirect,
		Scope:       []string{"openid"},
	})

	form := authCodeForm(codeID, redirect, "")
	form.Del("code_verifier")
	form.Set("client_id", client.ID)
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()
	if body := decodeJSON(t, resp); resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("status=%d body=%v want 400 invalid_grant", resp.StatusCode, body)
	}
	assertCodeUnconsumed(t, f, codeID)
}

// TestAuthCode_AuthorizationDetailsExceedingGrantLeavesCodeRedeemable sends an
// authorization_details entry the grant does not carry: the exchange is
// refused with invalid_authorization_details, the code stays unconsumed, and
// a conforming retry redeems it.
func TestAuthCode_AuthorizationDetailsExceedingGrantLeavesCodeRedeemable(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-rar-gate"
	const grantID = "grant-rar-gate"
	redirect := client.RedirectURIs[0]
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-rar-gate", ClientID: client.ID,
		Scope:                []string{"openid"},
		AuthorizationDetails: []map[string]any{{"type": "payment", "amount": "100"}},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-rar-gate",
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := authCodeForm(codeID, redirect, verifier)
	form.Set("authorization_details", `[{"type":"payment","amount":"999"}]`)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_authorization_details" {
		t.Fatalf("error=%v want invalid_authorization_details", got)
	}
	assertCodeUnconsumed(t, f, codeID)

	retry := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("retry status=%d want 200 body=%v", retry.StatusCode, decodeJSON(t, retry))
	}
}
