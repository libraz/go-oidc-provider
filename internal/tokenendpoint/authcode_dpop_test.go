package tokenendpoint_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestAuthCode_DPoP_BindsCnfJkt drives an authorization_code exchange
// with a DPoP proof on the token request and asserts that the issued
// access token carries cnf.jkt. Per RFC 9449 §5, refresh-token DPoP
// binding is OPTIONAL for confidential clients (and the library
// chooses NOT to bind so OFCS' FAPI 2.0 modules pass) — the
// access-token cnf.jkt is the only DPoP-binding the chain carries.
func TestAuthCode_DPoP_BindsCnfJkt(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-dpop"
	const grantID = "grant-dpop"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email", "offline_access"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-dpop",
	})

	key := newDPoPKey(t)
	form := authCodeForm(codeID, redirect, verifier)
	proof := makeDPoPProof(t, key, "POST", f.endpoint, f.clock.now, "jti-authcode-1", "")
	resp := postWithDPoP(t, f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing")
	}

	// Verify cnf.jkt is present on the access token.
	keySet := mustKeySet(t, f.prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: f.prov.Issuer, Clock: f.clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if parsed.Confirmation["jkt"] != key.jkt {
		t.Errorf("cnf.jkt=%q want %q", parsed.Confirmation["jkt"], key.jkt)
	}

	// Confidential clients leave the refresh-token record's DPoPJKT
	// empty per RFC 9449 §5 so the client may rotate its DPoP key
	// across refreshes; only the access-token-level cnf.jkt is bound.
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rt)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.DPoPJKT != "" {
		t.Errorf("refresh DPoPJKT=%q want empty (confidential client, RFC 9449 §5)", rec.DPoPJKT)
	}
}

// TestAuthCode_DPoP_NoProofBearer mints a bearer token when the
// request omits the DPoP header even with the feature enabled.
func TestAuthCode_DPoP_NoProofBearer(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-bearer-with-dpop-feature"
	const grantID = "grant-bearer-feat"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-bearer-feat",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}
	at, _ := body["access_token"].(string)
	keySet := mustKeySet(t, f.prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: f.prov.Issuer, Clock: f.clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if len(parsed.Confirmation) != 0 {
		t.Errorf("cnf must be absent on bearer token: %v", parsed.Confirmation)
	}
}

// TestAuthCode_DPoP_Replay rejects the second request that re-uses the
// same proof jti within the replay window.
func TestAuthCode_DPoP_Replay(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	key := newDPoPKey(t)

	// Seed two distinct codes; the second exchange uses the same
	// proof jti, which the verifier must reject.
	verifier1, challenge1 := pkcePair()
	const codeID1 = "code-replay-1"
	const grantID1 = "grant-replay-1"
	redirect := client.RedirectURIs[0]
	f.seedGrant(t, &store.Grant{
		ID: grantID1, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID1,
		ClientID:            client.ID,
		Subject:             "user-1",
		GrantID:             grantID1,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge1,
		CodeChallengeMethod: "S256",
		Nonce:               "n1",
	})
	verifier2 := verifier1 // PKCE pair generator produces identical pairs across calls
	challenge2 := challenge1
	const codeID2 = "code-replay-2"
	const grantID2 = "grant-replay-2"
	f.seedGrant(t, &store.Grant{
		ID: grantID2, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID2,
		ClientID:            client.ID,
		Subject:             "user-1",
		GrantID:             grantID2,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge2,
		CodeChallengeMethod: "S256",
		Nonce:               "n2",
	})

	proof := makeDPoPProof(t, key, "POST", f.endpoint, f.clock.now, "jti-replay-shared", "")

	first := postWithDPoP(t, f.endpoint, authCodeForm(codeID1, redirect, verifier1), client.ID, secret, proof)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d want 200, body=%v", first.StatusCode, decodeJSON(t, first))
	}
	first.Body.Close()

	second := postWithDPoP(t, f.endpoint, authCodeForm(codeID2, redirect, verifier2), client.ID, secret, proof)
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400", second.StatusCode)
	}
	if got := decodeJSON(t, second)["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}
