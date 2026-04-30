package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// authCodeForm builds the canonical authorization_code form body.
func authCodeForm(code, redirect, verifier string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("code_verifier", verifier)
	return form
}

// TestAuthCode_HappyPath drives the full code → token exchange and
// verifies every field of the response, including signature validity
// and at_hash / c_hash binding.
func TestAuthCode_HappyPath(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-happy"
	const grantID = "grant-happy"
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
		Nonce:               "nonce-happy",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	assertCacheControl(t, resp)
	body := decodeJSON(t, resp)
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type=%v want Bearer", body["token_type"])
	}
	if got := body["scope"]; got != "openid email offline_access" {
		t.Errorf("scope=%v want openid email offline_access", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Errorf("refresh_token missing — offline_access-bearing grant should rotate")
	}
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}

	// Verify the access token: signature, issuer, expiry.
	verifier2 := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	if _, _, err := verifier2.Verify(at); err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	// Verify at_hash binds to the access token by computing it ourselves.
	wantAtHash := tokens.Hash(at)
	idClaims := decodeIDTokenClaims(t, idt)
	if idClaims["at_hash"] != wantAtHash {
		t.Errorf("at_hash=%v want %s", idClaims["at_hash"], wantAtHash)
	}
	wantCHash := tokens.Hash(codeID)
	if idClaims["c_hash"] != wantCHash {
		t.Errorf("c_hash=%v want %s", idClaims["c_hash"], wantCHash)
	}
	if idClaims["nonce"] != "nonce-happy" {
		t.Errorf("nonce=%v want nonce-happy", idClaims["nonce"])
	}
}

func TestAuthCode_NoOfflineAccess_DoesNotIssueRefreshToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-no-offline"
	const grantID = "grant-no-offline"
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
		Nonce:               "nonce-no-offline",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("refresh_token must be absent without offline_access: %v", body)
	}
}

func TestAuthCode_ResourceBindsAudienceAndRefreshToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-resource"
	const grantID = "grant-resource"
	const subject = "user-1"
	const resource = "https://api.example.com"
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
		Resource:            resource,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-resource",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier2 := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier2.Verify(at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != resource {
		t.Fatalf("aud=%v want [%q]", claims.Audience, resource)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing")
	}
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rt)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.Resource != resource {
		t.Fatalf("refresh resource=%q want %q", rec.Resource, resource)
	}
}

func TestAuthCode_RequireAuthTime_EmitsAuthTime(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	client.RequireAuthTime = true
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	verifier, challenge := pkcePair()
	const codeID = "code-require-auth-time"
	const grantID = "grant-require-auth-time"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]
	authTime := f.clock.now.Add(-2 * time.Minute)

	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   subject,
		ClientID:  client.ID,
		Scope:     []string{"openid", "offline_access"},
		AuthTime:  authTime,
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-require-auth-time",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got := idClaims["auth_time"]; got != float64(authTime.Unix()) {
		t.Fatalf("auth_time=%v want %d", got, authTime.Unix())
	}
}

func TestAuthCode_RequireAuthTime_MissingAuthTimeFails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	client.RequireAuthTime = true
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	verifier, challenge := pkcePair()
	const codeID = "code-require-auth-time-missing"
	const grantID = "grant-require-auth-time-missing"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:       grantID,
		Subject:  subject,
		ClientID: client.ID,
		Scope:    []string{"openid", "offline_access"},
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-require-auth-time-missing",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "server_error" {
		t.Fatalf("error=%v want server_error", got)
	}
}

// TestAuthCode_NoPKCE_HappyPath drives the profile-conditional non-
// PKCE path: a code that was issued without a code_challenge MUST be
// redeemable without a code_verifier. The test pins the new contract
// so a regression that re-instates the always-required gate at
// /token surfaces here.
func TestAuthCode_NoPKCE_HappyPath(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const codeID = "code-no-pkce"
	const grantID = "grant-no-pkce"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:          codeID,
		ClientID:    client.ID,
		Subject:     subject,
		GrantID:     grantID,
		RedirectURI: redirect,
		Scope:       []string{"openid"},
		Nonce:       "nonce-no-pkce",
		// CodeChallenge / CodeChallengeMethod intentionally empty.
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", codeID)
	form.Set("redirect_uri", redirect)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if _, ok := body["access_token"].(string); !ok {
		t.Errorf("access_token missing: %v", body)
	}
}

// TestAuthCode_NoPKCE_RejectsSmuggledVerifier covers the downgrade
// guard: a code issued without PKCE MUST refuse a code_verifier on
// exchange. The error surface is invalid_grant ("PKCE verification
// failed") because [authcode.Exchanger.Exchange] returns
// pkce.ErrVerifierMismatch for the smuggled case.
func TestAuthCode_NoPKCE_RejectsSmuggledVerifier(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const codeID = "code-no-pkce-smuggle"
	const grantID = "grant-no-pkce-smuggle"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:          codeID,
		ClientID:    client.ID,
		Subject:     subject,
		GrantID:     grantID,
		RedirectURI: redirect,
		Scope:       []string{"openid"},
	})

	resp := f.post(t, authCodeForm(codeID, redirect, "smuggled-verifier-smuggled-verifier-smuggled-1234"), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", body["error"])
	}
}

// TestAuthCode_PublicClient_PKCE_OK confirms the public-client path:
// no Basic auth, client_id in the body, PKCE replaces the secret as
// the proof of possession.
func TestAuthCode_PublicClient_PKCE_OK(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client := f.publicClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-pub"
	redirect := client.RedirectURIs[0]
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := authCodeForm(codeID, redirect, verifier)
	form.Set("client_id", client.ID)
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
}

// TestAuthCode_PublicClient_NoPKCE_Rejected pins the RFC 9700 §2.1.1
// downgrade guard: a public client redeeming a code that was issued
// without PKCE MUST be rejected at /token regardless of the active
// profile's PKCE-mandatory posture. The guard is defence-in-depth in
// case the authorize-side gate is misconfigured or the stored code
// record was tampered with: a stolen code that lacks PKCE binding
// would otherwise let an attacker impersonate the public client.
//
// Tracks: RFC 9700 §2.1.1 (Security BCP), which mandates PKCE on
// every public-client code flow, and the analogous PKCE-downgrade
// threat shape against public SPAs / native clients.
func TestAuthCode_PublicClient_NoPKCE_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client := f.publicClientFixture(t)
	const codeID = "code-pub-no-pkce"
	redirect := client.RedirectURIs[0]
	// A code seeded WITHOUT a code_challenge for a public client.
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:          codeID,
		ClientID:    client.ID,
		Subject:     "user-1",
		RedirectURI: redirect,
		Scope:       []string{"openid"},
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", codeID)
	form.Set("redirect_uri", redirect)
	form.Set("client_id", client.ID)
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (public client + no PKCE must be rejected)", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", body["error"])
	}
}

// TestAuthCode_Replay verifies that consuming the same code twice
// surfaces invalid_grant on the second exchange.
func TestAuthCode_Replay(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-replay"
	redirect := client.RedirectURIs[0]
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	first := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d want 200", first.StatusCode)
	}
	first.Body.Close()

	second := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("second exchange status=%d want 400", second.StatusCode)
	}
	body := decodeJSON(t, second)
	if body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", body["error"])
	}
}

// TestAuthCode_Replay_RevokesIssuedRefreshToken pins the §A.12.4 /
// RFC 6749 §4.1.2 escalation contract: a replayed authorization code
// is treated as evidence that the chain is compromised. The token
// endpoint MUST (a) reject the replay with invalid_grant AND (b)
// revoke every refresh token descended from the same grant. Without
// (b) an attacker who captured the legitimate refresh token would
// retain working credentials even after the OP has detected the
// theft.
//
// Tracks: RFC 6749 §4.1.2 ("if an authorization code is used more
// than once, the authorization server MUST deny the request and
// SHOULD revoke ... all tokens previously issued based on that
// authorization code"), RFC 9700 §2.1.1 (Security BCP recommends
// rotation + reuse-detection revocation as the strict-stance default),
// and the matching threat shape that drives ory/fosite's
// "TestRefreshTokenChainRevocation" — the same revocation contract
// flipped on the code half of the flow. CWE-294 (Authentication
// Bypass by Capture-Replay) is the canonical CWE.
func TestAuthCode_Replay_RevokesIssuedRefreshToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-replay-revoke"
	const grantID = "grant-replay-revoke"
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
	})

	// 1. First exchange succeeds and yields a refresh token.
	first := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d want 200", first.StatusCode)
	}
	body := decodeJSON(t, first)
	first.Body.Close()
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("refresh_token missing on first exchange")
	}

	// 2. Replaying the code MUST fail with invalid_grant.
	second := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400", second.StatusCode)
	}
	body2 := decodeJSON(t, second)
	second.Body.Close()
	if body2["error"] != "invalid_grant" {
		t.Errorf("replay error=%v want invalid_grant", body2["error"])
	}

	// 3. The refresh token issued in step 1 MUST now be revoked.
	// Presenting it on /token with grant_type=refresh_token SHOULD
	// produce invalid_grant.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", rt)
	third := f.post(t, form, client.ID, secret)
	defer third.Body.Close()
	if third.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-revoke refresh status=%d want 400 (refresh token must be revoked after code replay)", third.StatusCode)
	}
	body3 := decodeJSON(t, third)
	if body3["error"] != "invalid_grant" {
		t.Errorf("post-revoke refresh error=%v want invalid_grant", body3["error"])
	}
}

// TestAuthCode_WrongClient: a code issued to client A cannot be
// redeemed by client B even when both authenticate successfully.
func TestAuthCode_WrongClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner, ownerSecret := f.confidentialClientFixture(t)
	_ = ownerSecret
	intruder := f.publicClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-wrong-client"
	redirect := owner.RedirectURIs[0]
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            owner.ID,
		Subject:             "user-1",
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := authCodeForm(codeID, redirect, verifier)
	form.Set("client_id", intruder.ID)
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if body := decodeJSON(t, resp); body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", body["error"])
	}
}

// TestAuthCode_WrongRedirectURI confirms redirect_uri matching is
// enforced (RFC 6749 §4.1.3).
func TestAuthCode_WrongRedirectURI(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-wrong-redirect"
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		RedirectURI:         client.RedirectURIs[0],
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t,
		authCodeForm(codeID, "https://attacker.example/callback", verifier),
		client.ID, secret,
	)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if body := decodeJSON(t, resp); body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", body["error"])
	}
}

// TestAuthCode_BadVerifier verifies PKCE rejection.
func TestAuthCode_BadVerifier(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	_, challenge := pkcePair()
	const codeID = "code-bad-pkce"
	redirect := client.RedirectURIs[0]
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	const badVerifier = "different-different-different-different-1234567" // length 47, valid charset
	resp := f.post(t, authCodeForm(codeID, redirect, badVerifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if body := decodeJSON(t, resp); body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", body["error"])
	}
}

// TestAuthCode_WrongSecret verifies confidential-client rejection on
// invalid Basic credentials. The handler must add WWW-Authenticate so
// RP libraries retry intelligently.
func TestAuthCode_WrongSecret(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, _ := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-wrong-secret"
	redirect := client.RedirectURIs[0]
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, "bogus")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Errorf("WWW-Authenticate missing on Basic-auth invalid_client")
	}
	if body := decodeJSON(t, resp); body["error"] != "invalid_client" {
		t.Errorf("error=%v want invalid_client", body["error"])
	}
}

// TestAuthCode_MissingVerifier checks the PKCE-mandatory posture.
func TestAuthCode_MissingVerifier(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	_, challenge := pkcePair()
	const codeID = "code-missing-verifier"
	redirect := client.RedirectURIs[0]
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", codeID)
	form.Set("redirect_uri", redirect)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if body := decodeJSON(t, resp); body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", body["error"])
	}
}

// opaqueFormatFixture builds a fixture whose op.Provider is configured
// with [op.WithAccessTokenFormat] selecting opaque tokens (ADR 0024).
// The clock is the same anchor used by [newFixture] so tests that
// inherit time-sensitive assertions stay aligned.
func opaqueFormatFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithAccessTokenFormat(op.AccessTokenFormatOpaque)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// TestAuthCode_OpaqueFormat_HappyPath pins the ADR 0024 issuance plumbing:
// when the OP is configured for opaque access tokens the wire response
// carries a 43-character base64url string with no '.' separator, the
// shadow row in [store.OpaqueAccessTokenStore] mirrors the issuance
// metadata, and the same DPoP / mTLS bindings the JWT path would have
// recorded land on the row's cnf-thumbprint columns.
func TestAuthCode_OpaqueFormat_HappyPath(t *testing.T) {
	t.Parallel()

	f := opaqueFormatFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-opaque-happy"
	const grantID = "grant-opaque-happy"
	const subject = "user-opaque"
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
		Nonce:               "nonce-opaque",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	// Opaque tokens are 43-char base64url-no-pad. RFC 7515 §3 forbids a
	// JWS Compact Serialisation that lacks two '.' separators; the
	// inverse — the opaque token MUST NOT contain any '.' — is the
	// invariant the introspection-side dispatch relies on.
	if len(at) != 43 {
		t.Errorf("len(access_token)=%d want 43 (opaque format)", len(at))
	}
	if strings.Contains(at, ".") {
		t.Errorf("opaque access_token must not contain '.', got %q", at)
	}

	// The opaque store SHOULD carry exactly one live row for this grant.
	rec, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), at)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find: %v", err)
	}
	if rec.GrantID != grantID {
		t.Errorf("rec.GrantID=%q want %q", rec.GrantID, grantID)
	}
	if rec.Subject != subject {
		t.Errorf("rec.Subject=%q want %q", rec.Subject, subject)
	}
	if rec.ClientID != client.ID {
		t.Errorf("rec.ClientID=%q want %q", rec.ClientID, client.ID)
	}
	if rec.Revoked {
		t.Errorf("rec.Revoked=true want false on freshly-issued opaque AT")
	}
	if rec.DPoPJKT != "" || rec.MTLSCertThumbprint != "" {
		t.Errorf("rec binding=(%q,%q) want bearer (no DPoP/mTLS in this test)",
			rec.DPoPJKT, rec.MTLSCertThumbprint)
	}
}

// TestAuthCode_OpaqueFormat_DPoPBindingPersisted verifies that when the
// /token request carries a DPoP proof the opaque substore row records
// the matching JKT (ADR 0024 §S.3). Without this, a stolen opaque
// token would not be checkable against the proof at userinfo /
// introspection time.
func TestAuthCode_OpaqueFormat_DPoPBindingPersisted(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.DPoP),
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		),
	)
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}

	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-opaque-dpop"
	const grantID = "grant-opaque-dpop"
	const subject = "user-opaque-dpop"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	key := newDPoPKey(t)
	form := authCodeForm(codeID, redirect, verifier)
	proof := makeDPoPProof(t, key, "POST", f.endpoint, f.clock.now, "jti-ac-opaque-dpop", "")
	resp := postWithDPoP(t, f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	rec, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), at)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find: %v", err)
	}
	if rec.DPoPJKT != key.jkt {
		t.Errorf("rec.DPoPJKT=%q want %q", rec.DPoPJKT, key.jkt)
	}
}

// decodeIDTokenClaims peeks at the unverified payload of a JWS so the
// happy-path tests can check at_hash / c_hash without re-implementing
// the verifier. The signature is exercised separately via the access
// token's [tokens.AccessTokenVerifier].
func decodeIDTokenClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("jws has %d parts, want 3", len(parts))
	}
	raw, err := decodeBase64URL(parts[1])
	if err != nil {
		tb.Fatalf("decodeBase64URL: %v", err)
	}
	out := map[string]any{}
	if err := jsonUnmarshal(raw, &out); err != nil {
		tb.Fatalf("Unmarshal: %v", err)
	}
	return out
}

// jtiRegistryFixture builds a fixture whose op.Provider is pinned to
// [op.RevocationStrategyJTIRegistry] (ADR 0013 model). The mintAccessToken
// path is expected to call AccessTokens.Register on every issuance under
// this strategy; the GrantTombstone default does not.
func jtiRegistryFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// TestAuthCode_GrantTombstone_NoRegisterAtIssuance pins the ADR 0025
// hot-path contract: under [op.RevocationStrategyGrantTombstone]
// (the default) the issuance path writes ZERO access-token shadow
// rows. The substore is consulted only on revocation cascades, so a
// freshly-issued AT MUST NOT have a row in
// [store.AccessTokenRegistry].
//
// The test runs the canonical authorization_code happy path and then
// looks the issued JTI up in the registry. The reference inmem
// implementation returns (nil, nil) for an absent record (the
// sentinel-free contract documented on
// [store.AccessTokenRegistry.Find]); observing a non-nil row would
// mean Register fired on the hot path, which is exactly what
// ADR 0025 removes. The companion test
// TestAuthCode_JTIRegistry_RegisterAtIssuance pins the opposite
// direction.
func TestAuthCode_GrantTombstone_NoRegisterAtIssuance(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-tombstone-no-register"
	const grantID = "grant-tombstone-no-register"
	const subject = "user-tombstone-no-register"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier2 := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier2.Verify(at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	if claims.JTI == "" {
		t.Fatalf("issued AT missing jti claim")
	}
	rec, err := f.prov.Store.AccessTokens().Find(context.Background(), claims.JTI)
	if err == nil && rec != nil {
		t.Fatalf("AccessTokens.Register MUST NOT fire under RevocationStrategyGrantTombstone; found shadow row jti=%q", claims.JTI)
	}
}

// TestAuthCode_JTIRegistry_RegisterAtIssuance is the positive
// counterpart to TestAuthCode_GrantTombstone_NoRegisterAtIssuance:
// when the embedder pins [op.RevocationStrategyJTIRegistry] the
// issuance path MUST write a shadow row per AT (ADR 0013 model). The
// row's JTI / GrantID / Subject / ClientID columns mirror the encoded
// claims so a future RevokeByGrant cascade can flip exactly the
// matching record.
func TestAuthCode_JTIRegistry_RegisterAtIssuance(t *testing.T) {
	t.Parallel()

	f := jtiRegistryFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-jti-register"
	const grantID = "grant-jti-register"
	const subject = "user-jti-register"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier2 := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier2.Verify(at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	rec, err := f.prov.Store.AccessTokens().Find(context.Background(), claims.JTI)
	if err != nil {
		t.Fatalf("AccessTokens.Find: %v", err)
	}
	if rec == nil {
		t.Fatalf("AccessTokens.Register MUST fire under RevocationStrategyJTIRegistry; no row for jti=%q", claims.JTI)
	}
	if rec.GrantID != grantID {
		t.Errorf("rec.GrantID=%q want %q", rec.GrantID, grantID)
	}
	if rec.Subject != subject {
		t.Errorf("rec.Subject=%q want %q", rec.Subject, subject)
	}
	if rec.ClientID != client.ID {
		t.Errorf("rec.ClientID=%q want %q", rec.ClientID, client.ID)
	}
	if rec.Revoked {
		t.Errorf("rec.Revoked=true want false on freshly-issued AT")
	}
}

// TestAuthCode_GidClaim_PresentOnIssuedAT pins the ADR 0025 wire
// invariant: every issued JWT access token under the default
// strategy carries the originating GrantID in its "gid" private
// claim (RFC 7519 §4.3). The verifier-side decoder maps the wire
// "gid" claim onto [tokens.AccessTokenClaims.GrantID]; asserting on
// the decoded value is equivalent to asserting on the encoded JSON.
//
// The claim is populated unconditionally (the strategy controls
// Register / cascade behaviour, not the claim) so the same assertion
// holds under [op.RevocationStrategyJTIRegistry]; a companion
// assertion in TestAuthCode_JTIRegistry_RegisterAtIssuance confirms
// the strategy independence.
func TestAuthCode_GidClaim_PresentOnIssuedAT(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-gid"
	const grantID = "grant-gid"
	const subject = "user-gid"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier2 := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier2.Verify(at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	if claims.GrantID != grantID {
		t.Errorf("gid claim=%q want %q", claims.GrantID, grantID)
	}
}

// TestAuthCode_Replay_GrantTombstone_WritesTombstone pins the ADR
// 0025 cascade contract: under
// [op.RevocationStrategyGrantTombstone] a code-replay revocation
// MUST write a single [store.GrantTombstone] keyed on the originating
// grant id, NOT one shadow-row update per AT. The tombstone's
// RevokedAt MUST be set so the verifier's "iat <= RevokedAt" rule
// rejects every AT issued before the cascade; ExpiresAt MUST outlive
// the longest possible JWT AT under the grant.
//
// The companion authcode-replay test
// (TestAuthCode_Replay_RevokesIssuedRefreshToken) covers the
// refresh-token cascade — that branch runs identically under both
// strategies and is independent of this one.
func TestAuthCode_Replay_GrantTombstone_WritesTombstone(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-tombstone-replay"
	const grantID = "grant-tombstone-replay"
	const subject = "user-tombstone-replay"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	// 1. First exchange succeeds — establishes the chain.
	first := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d want 200", first.StatusCode)
	}
	first.Body.Close()

	// Sanity: no tombstone yet.
	beforeRevoked, beforeErr := f.prov.Store.GrantRevocations().IsRevoked(
		context.Background(), grantID, "", f.clock.now,
	)
	if beforeErr != nil {
		t.Fatalf("IsRevoked(pre-replay): %v", beforeErr)
	}
	if beforeRevoked {
		t.Fatalf("grant tombstone unexpectedly present before replay")
	}

	// 2. Replay triggers the cascade.
	second := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400", second.StatusCode)
	}
	second.Body.Close()

	// 3. Tombstone MUST now exist for grantID. Probe with iat = clock.now
	//    (which equals the cascade's RevokedAt under the deterministic
	//    fixedClock fixture) so the "iat <= RevokedAt" rule trips.
	revoked, err := f.prov.Store.GrantRevocations().IsRevoked(
		context.Background(), grantID, "", f.clock.now,
	)
	if err != nil {
		t.Fatalf("IsRevoked(post-replay): %v", err)
	}
	if !revoked {
		t.Fatalf("expected GrantTombstone for grantID=%q after code replay; IsRevoked returned false", grantID)
	}

	// 4. An iat strictly after the tombstone's RevokedAt MUST NOT trip
	//    the rule — defence-in-depth pin against an "always revoked"
	//    bug in the verifier.
	stillRevoked, err := f.prov.Store.GrantRevocations().IsRevoked(
		context.Background(), grantID, "", f.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("IsRevoked(post-tombstone iat-future): %v", err)
	}
	if stillRevoked {
		t.Errorf("IsRevoked must return false for iat strictly after RevokedAt")
	}
}

// TestAuthCode_Replay_GrantTombstone_NoPerATFlips pins the storage-
// shape contract of ADR 0025: the GrantTombstone cascade replaces
// the per-AT row updates of ADR 0013. Under
// [op.RevocationStrategyGrantTombstone] the AccessTokens registry
// MUST NOT see any row writes from the cascade — the issued AT was
// never registered (no Register on issuance under the default
// strategy) and the cascade does not retroactively register it.
func TestAuthCode_Replay_GrantTombstone_NoPerATFlips(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-tombstone-no-flips"
	const grantID = "grant-tombstone-no-flips"
	const subject = "user-tombstone-no-flips"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	first := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d want 200", first.StatusCode)
	}
	body := decodeJSON(t, first)
	first.Body.Close()
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier2 := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier2.Verify(at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}

	// Trigger the cascade.
	second := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400", second.StatusCode)
	}
	second.Body.Close()

	// The AccessTokens registry MUST NOT carry a row for this JTI: it
	// was never written at issuance (RevocationStrategyGrantTombstone
	// is the default) and the cascade does not retroactively create
	// one. The row's absence is the load-bearing signal that the
	// tombstone cascade replaced — not augmented — the per-AT
	// bookkeeping.
	rec, err := f.prov.Store.AccessTokens().Find(context.Background(), claims.JTI)
	if err == nil && rec != nil {
		t.Fatalf("AccessTokens row unexpectedly present for jti=%q under tombstone cascade", claims.JTI)
	}
}

// Compile-time guard against the unused-import lint when this file is
// the only test in the package.
var _ time.Time
