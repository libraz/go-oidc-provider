package tokenendpoint_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
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
	if got := body["scope"]; got != "openid email" {
		t.Errorf("scope=%v want openid email", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Errorf("refresh_token missing — confidential client with refresh_token grant should rotate")
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

// Compile-time guard against the unused-import lint when this file is
// the only test in the package.
var _ time.Time
