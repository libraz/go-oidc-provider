package op_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	ssfE2EPushClient = "ssf-push-rx"
	ssfE2EPollClient = "ssf-poll-rx"
	//nolint:gosec // opaque test fixture secret, not a credential.
	ssfE2ESecret      = "ssf-e2e-receiver-secret"
	ssfE2ERedirectURI = "https://rp.testkit.invalid/callback"

	ssfEventSessionRevoked   = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	ssfEventCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec // event type URI.
	ssfEventVerification     = "https://schemas.openid.net/secevent/ssf/event-type/verification"

	// ssfE2EPushWait bounds the wait for one push. The worker ticks every
	// five seconds, so this covers two ticks.
	ssfE2EPushWait = 15 * time.Second
)

// ssfReceiver is a push receiver (RFC 8935) that records every SET it
// is handed and answers 202.
type ssfReceiver struct {
	server *httptest.Server
	sets   chan string
}

func newSSFReceiver(t *testing.T) *ssfReceiver {
	t.Helper()
	rx := &ssfReceiver{sets: make(chan string, 32)}
	rx.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Header.Get("Content-Type") != "application/secevent+jwt" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rx.sets <- string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(rx.server.Close)
	return rx
}

// await returns the first pushed SET whose single event is eventType,
// skipping others (the creation-time verification), or fails once
// ssfE2EPushWait elapses.
func (rx *ssfReceiver) await(t *testing.T, tk *testkit.Provider, eventType string) map[string]any {
	t.Helper()
	deadline := time.NewTimer(ssfE2EPushWait)
	defer deadline.Stop()
	for {
		select {
		case set := <-rx.sets:
			claims := verifySET(t, tk, set)
			if events, _ := claims["events"].(map[string]any); events[eventType] != nil {
				return claims
			}
		case <-deadline.C:
			t.Fatalf("no %s SET pushed within %s", eventType, ssfE2EPushWait)
			return nil
		}
	}
}

func newSSFE2EProvider(t *testing.T) *testkit.Provider {
	t.Helper()
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials),
		op.WithSharedSignals(),
		op.WithAllowInsecureSharedSignalsPushForDev(),
	))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := tk.OP.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	hash, err := op.HashClientSecret(ssfE2ESecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	for _, id := range []string{ssfE2EPushClient, ssfE2EPollClient} {
		tk.RegisterClient(t, testkit.ClientFixture{
			ID:                      id,
			SecretHash:              hash,
			RedirectURIs:            []string{ssfE2ERedirectURI},
			Scopes:                  []string{"openid", "profile", "ssf.read", "ssf.manage"},
			GrantTypes:              []string{"authorization_code", "client_credentials"},
			TokenEndpointAuthMethod: "client_secret_basic",
		})
	}
	return tk
}

// ssfDo sends one request to the testkit server and decodes a JSON body
// when there is one.
func ssfDo(t *testing.T, tk *testkit.Provider, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, tk.Server.URL+path, rd)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode %s %s body %q: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode, out
}

// ssfToken obtains a client_credentials access token for clientID.
func ssfToken(t *testing.T, tk *testkit.Provider, clientID, scope string) (int, map[string]any) {
	t.Helper()
	return ssfTokenRequest(t, tk, clientID, url.Values{"grant_type": {"client_credentials"}, "scope": {scope}})
}

func ssfTokenRequest(t *testing.T, tk *testkit.Provider, clientID string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, ssfE2ESecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /token: %v", err)
	}
	return resp.StatusCode, out
}

func mustSSFToken(t *testing.T, tk *testkit.Provider, clientID string) string {
	t.Helper()
	status, body := ssfToken(t, tk, clientID, "ssf.manage")
	tok, _ := body["access_token"].(string)
	if status != http.StatusOK || tok == "" {
		t.Fatalf("client_credentials ssf.manage for %s: status=%d body=%v", clientID, status, body)
	}
	return tok
}

// verifySET checks set against the OP's JWKS and returns its claims.
func verifySET(t *testing.T, tk *testkit.Provider, set string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSignedCompact(set, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse SET: %v", err)
	}
	if typ, _ := jws.Signatures[0].Protected.ExtraHeaders["typ"].(string); typ != "secevent+jwt" {
		t.Fatalf("SET typ = %q, want secevent+jwt", typ)
	}
	resp := ssfBrowserGet(t, tk.HTTPClient(nil), tk.Server.URL+"/oidc/jwks")
	defer func() { _ = resp.Body.Close() }()
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	keys := jwks.Key(jws.Signatures[0].Protected.KeyID)
	if len(keys) == 0 {
		t.Fatalf("SET kid %q not in the OP JWKS", jws.Signatures[0].Protected.KeyID)
	}
	payload, err := jws.Verify(keys[0])
	if err != nil {
		t.Fatalf("SET does not verify with the OP JWKS: %v", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode SET claims: %v", err)
	}
	if _, ok := claims["sub"]; ok {
		t.Errorf("SET carries sub: %v", claims)
	}
	if _, ok := claims["exp"]; ok {
		t.Errorf("SET carries exp: %v", claims)
	}
	if claims["iss"] != tk.Issuer {
		t.Errorf("SET iss = %v, want %s", claims["iss"], tk.Issuer)
	}
	return claims
}

// wantIssSub asserts the SET's sub_id is the iss_sub identifier of sub.
func wantIssSub(t *testing.T, tk *testkit.Provider, claims map[string]any, sub string) {
	t.Helper()
	subID, _ := claims["sub_id"].(map[string]any)
	if subID["format"] != "iss_sub" || subID["iss"] != tk.Issuer || subID["sub"] != sub {
		t.Errorf("sub_id = %v, want iss_sub of %s", subID, sub)
	}
}

func createSSFStream(t *testing.T, tk *testkit.Provider, token string, body map[string]any) string {
	t.Helper()
	status, resp := ssfDo(t, tk, http.MethodPost, "/oidc/ssf/streams", token, body)
	id, _ := resp["stream_id"].(string)
	if status != http.StatusCreated || id == "" {
		t.Fatalf("create stream: status=%d body=%v", status, resp)
	}
	return id
}

func seedSSFGrant(t *testing.T, tk *testkit.Provider, subject, clientID string) {
	t.Helper()
	if err := tk.Store.Grants().Save(context.Background(), &store.Grant{
		ID:       "grant-" + subject + "-" + clientID,
		Subject:  subject,
		ClientID: clientID,
		Scope:    []string{"openid"},
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// runSSFCodeFlow logs subject in to clientID on browser and returns the
// id_token, establishing both the OP session and the grant.
func runSSFCodeFlow(t *testing.T, tk *testkit.Provider, browser *http.Client, clientID, subject string) string {
	t.Helper()
	verifier := "ssf-e2e-pkce-verifier-0123456789-abcdefghijklmnop"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {ssfE2ERedirectURI},
		"scope":                 {"openid profile"},
		"state":                 {"ssf-state"},
		"nonce":                 {"ssf-nonce"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	resp := ssfBrowserGet(t, browser, tk.Server.URL+"/oidc/auth?"+q.Encode())
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize status=%d location=%v", resp.StatusCode, loc)
	}
	interactionURL := tk.Server.URL + loc.Path

	prompt := ssfBrowserGet(t, browser, interactionURL)
	var step map[string]any
	if err := json.NewDecoder(prompt.Body).Decode(&step); err != nil {
		t.Fatalf("decode interaction prompt: %v", err)
	}
	_ = prompt.Body.Close()
	csrf := ssfCookie(prompt.Cookies(), "__Host-oidc_csrf")
	stateRef, _ := step["state_ref"].(string)
	if csrf == nil || stateRef == "" {
		t.Fatalf("interaction prompt lacks state_ref or CSRF cookie: %v", step)
	}
	raw, _ := json.Marshal(map[string]any{"state_ref": stateRef, "values": map[string]string{testkit.SubjectFieldName: subject}})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", tk.Issuer)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(csrf)
	final, err := browser.Do(req)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	if rotated := ssfCookie(final.Cookies(), "__Host-oidc_csrf"); rotated != nil {
		csrf = rotated
	}
	if consent, env, err := testkit.IsConsentPrompt(final); err != nil {
		t.Fatalf("inspect consent: %v", err)
	} else if consent {
		ref, _ := env["state_ref"].(string)
		final = testkit.PostConsentApproval(t, browser, interactionURL, tk.Issuer, csrf.Value, ref, testkit.ApprovedScopesFrom(t, env))
	}
	_ = final.Body.Close()
	cb, err := final.Location()
	if final.StatusCode != http.StatusFound || err != nil || cb.Query().Get("code") == "" {
		t.Fatalf("interaction did not redirect with a code: status=%d location=%v", final.StatusCode, cb)
	}

	status, tok := ssfTokenRequest(t, tk, clientID, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.Query().Get("code")},
		"redirect_uri":  {ssfE2ERedirectURI},
		"code_verifier": {verifier},
	})
	idToken, _ := tok["id_token"].(string)
	if status != http.StatusOK || idToken == "" {
		t.Fatalf("code exchange: status=%d body=%v", status, tok)
	}
	return idToken
}

func ssfBrowserGet(t *testing.T, browser *http.Client, target string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

func ssfCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// idTokenSubject reads the sub claim of an id_token the OP issued; the
// receiver-facing subject in sub_id must be the same value.
func idTokenSubject(t *testing.T, idToken string) string {
	t.Helper()
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Sub == "" {
		t.Fatalf("id_token sub: %v", err)
	}
	return claims.Sub
}

// TestSSFE2E_PushSessionRevoked drives the push path end to end: a
// receiver creates a push stream with its own access token, an
// RP-Initiated Logout and then RevokeSubject each deliver a CAEP
// session-revoked SET the receiver verifies against the OP JWKS.
func TestSSFE2E_PushSessionRevoked(t *testing.T) {
	t.Parallel()
	tk := newSSFE2EProvider(t)
	rx := newSSFReceiver(t)
	token := mustSSFToken(t, tk, ssfE2EPushClient)
	createSSFStream(t, tk, token, map[string]any{
		"delivery":         map[string]any{"method": "urn:ietf:rfc:8935", "endpoint_url": rx.server.URL + "/push"},
		"events_requested": []string{ssfEventSessionRevoked, ssfEventCredentialChange},
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	browser := tk.HTTPClient(jar)
	idToken := runSSFCodeFlow(t, tk, browser, ssfE2EPushClient, "alice")
	resp := ssfBrowserGet(t, browser, tk.Server.URL+"/oidc/end_session?"+url.Values{"id_token_hint": {idToken}}.Encode())
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("/end_session status=%d", resp.StatusCode)
	}
	logout := rx.await(t, tk, ssfEventSessionRevoked)
	wantIssSub(t, tk, logout, idTokenSubject(t, idToken))
	if logout["aud"] != ssfE2EPushClient {
		t.Errorf("SET aud = %v, want %s", logout["aud"], ssfE2EPushClient)
	}
	ev, _ := logout["events"].(map[string]any)[ssfEventSessionRevoked].(map[string]any)
	if ev["initiating_entity"] != "user" {
		t.Errorf("logout session-revoked initiating_entity = %v, want user", ev["initiating_entity"])
	}
	if reason, _ := ev["reason_admin"].(map[string]any); len(reason) == 0 {
		t.Errorf("logout session-revoked has no reason_admin: %v", ev)
	}

	seedSSFGrant(t, tk, "bob", ssfE2EPushClient)
	if err := tk.OP.RevokeSubject(context.Background(), "bob"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	revoked := rx.await(t, tk, ssfEventSessionRevoked)
	wantIssSub(t, tk, revoked, "bob")
	ev, _ = revoked["events"].(map[string]any)[ssfEventSessionRevoked].(map[string]any)
	if _, ok := ev["initiating_entity"]; ok {
		t.Errorf("RevokeSubject session-revoked carries initiating_entity: %v", ev)
	}
}

// TestSSFE2E_PollCredentialChange covers the embedder path: an
// EmitSecurityEvent CredentialChange lands on the receiver's poll
// stream, an ack removes it, and another receiver's token cannot see
// the stream.
func TestSSFE2E_PollCredentialChange(t *testing.T) {
	t.Parallel()
	tk := newSSFE2EProvider(t)
	token := mustSSFToken(t, tk, ssfE2EPollClient)
	streamID := createSSFStream(t, tk, token, map[string]any{
		"events_requested": []string{ssfEventCredentialChange},
	})
	pollPath := "/oidc/ssf/poll/" + streamID

	seedSSFGrant(t, tk, "carol", ssfE2EPollClient)
	if err := tk.OP.EmitSecurityEvent(context.Background(), op.CredentialChange{
		Subject:        "carol",
		CredentialType: op.CredentialTypePassword,
		ChangeType:     op.CredentialChangeUpdate,
	}); err != nil {
		t.Fatalf("EmitSecurityEvent: %v", err)
	}

	status, body := ssfDo(t, tk, http.MethodPost, pollPath, token, map[string]any{"returnImmediately": true})
	if status != http.StatusOK {
		t.Fatalf("poll status=%d body=%v", status, body)
	}
	sets, _ := body["sets"].(map[string]any)
	var change string
	acks := make([]string, 0, len(sets))
	for jti, raw := range sets {
		acks = append(acks, jti)
		claims := verifySET(t, tk, raw.(string))
		events, _ := claims["events"].(map[string]any)
		switch {
		case events[ssfEventCredentialChange] != nil:
			change = jti
			wantIssSub(t, tk, claims, "carol")
			ev, _ := events[ssfEventCredentialChange].(map[string]any)
			if ev["credential_type"] != "password" || ev["change_type"] != "update" {
				t.Errorf("credential-change payload = %v", ev)
			}
			if reason, _ := ev["reason_admin"].(map[string]any); len(reason) == 0 {
				t.Errorf("credential-change has no reason_admin: %v", ev)
			}
		case events[ssfEventVerification] != nil:
		default:
			t.Errorf("unexpected SET on the poll stream: %v", claims)
		}
	}
	if change == "" {
		t.Fatalf("poll did not return the credential-change SET: %v", body)
	}

	status, body = ssfDo(t, tk, http.MethodPost, pollPath, token, map[string]any{"returnImmediately": true, "ack": acks})
	if status != http.StatusOK {
		t.Fatalf("ack poll status=%d body=%v", status, body)
	}
	if sets, _ := body["sets"].(map[string]any); len(sets) != 0 {
		t.Errorf("acked SETs returned again: %v", sets)
	}

	other := mustSSFToken(t, tk, ssfE2EPushClient)
	if status, body := ssfDo(t, tk, http.MethodPost, pollPath, other, map[string]any{"returnImmediately": true}); status != http.StatusNotFound {
		t.Errorf("other receiver polling the stream: status=%d body=%v, want 404", status, body)
	}
	if status, body := ssfDo(t, tk, http.MethodGet, "/oidc/ssf/streams?stream_id="+url.QueryEscape(streamID), other, nil); status != http.StatusNotFound {
		t.Errorf("other receiver reading the stream: status=%d body=%v, want 404", status, body)
	}
}

// TestSSFE2E_Metadata pins the transmitter metadata route outside the
// mount prefix and its advertised endpoints.
func TestSSFE2E_Metadata(t *testing.T) {
	t.Parallel()
	tk := newSSFE2EProvider(t)
	resp := ssfBrowserGet(t, tk.HTTPClient(nil), tk.Server.URL+"/.well-known/ssf-configuration")
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status=%d err=%v", resp.StatusCode, err)
	}
	want := map[string]string{
		"spec_version":           "1_0",
		"issuer":                 tk.Issuer,
		"jwks_uri":               tk.Issuer + "/oidc/jwks",
		"configuration_endpoint": tk.Issuer + "/oidc/ssf/streams",
		"status_endpoint":        tk.Issuer + "/oidc/ssf/status",
		"verification_endpoint":  tk.Issuer + "/oidc/ssf/verify",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("metadata %s = %v, want %s", k, doc[k], v)
		}
	}
}

// TestSSFE2E_EmitSecurityEventValidation pins the input checks that run
// whether or not the transmitter is on, and the silent no-op without it.
func TestSSFE2E_EmitSecurityEventValidation(t *testing.T) {
	t.Parallel()
	on := newSSFE2EProvider(t)
	off := testkit.NewProvider(t)
	bad := []op.SecurityEvent{
		nil,
		op.SessionRevoked{},
		op.CredentialChange{Subject: "s", CredentialType: "smoke-signal", ChangeType: op.CredentialChangeCreate},
		op.CredentialChange{Subject: "s", CredentialType: op.CredentialTypePIN, ChangeType: "rename"},
		op.AccountDisabled{Subject: "s", Reason: "boredom"},
		op.CredentialCompromise{Subject: "s"},
	}
	for _, p := range []*op.Provider{on.OP, off.OP} {
		for i, ev := range bad {
			if err := p.EmitSecurityEvent(context.Background(), ev); err == nil {
				t.Errorf("case %d: EmitSecurityEvent(%#v) = nil, want an error", i, ev)
			}
		}
	}
	for _, ev := range []op.SecurityEvent{
		op.SessionRevoked{Subject: "s"},
		op.AccountDisabled{Subject: "s", Reason: op.AccountDisabledHijacking},
		op.AccountEnabled{Subject: "s"},
		op.AccountPurged{Subject: "s"},
		op.CredentialCompromise{Subject: "s", CredentialType: op.CredentialTypeFIDOU2F},
	} {
		if err := off.OP.EmitSecurityEvent(context.Background(), ev); err != nil {
			t.Errorf("without WithSharedSignals EmitSecurityEvent(%#v) = %v, want nil", ev, err)
		}
		if err := on.OP.EmitSecurityEvent(context.Background(), ev); err != nil {
			t.Errorf("EmitSecurityEvent(%#v) with no receiver = %v, want nil", ev, err)
		}
	}
}
