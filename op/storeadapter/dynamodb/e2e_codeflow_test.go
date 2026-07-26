//go:build testcontainers

package oidcdynamo_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	e2eClientID    = "dynamo-rp"
	e2eRedirectURI = "https://rp.example.com/callback"
	e2eSubject     = "dynamo-user"
	csrfCookieName = "__Host-oidc_csrf"
)

// TestDynamoDB_AuthorizationCodeFlow drives a full browser
// authorization-code round-trip against an OP whose only storage is
// DynamoDB. It is the end-to-end counterpart to the contract harness:
// the contract pins each substore's semantics in isolation, while this
// proves the pieces compose — in particular that op.New accepts the
// adapter as a transactional store and that the grant, the code, and
// the tokens all commit through it.
func TestDynamoDB_AuthorizationCodeFlow(t *testing.T) {
	t.Parallel()

	client := newEmulatorClient(t)
	dynamo, err := oidcdynamo.New(client, oidcdynamo.WithTablePrefix("e2e_"))
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := dynamo.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}

	provider := testkit.NewProvider(t, testkit.WithOptions(
		op.WithStore(dynamo),
		op.WithStaticClients(op.PublicClient{
			ID:           e2eClientID,
			RedirectURIs: []string{e2eRedirectURI},
			Scopes:       []string{"openid", "profile"},
		}),
	))

	if err := dynamo.PutUser(t.Context(), &store.User{
		Subject: e2eSubject,
		Claims:  map[string]any{"name": "Dynamo User"},
	}); err != nil {
		t.Fatalf("PutUser: %v", err)
	}

	verifier := "dynamo-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	code := runCodeFlow(t, provider, verifier)
	if code == "" {
		t.Fatal("authorization code was not issued")
	}

	tokens := exchangeCode(t, provider, code, verifier)
	if tokens["access_token"] == nil {
		t.Fatalf("token response carries no access_token: %v", tokens)
	}
	if tokens["id_token"] == nil {
		t.Fatalf("token response carries no id_token: %v", tokens)
	}

	accessToken, _ := tokens["access_token"].(string)
	assertUserInfoStatus(t, provider, accessToken, http.StatusOK)

	// The code is single-use, and redeeming it twice is the RFC 6749
	// §4.1.2 replay signal: the exchange fails and the whole grant is
	// cascaded to revoked. Asserting both halves is what proves the
	// cascade actually reached DynamoDB rather than failing silently.
	replay := exchangeCodeRaw(t, provider, code, verifier)
	_ = replay.Body.Close()
	if replay.StatusCode == http.StatusOK {
		t.Fatal("replayed authorization code was accepted")
	}
	assertUserInfoStatus(t, provider, accessToken, http.StatusUnauthorized)
}

// jtiOf pulls the jti claim out of a JWT access token without verifying
// it: the signature is the OP's own and the test only needs the id.
func jtiOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode access token claims: %v", err)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatalf("access token carries no jti: %s", payload)
	}
	return jti
}

// runCodeFlow walks /authorize → interaction → consent → callback and
// returns the authorization code.
func runCodeFlow(t *testing.T, p *testkit.Provider, verifier string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	httpClient := p.HTTPClient(jar)

	params := url.Values{
		"client_id":             {e2eClientID},
		"redirect_uri":          {e2eRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"dynamo-state"},
		"nonce":                 {"dynamo-nonce"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}

	resp := mustGet(t, httpClient, p.Server.URL+"/oidc/auth?"+params.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/authorize status=%d body=%s", resp.StatusCode, body)
	}
	location, err := resp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize Location=%s, want an interaction URL", location)
	}
	interactionURL := p.Server.URL + location.Path

	prompt := mustGet(t, httpClient, interactionURL)
	defer func() { _ = prompt.Body.Close() }()
	if prompt.StatusCode != http.StatusOK {
		t.Fatalf("GET interaction status=%d", prompt.StatusCode)
	}
	envelope := decodeJSON(t, prompt)
	stateRef, _ := envelope["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("interaction prompt carries no state_ref")
	}
	csrf := findCookie(prompt.Cookies(), csrfCookieName)
	if csrf == nil {
		t.Fatalf("interaction prompt set no %s cookie", csrfCookieName)
	}

	authnResp := postInteraction(t, httpClient, interactionURL, p.Issuer, csrf, stateRef,
		map[string]string{testkit.SubjectFieldName: e2eSubject})
	final := approveConsent(t, httpClient, interactionURL, p.Issuer, csrf, authnResp)
	defer func() { _ = final.Body.Close() }()

	if final.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(final.Body)
		t.Fatalf("final interaction status=%d body=%s", final.StatusCode, body)
	}
	callback, err := final.Location()
	if err != nil {
		t.Fatalf("final Location: %v", err)
	}
	if got := callback.Query().Get("error"); got != "" {
		t.Fatalf("callback carries error=%s (%s)", got, callback.Query().Get("error_description"))
	}
	if got := callback.Query().Get("state"); got != "dynamo-state" {
		t.Fatalf("callback state=%q, want dynamo-state", got)
	}
	return callback.Query().Get("code")
}

// approveConsent submits the built-in consent screen when one is
// prompted, approving every requested scope.
func approveConsent(
	t *testing.T,
	httpClient *http.Client,
	interactionURL, origin string,
	csrf *http.Cookie,
	prior *http.Response,
) *http.Response {
	t.Helper()
	consent, envelope, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	stateRef, _ := envelope["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("consent prompt carries no state_ref")
	}
	// Each step boundary re-issues the CSRF cookie, so the value minted
	// for the authentication step does not verify against consent.
	if rotated := findCookie(prior.Cookies(), csrfCookieName); rotated != nil {
		csrf = rotated
	}
	scopes := requestedScopes(t, envelope)
	_ = prior.Body.Close()

	return postInteraction(t, httpClient, interactionURL, origin, csrf, stateRef,
		map[string]string{"approved_scopes": strings.Join(scopes, " ")})
}

func requestedScopes(t *testing.T, envelope map[string]any) []string {
	t.Helper()
	data, _ := envelope["data"].(map[string]any)
	raw, _ := data["scopes"].([]any)
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		switch v := entry.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			if name, ok := v["name"].(string); ok {
				out = append(out, name)
			}
		}
	}
	return out
}

func exchangeCode(t *testing.T, p *testkit.Provider, code, verifier string) map[string]any {
	t.Helper()
	resp := exchangeCodeRaw(t, p, code, verifier)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status=%d body=%s", resp.StatusCode, body)
	}
	return decodeJSON(t, resp)
}

func exchangeCodeRaw(t *testing.T, p *testkit.Provider, code, verifier string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {e2eRedirectURI},
		"client_id":     {e2eClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.Server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	return resp
}

// assertUserInfoStatus drives /userinfo with the token and asserts the
// status. A 200 confirms the token resolves back to the subject through
// the grant stored in DynamoDB; a 401 after the replay confirms the
// revocation cascade landed there too.
func assertUserInfoStatus(t *testing.T, p *testkit.Provider, accessToken string, want int) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		p.Server.URL+"/oidc/userinfo", nil)
	if err != nil {
		t.Fatalf("build /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := p.Server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/userinfo status=%d want %d challenge=%q body=%s",
			resp.StatusCode, want, resp.Header.Get("WWW-Authenticate"), body)
	}
	if want != http.StatusOK {
		return
	}
	claims := decodeJSON(t, resp)
	if claims["sub"] != e2eSubject {
		t.Fatalf("/userinfo sub=%v, want %s", claims["sub"], e2eSubject)
	}
}

func postInteraction(
	t *testing.T,
	httpClient *http.Client,
	interactionURL, origin string,
	csrf *http.Cookie,
	stateRef string,
	values map[string]string,
) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		t.Fatalf("marshal interaction submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		interactionURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build interaction POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(csrf)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	return resp
}

func mustGet(t *testing.T, httpClient *http.Client, target string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", target, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body %s: %v", raw, err)
	}
	return out
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
