package parendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_PAR_AuthorizeInteractionToken drives the full
// /par → /authorize → /interaction → /token flow against a real testkit-
// backed server. The shape mirrors the equivalent non-PAR end-to-end test
// inside internal/authorizeendpoint so a regression in either path is
// equally visible.
func TestEndToEnd_PAR_AuthorizeInteractionToken(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.PAR)),
	)
	const secret = "rp-par-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-par-1",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	// 1: POST /par with client_secret_basic.
	verifier, challenge := pkcePair()
	parForm := url.Values{
		"client_id":             {rp.ID},
		"response_type":         {"code"},
		"redirect_uri":          {rp.RedirectURIs[0]},
		"scope":                 {"openid profile email"},
		"state":                 {"par-state"},
		"nonce":                 {"par-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	parReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/par", strings.NewReader(parForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.SetBasicAuth(rp.ID, secret)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)
	parResp, err := client.Do(parReq)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	defer parResp.Body.Close()
	if parResp.StatusCode != http.StatusCreated {
		dump, _ := io.ReadAll(parResp.Body)
		t.Fatalf("/par status=%d body=%s", parResp.StatusCode, dump)
	}
	parBody := decodeJSON(t, parResp)
	requestURI, _ := parBody["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("request_uri missing: %v", parBody)
	}

	// 2: GET /authorize?client_id=...&request_uri=...
	authorizeQuery := url.Values{
		"client_id":   {rp.ID},
		"request_uri": {requestURI},
	}
	authReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+authorizeQuery.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("Do /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("/authorize status=%d body=%s", authResp.StatusCode, dump)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s", location.String())
	}

	// 3: GET /interaction/{uid} → CSRF token.
	stepReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+location.Path, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /interaction: %v", err)
	}
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("Do /interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		t.Fatalf("/interaction GET status=%d", stepResp.StatusCode)
	}
	step := decodeJSON(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("state_ref missing from step body")
	}
	var csrfCookie *http.Cookie
	for _, c := range stepResp.Cookies() {
		if c.Name == "__Host-oidc_csrf" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing")
	}

	// 4: POST /interaction/{uid} with the SubjectAuthenticator
	// submission shape.
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-par"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+location.Path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest POST /interaction: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("Do POST /interaction: %v", err)
	}
	defer postResp.Body.Close()
	finalResp := completeConsentIfPromptedPAR(t, client, tk.Server.URL+location.Path, tk.Issuer, csrfCookie.Value, postResp)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("POST /interaction status=%d body=%s", finalResp.StatusCode, dump)
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}
	if rpRedirect.Query().Get("state") != "par-state" {
		t.Errorf("state=%q want par-state", rpRedirect.Query().Get("state"))
	}

	// 5: POST /token to exchange the code for tokens.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {verifier},
	}
	tokenReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(rp.ID, secret)
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("Do /token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("/token status=%d body=%s", tokenResp.StatusCode, dump)
	}
	tokenBody := decodeJSON(t, tokenResp)
	if at, _ := tokenBody["access_token"].(string); at == "" {
		t.Errorf("access_token missing: %v", tokenBody)
	}
	if idt, _ := tokenBody["id_token"].(string); idt == "" {
		t.Errorf("id_token missing: %v", tokenBody)
	}
}

// TestEndToEnd_PAR_AuthorizeRejectsReplay confirms that a request_uri
// becomes single-use once an authorization code has been issued against
// it. Pins the RFC 9126 §2.2 / FAPI 2.0 §5.3.2 one-time-use contract.
//
// The library deliberately permits multiple /authorize visits before
// authentication completes (see [FAPI2SPID2PAREnsureServerAcceptsReused
// RequestUriBeforeAuthenticationCompletion] in the conformance suite —
// a multi-step interaction or the user opening the URL twice MUST keep
// resolving). The single-use guarantee is enforced when the code is
// emitted, simulated here by directly stamping ConsumedAt on the
// substore record.
//
// Tracks: RFC 9126 §2.2 ("the AS MUST treat the request_uri as a
// one-time-use value"), and the security rationale documented in the
// 2024 formal analysis of FAPI 2.0 (eprint.iacr.org/2024/1540) — a
// re-redeemable request_uri lets an attacker who intercepts the URI
// log in as the victim by repeating /authorize after the legitimate
// flow finishes. The threat shape mirrors the authorization-code
// replay class for which RFC 6749 §4.1.2 already prescribes
// invalid_grant.
func TestEndToEnd_PAR_AuthorizeRejectsReplay(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.PAR)),
	)
	const secret = "rp-replay-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-replay",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	_, challenge := pkcePair()
	parForm := url.Values{
		"client_id":             {rp.ID},
		"response_type":         {"code"},
		"redirect_uri":          {rp.RedirectURIs[0]},
		"scope":                 {"openid profile email"},
		"state":                 {"par-replay-state"},
		"nonce":                 {"par-replay-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	parReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/par", strings.NewReader(parForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.SetBasicAuth(rp.ID, secret)
	parResp, err := tk.HTTPClient(nil).Do(parReq)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	defer parResp.Body.Close()
	if parResp.StatusCode != http.StatusCreated {
		t.Fatalf("/par status=%d", parResp.StatusCode)
	}
	requestURI, _ := decodeJSON(t, parResp)["request_uri"].(string)

	// First /authorize parks the user at interaction; the URI remains
	// resolvable so a second visit before auth completes can reuse it.
	first := getAuthorize(t, tk, rp.ID, requestURI)
	if first.StatusCode != http.StatusFound {
		t.Fatalf("first /authorize status=%d want 302", first.StatusCode)
	}
	first.Body.Close()

	// Second /authorize before auth completion: still acceptable, the
	// URI is single-use only once a code has been issued.
	preAuth := getAuthorize(t, tk, rp.ID, requestURI)
	if preAuth.StatusCode != http.StatusFound {
		t.Fatalf("pre-auth replay status=%d want 302", preAuth.StatusCode)
	}
	preAuth.Body.Close()

	// Simulate code emission: redeem the PAR record via the store
	// (the same call interaction.go performs immediately before the
	// authorization code is persisted).
	if _, err := tk.Store.PushedAuthRequests().Consume(context.Background(), requestURI); err != nil {
		t.Fatalf("PARs.Consume: %v", err)
	}

	// Post-emission /authorize must be rejected as invalid_request_uri.
	second := getAuthorize(t, tk, rp.ID, requestURI)
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("second /authorize status=%d want 400", second.StatusCode)
	}
	body := decodeJSON(t, second)
	if body["error"] != "invalid_request_uri" {
		t.Errorf("error=%v want invalid_request_uri", body["error"])
	}
}

// TestEndToEnd_PAR_DisabledRejectsRequestURI confirms that an OP without
// the [feature.PAR] flag enabled rejects a /authorize request carrying a
// request_uri. Per RFC 9126 §2.3 the OP must NOT honour request_uri
// unless it advertises the PAR endpoint.
func TestEndToEnd_PAR_DisabledRejectsRequestURI(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{ID: "rp-no-par"})

	resp := getAuthorize(t, tk, rp.ID,
		"urn:ietf:params:oauth:request_uri:something")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

// TestEndToEnd_PAR_DiscoveryAdvertisement confirms PAR discovery gating.
// Without the flag the endpoint metadata is absent; with the flag it
// surfaces under pushed_authorization_request_endpoint.
func TestEndToEnd_PAR_DiscoveryAdvertisement(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithFeature(feature.PAR)),
	)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	doc := decodeJSON(t, resp)
	endpoint, _ := doc["pushed_authorization_request_endpoint"].(string)
	if !strings.HasSuffix(endpoint, "/oidc/par") {
		t.Errorf("PAR endpoint=%q does not match /oidc/par suffix", endpoint)
	}
}

// completeConsentIfPromptedPAR submits the built-in consent screen
// with every requested scope approved when prior is a consent prompt.
// Returns prior unchanged when it is already a redirect or a non-
// consent response.
func completeConsentIfPromptedPAR(t testing.TB, client *http.Client, interactionURL, origin, csrf string, prior *http.Response) *http.Response {
	t.Helper()
	consent, env, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	stateRef, _ := env["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("consent prompt missing state_ref")
	}
	for _, c := range prior.Cookies() {
		if c.Name == "__Host-oidc_csrf" {
			csrf = c.Value
			break
		}
	}
	approved := approvedScopesFromPromptPAR(env)
	return testkit.PostConsentApproval(t, client, interactionURL, origin, csrf, stateRef, approved)
}

// approvedScopesFromPromptPAR extracts the requested scope names from
// the consent prompt envelope and returns them as a space-delimited
// string.
func approvedScopesFromPromptPAR(env map[string]any) string {
	data, _ := env["data"].(map[string]any)
	scopesAny, _ := data["Scopes"].([]any)
	out := make([]string, 0, len(scopesAny))
	for _, s := range scopesAny {
		entry, _ := s.(map[string]any)
		name, _ := entry["Name"].(string)
		if name != "" {
			out = append(out, name)
		}
	}
	return strings.Join(out, " ")
}

// getAuthorize issues a GET /authorize with the supplied client_id and
// request_uri. It returns the raw [http.Response]; the caller is
// responsible for closing the body.
func getAuthorize(tb testing.TB, tk *testkit.Provider, clientID, requestURI string) *http.Response {
	tb.Helper()
	values := url.Values{"client_id": {clientID}, "request_uri": {requestURI}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	// HTTPClient already disables redirect following so the test sees the 302.
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}
