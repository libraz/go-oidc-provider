package op_test

// End-to-end coverage of client ID metadata documents: an httptest server
// publishes a document whose client_id is its own URL, and the OP resolves
// it under the dev-only private-network option (the document is served
// over http on 127.0.0.1).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	cimdDocPath  = "/client.json"
	cimdCallback = "http://127.0.0.1:53111/callback"
	// cimdPublicJWK is a fixed P-256 public key; the PKCE test never signs.
	cimdPublicJWK = `{"kty":"EC","crv":"P-256","kid":"mcp-1","use":"sig","alg":"ES256",` +
		`"x":"Ic7hdc2EYvl1G6v4UzZhXxDpVPMkMfJzad8tjzD7R80","y":"WEdXWZ-oH_wg4OQA124qdcN2Fs9iBINN-EfV0ewy6V0"}`
)

// cimdDocServer serves one client ID metadata document and counts fetches.
type cimdDocServer struct {
	srv   *httptest.Server
	id    string
	hits  atomic.Int32
	extra map[string]any
}

func newCIMDDocServer(t *testing.T, extra map[string]any) *cimdDocServer {
	t.Helper()
	d := &cimdDocServer{extra: extra}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cimdDocPath {
			http.NotFound(w, r)
			return
		}
		d.hits.Add(1)
		doc := map[string]any{
			"client_id":     d.id,
			"client_name":   "Example MCP Client",
			"logo_uri":      "https://mcp.example.com/logo.png",
			"redirect_uris": []string{cimdCallback},
		}
		for k, v := range d.extra {
			doc[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(d.srv.Close)
	d.id = d.srv.URL + cimdDocPath
	return d
}

func newCIMDProvider(t *testing.T, extra ...op.Option) *testkit.Provider {
	t.Helper()
	opts := append([]op.Option{
		op.WithClientIDMetadataDocuments(op.ClientIDMetadataDocuments{}),
		op.WithAllowPrivateNetwork(op.OutboundClientIDMetadata),
	}, extra...)
	return testkit.NewProvider(t, testkit.WithOptions(opts...))
}

// cimdFlow drives one authorization-code round trip on its own cookie jar.
type cimdFlow struct {
	tk       *testkit.Provider
	client   *http.Client
	clientID string
}

func newCIMDFlow(t *testing.T, tk *testkit.Provider, clientID string) *cimdFlow {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &cimdFlow{tk: tk, client: tk.HTTPClient(jar), clientID: clientID}
}

func (f *cimdFlow) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

func (f *cimdFlow) authorizeQuery(pkce bool) url.Values {
	q := url.Values{
		"client_id":     {f.clientID},
		"response_type": {"code"},
		"redirect_uri":  {cimdCallback},
		"scope":         {"openid"},
		"state":         {"state-cimd"},
		"nonce":         {"nonce-cimd"},
	}
	if pkce {
		q.Set("code_challenge", scdChallenge())
		q.Set("code_challenge_method", "S256")
	}
	return q
}

// startAuthorize sends /authorize and returns the redirect Location.
func (f *cimdFlow) startAuthorize(t *testing.T, q url.Values) *url.URL {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.tk.Server.URL+"/oidc/auth?"+q.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	resp := f.do(t, req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/authorize status=%d want 302 body=%s", resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	return loc
}

// login submits the testkit subject on the interaction and returns the
// consent prompt envelope, the interaction URL and the current CSRF value.
func (f *cimdFlow) login(t *testing.T, interactionPath string) (envelope map[string]any, interactionURL, csrf string) {
	t.Helper()
	interactionURL = f.tk.Server.URL + interactionPath
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("build interaction GET: %v", err)
	}
	prompt := f.do(t, req)
	var step map[string]any
	err = json.NewDecoder(prompt.Body).Decode(&step)
	_ = prompt.Body.Close()
	if err != nil {
		t.Fatalf("decode interaction prompt: %v", err)
	}
	stateRef, _ := step["state_ref"].(string)
	cookie := scdCSRFCookie(prompt.Cookies())
	if stateRef == "" || cookie == nil {
		t.Fatalf("interaction prompt missing state_ref/csrf: %v", step)
	}
	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{testkit.SubjectFieldName: "user-cimd"},
	})
	if err != nil {
		t.Fatalf("marshal interaction body: %v", err)
	}
	post, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build interaction POST: %v", err)
	}
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Origin", f.tk.Issuer)
	post.Header.Set("X-CSRF-Token", cookie.Value)
	post.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: cookie.Value})
	resp := f.do(t, post)
	defer func() { _ = resp.Body.Close() }()
	consent, env, err := testkit.IsConsentPrompt(resp)
	if err != nil || !consent {
		t.Fatalf("expected consent prompt (err=%v): %v", err, env)
	}
	if rotated := scdCSRFCookie(resp.Cookies()); rotated != nil {
		cookie = rotated
	}
	return env, interactionURL, cookie.Value
}

// approve submits consent and returns the authorization code.
func (f *cimdFlow) approve(t *testing.T, env map[string]any, interactionURL, csrf string) string {
	t.Helper()
	stateRef, _ := env["state_ref"].(string)
	final := testkit.PostConsentApproval(t, f.client, interactionURL, f.tk.Issuer, csrf, stateRef, "openid")
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(final.Body)
		t.Fatalf("consent status=%d body=%s", final.StatusCode, body)
	}
	loc, err := final.Location()
	if err != nil {
		t.Fatalf("consent Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != cimdCallback {
		t.Fatalf("callback=%s want %s", got, cimdCallback)
	}
	return scdCodeFrom(t, loc)
}

func (f *cimdFlow) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := f.do(t, req)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp.StatusCode, out
}

func (f *cimdFlow) redeem(t *testing.T, code string) map[string]any {
	t.Helper()
	status, body := f.token(t, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.clientID},
		"code":          {code},
		"redirect_uri":  {cimdCallback},
		"code_verifier": {scdVerifier},
	})
	if status != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", status, body)
	}
	return body
}

// TestCIMD_E2E_AuthorizeConsentToken runs the full public-client flow: the
// OP fetches the document at /authorize, the consent prompt names the
// document host and the loopback redirect without the document's logo, and
// the code redeems with "none" plus PKCE.
func TestCIMD_E2E_AuthorizeConsentToken(t *testing.T) {
	t.Parallel()

	doc := newCIMDDocServer(t, nil)
	tk := newCIMDProvider(t)
	f := newCIMDFlow(t, tk, doc.id)

	loc := f.startAuthorize(t, f.authorizeQuery(true))
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize Location=%s want interaction", loc)
	}
	env, interactionURL, csrf := f.login(t, loc.Path)

	data, _ := env["data"].(map[string]any)
	client, _ := data["client"].(map[string]any)
	docHost := strings.TrimPrefix(doc.srv.URL, "http://")
	for key, want := range map[string]any{
		"client_id":              doc.id,
		"name":                   "Example MCP Client",
		"metadata_document_host": docHost,
		"redirect_host":          "127.0.0.1",
		"redirect_loopback":      true,
		"logo_url":               "",
	} {
		if got := client[key]; got != want {
			t.Errorf("consent client.%s = %v, want %v", key, got, want)
		}
	}

	code := f.approve(t, env, interactionURL, csrf)
	body := f.redeem(t, code)
	if at, _ := body["access_token"].(string); at == "" {
		t.Fatalf("token response carries no access_token: %v", body)
	}
	if got := doc.hits.Load(); got != 1 {
		t.Errorf("document fetched %d times, want 1 (cached across /authorize and /token)", got)
	}
}

// TestCIMD_E2E_RegisteredClientWins pins that a registered client with the
// same id is served from the store without a fetch, and is projected like
// any registered client.
func TestCIMD_E2E_RegisteredClientWins(t *testing.T) {
	t.Parallel()

	doc := newCIMDDocServer(t, nil)
	tk := newCIMDProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      doc.id,
		RedirectURIs:            []string{scdCallback},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
	})
	code, _ := newSCDFlow(t, tk, doc.id).authorize(t)
	if code == "" {
		t.Fatal("registered client did not complete /authorize")
	}
	if got := doc.hits.Load(); got != 0 {
		t.Errorf("document fetched %d times for a registered client_id, want 0", got)
	}
}

// TestCIMD_E2E_PrivateKeyJWTRequiresPKCE pins that a document client must
// send PKCE even when it authenticates with private_key_jwt and no profile
// makes PKCE mandatory OP-wide.
func TestCIMD_E2E_PrivateKeyJWTRequiresPKCE(t *testing.T) {
	t.Parallel()

	var jwk map[string]any
	if err := json.Unmarshal([]byte(cimdPublicJWK), &jwk); err != nil {
		t.Fatalf("unmarshal jwk: %v", err)
	}
	// A web redirect: a loopback one would make the client native, which
	// requires PKCE on its own.
	doc := newCIMDDocServer(t, map[string]any{ //nolint:gosec // G101: auth method name, not a credential.
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       map[string]any{"keys": []any{jwk}},
		"redirect_uris":              []string{scdCallback},
	})
	tk := newCIMDProvider(t)
	f := newCIMDFlow(t, tk, doc.id)

	q := f.authorizeQuery(false)
	q.Set("redirect_uri", scdCallback)
	loc := f.startAuthorize(t, q)
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != scdCallback {
		t.Fatalf("/authorize Location=%s want error redirect to %s", loc, scdCallback)
	}
	if e, d := loc.Query().Get("error"), loc.Query().Get("error_description"); e != "invalid_request" ||
		!strings.Contains(d, "code_challenge") {
		t.Fatalf("error=%q (%s), want invalid_request for the missing code_challenge", e, d)
	}
	if doc.hits.Load() != 1 {
		t.Errorf("document fetched %d times, want 1", doc.hits.Load())
	}
}

// TestCIMD_E2E_TokenExchangeUnauthorized pins that a document client is
// resolved at the token-exchange grant and refused there: documents may
// declare only the authorization_code and refresh_token grants.
func TestCIMD_E2E_TokenExchangeUnauthorized(t *testing.T) {
	t.Parallel()

	doc := newCIMDDocServer(t, map[string]any{
		"grant_types": []string{"authorization_code", op.TokenExchangeGrantType},
	})
	tk := newCIMDProvider(t, op.WithTokenExchangeGrant(op.TokenExchangeGrant{Policy: cimdAllowAllExchange{}}))
	f := newCIMDFlow(t, tk, doc.id)

	loc := f.startAuthorize(t, f.authorizeQuery(true))
	env, interactionURL, csrf := f.login(t, loc.Path)
	body := f.redeem(t, f.approve(t, env, interactionURL, csrf))
	accessToken, _ := body["access_token"].(string)

	status, out := f.token(t, url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"client_id":          {doc.id},
		"subject_token":      {accessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != http.StatusBadRequest || out["error"] != "unauthorized_client" {
		t.Fatalf("token exchange status=%d body=%v, want 400 unauthorized_client", status, out)
	}
}

type cimdAllowAllExchange struct{}

func (cimdAllowAllExchange) Allow(context.Context, op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return &op.TokenExchangeDecision{}, nil
}

// TestCIMD_New_RejectsFAPIProfile pins the op.New refusal end to end.
func TestCIMD_New_RejectsFAPIProfile(t *testing.T) {
	t.Parallel()

	_, err := op.New(testkit.MinimalOptions(t,
		op.WithProfile(profile.FAPI2Baseline),
		op.WithClientIDMetadataDocuments(op.ClientIDMetadataDocuments{}),
	)...)
	if err == nil || !strings.Contains(err.Error(), "WithClientIDMetadataDocuments") {
		t.Fatalf("op.New = %v, want a WithClientIDMetadataDocuments configuration error", err)
	}
}

// TestCIMD_New_RejectsURLFirstPartyClient pins that a document URL cannot
// be named first-party: the set only admits static client ids.
func TestCIMD_New_RejectsURLFirstPartyClient(t *testing.T) {
	t.Parallel()

	const id = "https://mcp.example.com/client.json"
	_, err := op.New(testkit.MinimalOptions(t,
		op.WithClientIDMetadataDocuments(op.ClientIDMetadataDocuments{}),
		op.WithFirstPartyClients(id),
	)...)
	if err == nil || !strings.Contains(err.Error(), id) {
		t.Fatalf("op.New = %v, want unknown first-party client_id %s", err, id)
	}
}

// TestCIMD_Discovery_Advertises pins the discovery fields a CIMD client
// looks for: the support flag, "none" and S256.
func TestCIMD_Discovery_Advertises(t *testing.T) {
	t.Parallel()

	for _, enabled := range []bool{false, true} {
		var tk *testkit.Provider
		if enabled {
			tk = newCIMDProvider(t)
		} else {
			tk = testkit.NewProvider(t)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tk.Server.URL+"/.well-known/openid-configuration", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := tk.Server.Client().Do(req)
		if err != nil {
			t.Fatalf("GET discovery: %v", err)
		}
		var doc map[string]any
		err = json.NewDecoder(resp.Body).Decode(&doc)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("decode discovery: %v", err)
		}
		flag, present := doc["client_id_metadata_document_supported"]
		if present != enabled || (enabled && flag != true) {
			t.Errorf("enabled=%v: client_id_metadata_document_supported=%v present=%v", enabled, flag, present)
		}
		if enabled {
			methods, _ := doc["token_endpoint_auth_methods_supported"].([]any)
			if !containsAny(methods, "none") {
				t.Errorf("token_endpoint_auth_methods_supported=%v, want none", methods)
			}
			challenges, _ := doc["code_challenge_methods_supported"].([]any)
			if !containsAny(challenges, "S256") {
				t.Errorf("code_challenge_methods_supported=%v, want S256", challenges)
			}
		}
	}
}

func containsAny(list []any, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
