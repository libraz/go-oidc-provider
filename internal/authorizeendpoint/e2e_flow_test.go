package authorizeendpoint_test

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

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// e2eFlow bundles what a multi-hop /authorize → /interaction → /token
// test threads through every request: the provider under test, a
// cookie-jar-backed browser (so the session cookie survives between
// authorize requests), and the registered RP with its secret.
//
// The helper exists for the tests that need MORE THAN ONE authorize
// pass against the same session — the single-pass tests in this package
// spell their hops out inline.
type e2eFlow struct {
	tk     *testkit.Provider
	client *http.Client
	rp     *store.Client
	secret string
}

// newE2EFlow builds a provider with the supplied testkit options and
// registers one client_secret_basic RP under clientID.
func newE2EFlow(t *testing.T, clientID string, opts ...testkit.Option) *e2eFlow {
	t.Helper()
	tk := testkit.NewProvider(t, opts...)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &e2eFlow{tk: tk, client: tk.HTTPClient(jar), rp: rp, secret: secret}
}

// values returns the canonical happy-path authorize parameters for the
// registered RP; callers Set the parameter under test on top.
func (f *e2eFlow) values() url.Values {
	return e2eAuthorizeValues(f.rp.ID, f.rp.RedirectURIs[0])
}

// authorize issues GET /authorize and returns the Location of the 302.
func (f *e2eFlow) authorize(t *testing.T, values url.Values) *url.URL {
	t.Helper()
	resp, err := newGet(f.tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(f.client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status=%d body=%s", resp.StatusCode, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	return loc
}

// interactionURL is the absolute URL of the interaction the authorize
// redirect points at.
func (f *e2eFlow) interactionURL(loc *url.URL) string {
	return f.tk.Server.URL + loc.Path
}

// submitSubject drives the first interaction hop: GET the prompt, then
// POST the testkit subject factor. The returned response is whatever
// the chain produced next — a consent prompt when consent is still
// owed, or the final redirect back to the RP — and stays open for the
// caller. The returned token is the CSRF value minted for the authn
// step; a consent submission re-reads the rotated cookie off the
// response.
func (f *e2eFlow) submitSubject(t *testing.T, interactionURL, subject string) (*http.Response, string) {
	t.Helper()
	stepResp, err := newGet(interactionURL).Do(f.client)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	step := decodeMap(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		t.Fatalf("state_ref missing from interaction step: %v", step)
	}
	csrfCookie := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing from interaction step")
	}
	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": subject},
	})
	if err != nil {
		t.Fatalf("marshal subject submission: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest POST interaction: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", f.tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postResp, err := f.client.Do(postReq)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	return postResp, csrfCookie.Value
}

// completeLogin runs the whole interaction the authorize redirect points
// at — subject factor plus the consent screen when the chain asks for
// it — and returns the authorization code from the RP redirect.
func (f *e2eFlow) completeLogin(t *testing.T, loc *url.URL, subject string) string {
	t.Helper()
	interactionURL := f.interactionURL(loc)
	postResp, csrf := f.submitSubject(t, interactionURL, subject)
	defer postResp.Body.Close()
	finalResp := completeConsentIfPrompted(t, f.client, interactionURL, f.tk.Issuer, csrf, postResp)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("interaction final status=%d body=%s", finalResp.StatusCode, string(dump))
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after interaction: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}
	return code
}

// exchange redeems code at /token and returns the decoded id_token
// claim set.
func (f *e2eFlow) exchange(t *testing.T, code string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.rp.ID, f.secret)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("token status=%d body=%s", resp.StatusCode, string(dump))
	}
	body := decodeMap(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatalf("id_token missing: %v", body)
	}
	return decodeIDTokenPayload(t, idt)
}
