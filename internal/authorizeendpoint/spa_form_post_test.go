package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// spaFormPostMount is the SPA login mount every row in this file wires
// through [op.WithSPAUI]. It is deliberately distinct from the legacy
// /oidc/interaction prefix so a response arriving on the wrong surface
// is a routing failure rather than a silent pass.
const spaFormPostMount = "/login"

// rpCallbackRecorder stands in for the RP hosting the redirect_uri. It
// records the method and body of whatever is delivered to the callback
// so a test can assert the authorization response reached the client —
// the property a form-post response mode exists to provide, and the one
// no assertion on the OP's own response shape can establish on its own.
type rpCallbackRecorder struct {
	server *httptest.Server
	mu     sync.Mutex
	method string
	form   url.Values
}

func newRPCallbackRecorder(t *testing.T) *rpCallbackRecorder {
	t.Helper()

	rec := &rpCallbackRecorder{}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.mu.Lock()
		rec.method = r.Method
		rec.form = r.PostForm
		rec.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(rec.server.Close)
	return rec
}

func (rec *rpCallbackRecorder) callbackURL() string { return rec.server.URL + "/callback" }

func (rec *rpCallbackRecorder) received() (method string, form url.Values) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.method, rec.form
}

// spaFormPostHarness drives a Provider whose login surface is the SPA
// mount tree rather than the legacy /interaction/{uid} surface. Every
// hop after /authorize runs against SPALoginMount/state/{uid}, the
// route a SPA reaches with fetch().
type spaFormPostHarness struct {
	tk     *testkit.Provider
	rp     *rpCallbackRecorder
	rpID   string
	client *http.Client
}

func newSPAFormPostHarness(t *testing.T, extra ...op.Option) *spaFormPostHarness {
	t.Helper()

	// The bundle directory is populated so the shell and asset routes
	// mount too: the mount tree under test is the whole one an embedder
	// gets from op.WithSPAUI, not a state-routes-only subset.
	staticDir := t.TempDir()
	mustWriteFile(t, filepath.Join(staticDir, "index.html"),
		"<!doctype html><html><body>SHELL</body></html>")

	options := []testkit.Option{
		testkit.WithClock(fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}),
		testkit.WithOptions(append([]op.Option{
			op.WithSPAUI(op.SPAUI{LoginMount: spaFormPostMount, StaticDir: staticDir}),
		}, extra...)...),
	}
	tk := testkit.NewProvider(t, options...)

	rp := newRPCallbackRecorder(t)
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash("rp-secret")
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-spa-form-post",
		SecretHash:              hash,
		RedirectURIs:            []string{rp.callbackURL()},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &spaFormPostHarness{tk: tk, rp: rp, rpID: client.ID, client: tk.HTTPClient(jar)}
}

// beginInteraction runs /authorize in the requested response_mode and
// returns the SPA state URL the OP handed the user agent, plus the
// prompt envelope and CSRF token the SPA needs for the next hop.
func (h *spaFormPostHarness) beginInteraction(t *testing.T, mode string) (stateURL, stateRef, csrfToken string) {
	t.Helper()

	values := e2eAuthorizeValues(h.rpID, h.rp.callbackURL())
	values.Set("response_mode", mode)
	authResp, err := newGet(h.tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(h.client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, string(dump))
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, spaFormPostMount+"/") {
		t.Fatalf("authorize sent the user agent to %q, want the SPA mount %s/{uid}",
			location.Path, spaFormPostMount)
	}
	uid := strings.TrimPrefix(location.Path, spaFormPostMount+"/")
	stateURL = h.tk.Server.URL + spaFormPostMount + "/state/" + uid

	stepResp, err := newGet(stateURL).Do(h.client)
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	stateRef, _ = step["state_ref"].(string)
	if stateRef == "" {
		t.Fatalf("state_ref missing from SPA state envelope: %v", step)
	}
	csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing from SPA state response")
	}
	return stateURL, stateRef, csrfCookie.Value
}

// driveToTerminal walks /authorize → SPA state GET → SPA state POST in
// the requested response_mode and returns the terminal response, i.e.
// what a SPA's fetch() actually receives when the chain completes.
func (h *spaFormPostHarness) driveToTerminal(t *testing.T, mode string) *http.Response {
	t.Helper()

	stateURL, stateRef, csrfToken := h.beginInteraction(t, mode)
	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-1"},
	})
	if err != nil {
		t.Fatalf("marshal submission: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, stateURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Accept", "application/json")
	postReq.Header.Set("Origin", h.tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfToken)
	postResp, err := h.client.Do(postReq)
	if err != nil {
		t.Fatalf("POST state: %v", err)
	}
	return completeConsentIfPrompted(t, h.client, stateURL, h.tk.Issuer, csrfToken, postResp)
}

// decodeSPATerminal asserts the terminal response is a JSON envelope a
// SPA can consume — a 200 with an application/json body — and returns
// it decoded. A body the SPA cannot parse (the rendered auto-submitting
// HTML document, for instance) fails here with the raw bytes attached.
func decodeSPATerminal(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read terminal body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("terminal status=%d body=%s", resp.StatusCode, string(raw))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("terminal Content-Type=%q, want application/json; the SPA reaches this route with "+
			"fetch() and cannot render a document. body=%s", ct, string(raw))
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("terminal body is not a JSON envelope: %v (raw=%s)", err, string(raw))
	}
	return out
}

// formPostEnvelopeFields asserts the envelope is the form-post terminal
// shape and returns its action plus fields as the form values a SPA
// would post.
func formPostEnvelopeFields(t *testing.T, envelope map[string]any) (action string, fields url.Values) {
	t.Helper()

	if got, _ := envelope["type"].(string); got != "form_post" {
		t.Fatalf("envelope type=%q, want form_post: %v", got, envelope)
	}
	action, _ = envelope["action"].(string)
	if action == "" {
		t.Fatalf("envelope carries no form action: %v", envelope)
	}
	raw, _ := envelope["fields"].(map[string]any)
	if len(raw) == 0 {
		t.Fatalf("envelope carries no form fields: %v", envelope)
	}
	fields = url.Values{}
	for name, value := range raw {
		str, ok := value.(string)
		if !ok {
			t.Fatalf("field %q is %T, want a string the SPA can put in an input value", name, value)
		}
		fields.Set(name, str)
	}
	return action, fields
}

// submitFormPost performs the POST the SPA builds from the envelope —
// the same request the browser would have auto-submitted from the
// rendered form — and fails the test when the RP rejects it.
func submitFormPost(t *testing.T, action string, fields url.Values) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, action,
		strings.NewReader(fields.Encode()))
	if err != nil {
		t.Fatalf("NewRequest form POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST to redirect_uri: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("RP rejected the form POST: status=%d body=%s", resp.StatusCode, string(body))
	}
}

// TestSPA_FormPost_TerminalReachesRedirectURI is the reachability pin
// for response_mode=form_post under the SPA login mount. Discovery
// advertises form_post unconditionally, so the mode has to terminate
// through every supported login surface — including the one whose
// terminal hop is a fetch(), which can neither execute the
// auto-submitting HTML document nor perform the cross-origin POST that
// document would issue.
//
// The row drives the mount end to end and then completes the delivery
// exactly as a SPA would: build a form from the envelope, post it to
// the action, and confirm the RP received code / state / iss as form
// parameters.
func TestSPA_FormPost_TerminalReachesRedirectURI(t *testing.T) {
	t.Parallel()

	h := newSPAFormPostHarness(t)
	resp := h.driveToTerminal(t, "form_post")
	defer resp.Body.Close()

	action, fields := formPostEnvelopeFields(t, decodeSPATerminal(t, resp))
	if action != h.rp.callbackURL() {
		t.Errorf("form action=%q, want the registered redirect_uri %q", action, h.rp.callbackURL())
	}
	if fields.Get("code") == "" {
		t.Errorf("envelope carries no authorization code: %v", fields)
	}
	if got := fields.Get("state"); got != "state-abc" {
		t.Errorf("state=%q, want state-abc", got)
	}
	if got := fields.Get("iss"); got != h.tk.Issuer {
		t.Errorf("iss=%q, want %q (RFC 9207 §2.3)", got, h.tk.Issuer)
	}

	submitFormPost(t, action, fields)
	method, form := h.rp.received()
	if method != http.MethodPost {
		t.Fatalf("RP callback method=%q, want POST", method)
	}
	if form.Get("code") != fields.Get("code") {
		t.Errorf("RP received code=%q, want %q", form.Get("code"), fields.Get("code"))
	}
	if got := form.Get("state"); got != "state-abc" {
		t.Errorf("RP received state=%q, want state-abc", got)
	}
	// A form-post mode exists so the response never enters a URL. The
	// RP must therefore see the parameters in the body, and the OP must
	// not have handed the SPA a redirect envelope to navigate to.
	if form.Get("code") == "" {
		t.Errorf("authorization response did not arrive in the POST body: %v", form)
	}
}

// TestSPA_FormPostJWT_TerminalReachesRedirectURI is the JARM twin. The
// form_post.jwt mode delivers a single signed "response" parameter, and
// its terminal renders through the same writer as the OIDC Core mode —
// so it fails and recovers together with it. The row verifies the JWT
// the envelope carries is the OP's signed authorization response, not
// an opaque blob the SPA merely forwards.
func TestSPA_FormPostJWT_TerminalReachesRedirectURI(t *testing.T) {
	t.Parallel()

	h := newSPAFormPostHarness(t, op.WithFeature(feature.JARM))
	resp := h.driveToTerminal(t, "form_post.jwt")
	defer resp.Body.Close()

	action, fields := formPostEnvelopeFields(t, decodeSPATerminal(t, resp))
	if action != h.rp.callbackURL() {
		t.Errorf("form action=%q, want the registered redirect_uri %q", action, h.rp.callbackURL())
	}
	if fields.Get("code") != "" {
		t.Errorf("JARM response leaked a bare code parameter: %v", fields)
	}
	signed := fields.Get("response")
	if signed == "" {
		t.Fatalf("envelope carries no JARM response parameter: %v", fields)
	}
	claims := verifySPAJARMResponse(t, h.tk, signed)
	if got, _ := claims["code"].(string); got == "" {
		t.Errorf("JARM response has no code claim: %v", claims)
	}
	if got := claims["state"]; got != "state-abc" {
		t.Errorf("JARM state=%v, want state-abc", got)
	}

	submitFormPost(t, action, fields)
	method, form := h.rp.received()
	if method != http.MethodPost {
		t.Fatalf("RP callback method=%q, want POST", method)
	}
	if form.Get("response") != signed {
		t.Errorf("RP received response=%q, want the signed JWT %q", form.Get("response"), signed)
	}
}

// TestSPA_FormPost_CancelDeliversErrorEnvelope covers the cancel exit
// path. A DELETE on the state route terminates the interaction with
// access_denied, which the OP owes the RP through the response mode the
// request selected — the same form-post transport the success path
// uses, and the same one a fetch() cannot render.
func TestSPA_FormPost_CancelDeliversErrorEnvelope(t *testing.T) {
	t.Parallel()

	h := newSPAFormPostHarness(t)
	stateURL, _, csrfToken := h.beginInteraction(t, "form_post")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, stateURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest DELETE: %v", err)
	}
	req.Header.Set("Origin", h.tk.Issuer)
	req.Header.Set("X-CSRF-Token", csrfToken)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("DELETE state: %v", err)
	}
	defer resp.Body.Close()

	action, fields := formPostEnvelopeFields(t, decodeSPATerminal(t, resp))
	if action != h.rp.callbackURL() {
		t.Errorf("form action=%q, want the registered redirect_uri %q", action, h.rp.callbackURL())
	}
	if got := fields.Get("error"); got != "access_denied" {
		t.Errorf("error=%q, want access_denied", got)
	}
	if got := fields.Get("state"); got != "state-abc" {
		t.Errorf("state=%q, want state-abc", got)
	}
	if fields.Get("code") != "" {
		t.Errorf("cancelled interaction emitted an authorization code: %v", fields)
	}
}

// verifySPAJARMResponse validates the JARM JWT against the OP's active
// signing key and returns its claims.
func verifySPAJARMResponse(t *testing.T, tk *testkit.Provider, raw string) map[string]any {
	t.Helper()

	parsed, err := jwt.ParseSigned(raw, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(tk.SigningKey.Signer.Public(), &claims); err != nil {
		t.Fatalf("Claims (signature verify): %v", err)
	}
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v, want %s", got, tk.Issuer)
	}
	return claims
}
