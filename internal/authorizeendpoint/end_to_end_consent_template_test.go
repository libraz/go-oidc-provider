package authorizeendpoint_test

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// consentTemplateMarker is a unique element the embedder template
// emits. Asserting its presence in the GET /interaction body proves
// the [interaction.TemplateOverlayDriver] dispatched into the
// embedder's [op.WithConsentUI] template; the marker also doubles as
// a negative anchor against the HTMLDriver fallback (which never
// emits anything matching this attribute set). HTML comments cannot
// be used because Go's [html/template] strips them during parsing.
const consentTemplateMarker = `<meta name="overlay-fixture" content="consent">`

// consentEmbedderTemplate is the inline embedder consent template the
// end-to-end harness installs through [op.WithConsentUI]. The body is
// minimal but exercises every field the orchestrator surfaces in
// [interaction.ConsentTemplateData] and round-trips a form submission
// the built-in consent.Interaction.Continue accepts:
//   - state_ref hidden input (required by the orchestrator's CSRF /
//     state binding).
//   - csrf_token hidden input (HTMLDriver / overlay path; the
//     middleware accepts the header form too, but a SSR template needs
//     the field).
//   - approved_scopes pre-populated with the space-joined required +
//     optional scope names so a single submit approves the full set.
const consentEmbedderTemplate = `<!doctype html><html><head>` + consentTemplateMarker + `</head><body>
<h1>{{.Client.Name}} requests access</h1>
<form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">
<input type="hidden" name="state_ref" value="{{.StateRef}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="{{.ApprovedScopesField}}" value="{{range $i, $s := .Scopes}}{{if $i}} {{end}}{{$s.Name}}{{end}}">
<button type="submit">Approve</button>
</form>
</body></html>`

// stateRefHiddenInput extracts the state_ref hidden input value from
// an HTML body. The pattern matches the canonical form field shape the
// embedder template emits (and the HTMLDriver fallback emits too) so
// the helper survives a future template rewrite as long as the field
// name + value attribute order is preserved.
var stateRefHiddenInput = regexp.MustCompile(`name="state_ref" value="([^"]+)"`)

// extractStateRef pulls the orchestrator-issued state_ref token out of
// an HTML body. Failure to match fails the test; the orchestrator
// always emits exactly one state_ref hidden input per prompt.
func extractStateRef(t *testing.T, body string) string {
	t.Helper()
	m := stateRefHiddenInput.FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("state_ref hidden input not found in body:\n%s", body)
	}
	return m[1]
}

// TestEndToEnd_ConsentTemplate_RendersAndCompletes drives the
// authorize → consent template render → POST approved_scopes → token
// flow against an [op.New] provider configured with
// [op.WithConsentUI]. The test pins the public seam landed in plan
// 016 §3.2: the [interaction.TemplateOverlayDriver] intercepts the
// "consent.scope" prompt and replaces the HTMLDriver default surface
// with the embedder template, while the form-encoded POST round-trips
// through the consent.Interaction.Continue contract unchanged.
func TestEndToEnd_ConsentTemplate_RendersAndCompletes(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	tmpl := template.Must(template.New("consent").Parse(consentEmbedderTemplate))
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithInteractionDriver(interaction.HTMLDriver{}),
			op.WithConsentUI(op.ConsentUI{Template: tmpl}),
		),
	)

	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-consent-tmpl",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)
	ctx := context.Background()

	// Hop 1: /authorize → 302 to /interaction/{uid}.
	authorizeURL := tk.Server.URL + "/oidc/auth?" + e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0]).Encode()
	authResp, err := newGet(authorizeURL).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	interactionURL := tk.Server.URL + location.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on authorize 302")
	}

	// Hop 2: GET /interaction/{uid} for the first authn step (the
	// SubjectAuthenticator emits an HTML form via the HTMLDriver
	// because consent is the only prompt the overlay intercepts).
	stepResp, err := doGetWithCookies(ctx, client, interactionURL, interactionCookie)
	if err != nil {
		t.Fatalf("GET interaction (auth step): %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	authBody, err := io.ReadAll(stepResp.Body)
	if err != nil {
		t.Fatalf("read auth body: %v", err)
	}
	if strings.Contains(string(authBody), consentTemplateMarker) {
		t.Fatalf("consent template marker leaked into auth step body:\n%s", string(authBody))
	}
	authStateRef := extractStateRef(t, string(authBody))
	authCSRF := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if authCSRF == nil {
		t.Fatal("csrf cookie missing on auth step")
	}

	// Hop 3: POST the SubjectAuthenticator submission as form-encoded
	// (HTMLDriver consumes application/x-www-form-urlencoded). A
	// successful submission advances the chain to the consent prompt,
	// at which point the overlay fires.
	authForm := url.Values{
		"state_ref":  {authStateRef},
		"csrf_token": {authCSRF.Value},
		"subject":    {"user-template-1"},
	}
	consentResp, err := doFormPost(ctx, client, interactionURL, tk.Issuer, authForm,
		interactionCookie, authCSRF)
	if err != nil {
		t.Fatalf("POST auth step: %v", err)
	}
	defer consentResp.Body.Close()
	if consentResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(consentResp.Body)
		t.Fatalf("consent prompt status=%d body=%s", consentResp.StatusCode, string(dump))
	}
	if got := consentResp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("consent prompt Content-Type = %q, want text/html prefix (overlay path)", got)
	}
	consentBody, err := io.ReadAll(consentResp.Body)
	if err != nil {
		t.Fatalf("read consent body: %v", err)
	}
	consentText := string(consentBody)
	if !strings.Contains(consentText, consentTemplateMarker) {
		t.Fatalf("consent template marker missing — overlay did not fire.\n--- body ---\n%s",
			consentText)
	}
	// The HTMLDriver fallback consent screen renders the literal
	// "Continue" submit button and the "(required)" suffix on required
	// scopes. Neither appears in the embedder template, so detecting
	// either signals the overlay was bypassed.
	if strings.Contains(consentText, `<button type="submit">Continue</button>`) {
		t.Errorf("consent body contains HTMLDriver fallback submit; overlay was bypassed:\n%s", consentText)
	}
	if strings.Contains(consentText, "(required)") {
		t.Errorf("consent body contains HTMLDriver fallback (required) marker; overlay was bypassed:\n%s", consentText)
	}
	consentStateRef := extractStateRef(t, consentText)
	consentCSRF := findCookie(consentResp.Cookies(), cookie.CSRFProfile.Name)
	if consentCSRF == nil {
		t.Fatal("csrf cookie missing on consent prompt")
	}
	approvedScopes := extractApprovedScopesValue(t, consentText)
	if approvedScopes == "" {
		t.Fatalf("approved_scopes hidden input missing from consent body:\n%s", consentText)
	}

	// Hop 4: POST the consent submission as form-encoded. The overlay
	// passes the parse step through to HTMLDriver verbatim, so the
	// orchestrator sees the same FormSubmission shape it would for a
	// fallback consent screen.
	consentForm := url.Values{
		"state_ref":       {consentStateRef},
		"csrf_token":      {consentCSRF.Value},
		"approved_scopes": {approvedScopes},
	}
	finalResp, err := doFormPost(ctx, client, interactionURL, tk.Issuer, consentForm,
		interactionCookie, consentCSRF)
	if err != nil {
		t.Fatalf("POST consent: %v", err)
	}
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("final status=%d body=%s", finalResp.StatusCode, string(dump))
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after consent: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}

	// Hop 5: exchange the code for tokens. The token response confirms
	// the consent-template-driven path emits a working grant.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(rp.ID, secret)
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("/token status=%d body=%s", tokenResp.StatusCode, string(dump))
	}
	body := decodeMap(t, tokenResp)
	if at, _ := body["access_token"].(string); at == "" {
		t.Errorf("access_token missing: %v", body)
	}
	if idt, _ := body["id_token"].(string); idt == "" {
		t.Errorf("id_token missing: %v", body)
	}
}

// approvedScopesHiddenInput matches the hidden field the embedder
// template emits to pre-populate the approved scopes. The pattern
// captures the value attribute verbatim so the test echoes the
// orchestrator-rendered string back unchanged.
var approvedScopesHiddenInput = regexp.MustCompile(`name="approved_scopes" value="([^"]*)"`)

func extractApprovedScopesValue(t *testing.T, body string) string {
	t.Helper()
	m := approvedScopesHiddenInput.FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("approved_scopes hidden input not found in body:\n%s", body)
	}
	return m[1]
}

// doGetWithCookies issues a GET against url with the supplied cookies
// attached. The helper exists so the consent / chooser template
// end-to-end tests do not duplicate the AddCookie boilerplate per hop.
func doGetWithCookies(ctx context.Context, client *http.Client, url string, cookies ...*http.Cookie) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	return client.Do(req)
}

// doFormPost POSTs form as application/x-www-form-urlencoded. The
// HTMLDriver expects this content-type; the orchestrator's CSRF
// middleware also reads the csrf_token form field on the same path.
// extraCookies are attached after the canonical Origin header so the
// CSRF origin allowlist accepts the request.
func doFormPost(
	ctx context.Context,
	client *http.Client,
	url, origin string,
	form url.Values,
	cookies ...*http.Cookie,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	if csrf := form.Get("csrf_token"); csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	return client.Do(req)
}
