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
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// chooserTemplateMarker is a unique element the embedder chooser
// template emits. Asserting its presence in the GET /interaction
// body proves the [interaction.TemplateOverlayDriver] dispatched into
// the embedder's [op.WithChooserUI] template instead of falling back
// to the HTMLDriver default surface. HTML comments cannot be used
// because Go's [html/template] strips them during parsing.
const chooserTemplateMarker = `<meta name="overlay-fixture" content="chooser">`

// chooserEmbedderTemplate is the inline embedder chooser template the
// HTML chooser end-to-end test installs. Each account row is a
// standalone form so the user picks an account by submitting; the
// "Add another account" link is rendered after the loop. The form
// fields exactly mirror the contract the chooser interaction's
// Continue method expects:
//   - state_ref (orchestrator state binding)
//   - csrf_token (echoed from the per-step CSRF cookie)
//   - session_id (the chosen account's opaque SessionID)
const chooserEmbedderTemplate = `<!doctype html><html><head>` + chooserTemplateMarker + `</head><body>
<h1>Choose an account</h1>
{{range .Accounts}}<form method="{{$.SubmitMethod}}" action="{{$.SubmitAction}}">
<input type="hidden" name="state_ref" value="{{$.StateRef}}">
<input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
<input type="hidden" name="{{$.SessionIDField}}" value="{{.SessionID}}">
<button type="submit">Continue as {{if .DisplayName}}{{.DisplayName}}{{else}}{{.Subject}}{{end}}</button>
</form>{{end}}
<a href="{{.AddAccountURL}}">Sign in to a different account</a>
</body></html>`

// sessionIDHiddenInput matches a chooser-row hidden input that carries
// the session_id value. The test parses the rendered chooser body to
// pick the row whose subject matches the target account; the chooser
// template emits one of these per [interaction.ChooserAccount].
var sessionIDHiddenInput = regexp.MustCompile(`name="session_id" value="([^"]+)"`)

// TestEndToEnd_ChooserTemplate_RendersAndCompletes drives the
// authorize → chooser template render → POST session_id → consent →
// token flow against an [op.New] provider configured with
// [op.WithChooserUI]. Two seeded sessions share a chooser group so the
// chooser interaction has rows to render; the test picks the second
// account, walks the consent screen, and exchanges the resulting code
// to confirm the chooser-template-driven path emits a working grant.
//
// This complements the JSON chooser end-to-end test in
// [TestEndToEnd_ChooserSelectAccount_HappyPath]; the two coexist to
// keep both rendering paths covered.
func TestEndToEnd_ChooserTemplate_RendersAndCompletes(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	cookieKey := []byte(chooserCookieKey)
	tmpl := template.Must(template.New("chooser").Parse(chooserEmbedderTemplate))
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithCookieKeys(cookieKey),
			op.WithInteractionDriver(interaction.HTMLDriver{}),
			op.WithChooserUI(op.ChooserUI{Template: tmpl}),
		),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-chooser-tmpl",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	mgr, _ := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	ctx := context.Background()
	sessA, err := mgr.Issue(ctx, sessions.Login{Subject: "user-A", AuthTime: clock.now})
	if err != nil {
		t.Fatalf("Issue user-A: %v", err)
	}
	sessB, err := mgr.AddAccount(ctx, sessA.ChooserGroupID, sessions.Login{
		Subject:  "user-B",
		AuthTime: clock.now,
	})
	if err != nil {
		t.Fatalf("AddAccount user-B: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	// Hop 1: /authorize?prompt=select_account with the seeded session
	// cookie attached.
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "select_account")
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	authResp, err := client.Do(authReq)
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

	// Hop 2: GET /interaction → chooser template body. The body MUST
	// contain the marker and one session_id hidden input per seeded
	// account, and MUST NOT contain the HTMLDriver fallback markup.
	stepResp, err := doGetWithCookies(ctx, client, interactionURL,
		interactionCookie,
		&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie},
	)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	if got := stepResp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("chooser prompt Content-Type = %q, want text/html prefix (overlay path)", got)
	}
	chooserBytes, err := io.ReadAll(stepResp.Body)
	if err != nil {
		t.Fatalf("read chooser body: %v", err)
	}
	chooserBody := string(chooserBytes)
	if !strings.Contains(chooserBody, chooserTemplateMarker) {
		t.Fatalf("chooser template marker missing — overlay did not fire.\n--- body ---\n%s",
			chooserBody)
	}
	// The HTMLDriver fallback chooser screen renders a literal
	// "Continue" submit button outside any per-row form; the embedder
	// template only emits "Continue as <Subject>". A bare
	// `<button type="submit">Continue</button>` is therefore a
	// reliable bypass detector.
	if strings.Contains(chooserBody, `<button type="submit">Continue</button>`) {
		t.Errorf("chooser body contains HTMLDriver fallback submit; overlay was bypassed:\n%s", chooserBody)
	}
	rows := sessionIDHiddenInput.FindAllStringSubmatch(chooserBody, -1)
	if len(rows) != 2 {
		t.Fatalf("session_id rows = %d, want 2 (one per seeded account):\n%s",
			len(rows), chooserBody)
	}
	rowSet := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		rowSet[r[1]] = struct{}{}
	}
	if _, ok := rowSet[sessA.SessionID]; !ok {
		t.Errorf("user-A SessionID %q not in rendered chooser rows: %v", sessA.SessionID, rowSet)
	}
	if _, ok := rowSet[sessB.SessionID]; !ok {
		t.Errorf("user-B SessionID %q not in rendered chooser rows: %v", sessB.SessionID, rowSet)
	}

	chooserStateRef := extractStateRef(t, chooserBody)
	chooserCSRF := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if chooserCSRF == nil {
		t.Fatal("csrf cookie missing on chooser prompt")
	}

	// Hop 3: POST the chooser submission picking user-B as form-encoded.
	chooserForm := url.Values{
		"state_ref":  {chooserStateRef},
		"csrf_token": {chooserCSRF.Value},
		"session_id": {sessB.SessionID},
	}
	postResp, err := doFormPost(ctx, client, interactionURL, tk.Issuer, chooserForm,
		interactionCookie, chooserCSRF,
		&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie},
	)
	if err != nil {
		t.Fatalf("POST chooser: %v", err)
	}
	defer postResp.Body.Close()

	// The chooser pick advances the chain; user-B has no cached grant
	// for this client, so the next prompt is consent. Walk it inline
	// with form-encoded approval (HTMLDriver's default consent surface
	// renders the approved_scopes hidden field for us, since
	// WithConsentUI is intentionally NOT configured here — this test
	// pins the chooser overlay path; consent default falls through
	// the overlay's nil-template passthrough branch).
	if postResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(postResp.Body)
		t.Fatalf("consent prompt status=%d body=%s", postResp.StatusCode, string(dump))
	}
	consentBytes, err := io.ReadAll(postResp.Body)
	if err != nil {
		t.Fatalf("read consent body: %v", err)
	}
	consentBody := string(consentBytes)
	if strings.Contains(consentBody, chooserTemplateMarker) {
		t.Fatalf("chooser marker leaked into consent step body; overlay routing wrong:\n%s", consentBody)
	}
	consentStateRef := extractStateRef(t, consentBody)
	consentCSRF := findCookie(postResp.Cookies(), cookie.CSRFProfile.Name)
	if consentCSRF == nil {
		t.Fatal("csrf cookie missing on consent prompt")
	}
	approvedScopes := extractApprovedScopesValue(t, consentBody)
	if approvedScopes == "" {
		t.Fatalf("approved_scopes hidden input missing from consent body:\n%s", consentBody)
	}

	consentForm := url.Values{
		"state_ref":       {consentStateRef},
		"csrf_token":      {consentCSRF.Value},
		"approved_scopes": {approvedScopes},
	}
	finalResp, err := doFormPost(ctx, client, interactionURL, tk.Issuer, consentForm,
		interactionCookie, consentCSRF,
		&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie},
	)
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

	// Token exchange MUST mint an id_token whose sub is user-B —
	// confirms the chooser-template path bound the picked subject.
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
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatalf("id_token missing: %v", body)
	}
	idClaims := decodeIDTokenPayload(t, idt)
	if got, _ := idClaims["sub"].(string); got != "user-B" {
		t.Errorf("id_token sub = %q, want user-B (chooser-template-picked subject)", got)
	}
}
