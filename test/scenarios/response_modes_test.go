package scenarios_test

// Catalog: test/scenarios/catalog/response_modes.yaml (RMO-NNN)
// Spec:
//   - OAuth 2.0 Multiple Response Type Encoding Practices §2 (response_mode)
//   - OAuth 2.0 Form Post Response Mode (Final)
//   - OAuth 2.0 Web Message Response Mode (draft, deprecated)
//   - OIDC Core 1.0 §3.1.2 (response_mode default selection)
//   - RFC 9207 — Authorization Server Issuer Identification

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestScenario_RMO_001_FormPostSuccessRendersSelfSubmittingForm is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_001_FormPostSuccessRendersSelfSubmittingForm(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-001 (see catalog out_of_scope_reason)")
}

// formPostHostileRedirectURI is a registered redirect_uri carrying an
// HTML/JS breakout payload. Nothing upstream of the form writer strips
// it: the value parses as an absolute https URI with no fragment, so it
// passes redirect_uri validation and reaches the point where the OP
// interpolates it into the form's action attribute. The escaping at
// that point is the actual defence, which is what RMO-002 pins.
const formPostHostileRedirectURI = `https://rp.testkit.invalid/cb"><script>alert(1)</script><x="`

// formPostHostileState is the same class of payload on a parameter the
// RP fully controls and the OP echoes verbatim into a hidden input.
const formPostHostileState = `"><script>alert(2)</script>`

// formPostBreakoutSequences are the raw byte sequences from the two
// payloads that would end the quoted attribute and open an executable
// element. Their absence — not the absence of the payloads' inert
// substrings, since alert(1) survives escaping unchanged — is what
// distinguishes escaped output from injected output. A bare `">` is
// deliberately not on the list: it is the legitimate end of every
// attribute the emitter writes.
var formPostBreakoutSequences = []string{`"><script>`, `</script><x="`}

// TestScenario_RMO_002_FormPostHTMLEscapesRedirectURI drives a
// successful response_mode=form_post authorization to a client whose
// registered redirect_uri carries an HTML/JS breakout payload, and
// verifies the OP renders every interpolated value as escaped text.
//
// Two independent layers are asserted on the same response, because
// either one alone is a single point of failure:
//
//  1. HTML escaping. The raw attribute-breakout sequences MUST NOT
//     appear anywhere in the body, and both the action attribute and
//     the hidden input values MUST carry the escaped rendering.
//  2. The Content-Security-Policy form-action directive, which the OP
//     reduces to the redirect_uri's scheme://host. The payload lives
//     in the path, so the directive names the bare origin and a
//     breakout that somehow survived layer 1 still could not post
//     anywhere else.
//
// Spec: OAuth 2.0 Form Post Response Mode §2; OWASP output encoding
// (CWE-79).
func TestScenario_RMO_002_FormPostHTMLEscapesRedirectURI(t *testing.T) {
	t.Parallel()

	const clientID = "rp-rmo-002"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rmo-002-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{formPostHostileRedirectURI},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := scenariokit.RunFormPostFlow(t, tk, http.MethodGet, scenariokit.DefaultSubject,
		scenariokit.AuthorizeParams{
			ClientID:    rp.ID,
			RedirectURI: formPostHostileRedirectURI,
			State:       formPostHostileState,
			PKCE:        scenariokit.NewPKCEPair(""),
			Extra:       url.Values{"response_mode": {"form_post"}},
		})

	if form.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", form.StatusCode, form.Body)
	}
	if got := form.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type=%q want text/html prefix", got)
	}

	// Layer 1a: neither payload survives verbatim, and no raw breakout
	// sequence appears anywhere in the body.
	if strings.Contains(form.Body, formPostHostileRedirectURI) {
		t.Errorf("redirect_uri payload rendered verbatim in body: %s", form.Body)
	}
	if strings.Contains(form.Body, formPostHostileState) {
		t.Errorf("state payload rendered verbatim in body: %s", form.Body)
	}
	for _, seq := range formPostBreakoutSequences {
		if strings.Contains(form.Body, seq) {
			t.Errorf("unescaped breakout sequence %q present in body: %s", seq, form.Body)
		}
	}

	// Layer 1b: the action attribute carries the escaped redirect_uri.
	wantAction := html.EscapeString(formPostHostileRedirectURI)
	if got := form.FormAction(t); got != wantAction {
		t.Errorf("form action=%q want %q", got, wantAction)
	}

	// Layer 1c: the same escaping applies to hidden input values. The
	// state parameter is RP-controlled and echoed verbatim, so it is the
	// value-side counterpart of the action-side payload.
	wantState := html.EscapeString(formPostHostileState)
	if !strings.Contains(form.Body, `name="state" value="`+wantState+`"`) {
		t.Errorf("state hidden input is not escaped as %q: %s", wantState, form.Body)
	}
	inputs := form.Inputs(t)
	if got := inputs.Get("state"); got != formPostHostileState {
		t.Errorf("decoded state=%q want %q", got, formPostHostileState)
	}
	if inputs.Get("code") == "" {
		t.Errorf("successful form_post delivery is missing the code input: %s", form.Body)
	}

	// Layer 2: the CSP reduces form-action to the redirect_uri's origin,
	// dropping the payload that lives in the path.
	csp := form.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action https://rp.testkit.invalid;") {
		t.Errorf("Content-Security-Policy=%q want form-action reduced to https://rp.testkit.invalid", csp)
	}
	for _, seq := range formPostBreakoutSequences {
		if strings.Contains(csp, seq) {
			t.Errorf("breakout sequence %q leaked into Content-Security-Policy: %s", seq, csp)
		}
	}
}

// TestScenario_RMO_003_FormPostErrorPathRendersForm verifies that an
// authorization error is delivered through the selected response_mode
// rather than as a bare HTTP failure: a prompt=none request against an
// unauthenticated session under response_mode=form_post returns 200 OK
// with the auto-submitting form, carrying error, error_description and
// the echoed state as hidden inputs.
//
// The 200 is the point of the row. The HTTP status describes the
// delivery of the authorization response, not the response itself; an
// RP that reads the status to decide whether the authorization
// succeeded is reading the wrong layer, and an OP that answers 4xx here
// strands the user on the OP's origin instead of returning them to the
// RP.
//
// Spec: OAuth 2.0 Form Post Response Mode §2; OIDC Core 1.0 §3.1.2.6
// (prompt=none error codes).
func TestScenario_RMO_003_FormPostErrorPathRendersForm(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rmo-003"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rmo-003-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	// prompt=none with no session cookie: the OP cannot interact, so the
	// authorization terminates at /authorize with login_required.
	form := scenariokit.RunFormPostFlow(t, tk, http.MethodGet, scenariokit.DefaultSubject,
		scenariokit.AuthorizeParams{
			ClientID:    rp.ID,
			RedirectURI: callback,
			PKCE:        scenariokit.NewPKCEPair(""),
			Extra: url.Values{
				"response_mode": {"form_post"},
				"prompt":        {"none"},
			},
		})

	if form.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (form_post delivers the error, it is not an HTTP failure) body=%s",
			form.StatusCode, form.Body)
	}
	if got := form.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type=%q want text/html prefix", got)
	}
	if got := form.FormAction(t); got != callback {
		t.Errorf("form action=%q want %q", got, callback)
	}

	inputs := form.Inputs(t)
	if got := inputs.Get("error"); got != "login_required" {
		t.Errorf("error=%q want login_required", got)
	}
	if got := inputs.Get("error_description"); got != "user authentication is required" {
		t.Errorf("error_description=%q want %q", got, "user authentication is required")
	}
	if got := inputs.Get("state"); got != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", got, scenariokit.DefaultState)
	}
	if got := inputs.Get("iss"); got != tk.Issuer {
		t.Errorf("iss=%q want %q", got, tk.Issuer)
	}
	if got := inputs.Get("code"); got != "" {
		t.Errorf("error delivery must not carry a code input, got %q", got)
	}
	// The error rides in the body, never in a URL — that is the whole
	// point of the mode, and a regression that fell back to a redirect
	// would put login_required into browser history and proxy logs.
	if loc := form.Header.Get("Location"); loc != "" {
		t.Errorf("form_post error must not also emit a Location header, got %q", loc)
	}
}

// TestScenario_RMO_004_FormPostGetAndPostBehaveIdentically issues the
// same authorization twice under response_mode=form_post — once as a
// GET query string, once as an application/x-www-form-urlencoded POST
// body — and verifies the delivered forms agree.
//
// RFC 6749 §3.1 requires the authorization endpoint to support both
// verbs, and OIDC Core §3.1.2.1 makes the parameter set identical
// across them. A divergence would mean one of the two paths takes a
// different code route through the response emitter, which is exactly
// where a transport-specific defect hides.
//
// Spec: OAuth 2.0 Form Post Response Mode §2; RFC 6749 §3.1.
func TestScenario_RMO_004_FormPostGetAndPostBehaveIdentically(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rmo-004"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rmo-004-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	params := scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        scenariokit.NewPKCEPair(""),
		Extra:       url.Values{"response_mode": {"form_post"}},
	}
	viaGET := scenariokit.RunFormPostFlow(t, tk, http.MethodGet, scenariokit.DefaultSubject, params)
	viaPOST := scenariokit.RunFormPostFlow(t, tk, http.MethodPost, scenariokit.DefaultSubject, params)

	if viaGET.StatusCode != http.StatusOK || viaPOST.StatusCode != http.StatusOK {
		t.Fatalf("status GET=%d POST=%d want 200/200\nGET body=%s\nPOST body=%s",
			viaGET.StatusCode, viaPOST.StatusCode, viaGET.Body, viaPOST.Body)
	}
	if got, want := viaPOST.FormAction(t), viaGET.FormAction(t); got != want {
		t.Errorf("form action POST=%q GET=%q", got, want)
	}
	for _, header := range []string{"Content-Type", "Cache-Control", "Content-Security-Policy", "Referrer-Policy"} {
		if got, want := viaPOST.Header.Get(header), viaGET.Header.Get(header); got != want {
			t.Errorf("%s POST=%q GET=%q", header, got, want)
		}
	}

	getInputs := viaGET.Inputs(t)
	postInputs := viaPOST.Inputs(t)
	// The authorization code is the one field that legitimately differs:
	// each run is a distinct authorization and mints its own single-use
	// code. Assert both are non-empty and distinct, then compare the
	// remaining fields verbatim.
	getCode, postCode := getInputs.Get("code"), postInputs.Get("code")
	if getCode == "" || postCode == "" {
		t.Fatalf("code missing: GET=%q POST=%q", getCode, postCode)
	}
	if getCode == postCode {
		t.Errorf("two authorizations reused the same code %q", getCode)
	}
	getInputs.Del("code")
	postInputs.Del("code")
	if len(getInputs) != len(postInputs) {
		t.Fatalf("input sets differ: GET=%v POST=%v", getInputs, postInputs)
	}
	for name, want := range getInputs {
		if got := postInputs[name]; len(got) != 1 || len(want) != 1 || got[0] != want[0] {
			t.Errorf("input %q POST=%v GET=%v", name, got, want)
		}
	}

	// Byte-for-byte body comparison with the two codes substituted out,
	// which catches a divergence in anything the parsed view above does
	// not cover (element order, the noscript fallback, the auto-submit
	// script).
	const codePlaceholder = "{code}"
	if got, want := strings.ReplaceAll(viaPOST.Body, postCode, codePlaceholder),
		strings.ReplaceAll(viaGET.Body, getCode, codePlaceholder); got != want {
		t.Errorf("form bodies differ once the per-authorization code is normalised:\nGET =%s\nPOST=%s", want, got)
	}
}

// TestScenario_RMO_010_WebMessageSuccessRendersHTMLEnvelope is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_010_WebMessageSuccessRendersHTMLEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-010 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_011_WebMessageIncludesStandardFields is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_011_WebMessageIncludesStandardFields(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-011 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_012_WebMessageRelayModeRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_012_WebMessageRelayModeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-012 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_013_WebMessageStripsFramingHeaders is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_013_WebMessageStripsFramingHeaders(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-013 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_014_WebMessageErrorRendersEnvelope is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_014_WebMessageErrorRendersEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-014 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_020_DiscoveryAdvertisesWebMessage is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_020_DiscoveryAdvertisesWebMessage(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-020 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_030_RegisterResponseModeHookExposed is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_030_RegisterResponseModeHookExposed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-030 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_031_CustomModeInvokedForSuccess is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_031_CustomModeInvokedForSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-031 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_032_CustomModeInvokedForError is OOS — see catalog out_of_scope_reason.
func TestScenario_RMO_032_CustomModeInvokedForError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RMO-032 (see catalog out_of_scope_reason)")
}

// TestScenario_RMO_033_UnknownResponseModeRejected verifies that an
// /authorize request whose response_mode is neither the default nor any
// of the response_modes_supported values is rejected with a redirect
// carrying error=unsupported_response_mode and the OP's wire-form
// description "response_mode is not supported".
//
// The redirect target is the registered redirect_uri (the OP only emits
// a redirect-form error after redirect_uri has been validated; that
// gate already passes here because client_id and redirect_uri are
// well-formed).
//
// Spec: OAuth 2.0 Multiple Response Type Encoding Practices §2
// (response_mode); RFC 6749 §4.1.2.1 (error response shape).
func TestScenario_RMO_033_UnknownResponseModeRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rmo-033"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rmo-033-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	params := scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
		Extra:       url.Values{"response_mode": {"unknown-mode"}},
	}
	authorizeURL := tk.Server.URL + "/oidc/auth?" + params.Values().Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	want, err := url.Parse(callback)
	if err != nil {
		t.Fatalf("parse callback: %v", err)
	}
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
		t.Fatalf("redirect=%s does not target redirect_uri %s", loc.String(), callback)
	}
	q := loc.Query()
	if got := q.Get("error"); got != "unsupported_response_mode" {
		t.Errorf("error=%q want unsupported_response_mode", got)
	}
	if got := q.Get("error_description"); got != "response_mode is not supported" {
		t.Errorf("error_description=%q want %q", got, "response_mode is not supported")
	}
	if got := q.Get("state"); got != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", got, scenariokit.DefaultState)
	}
}

// TestScenario_RMO_040_DefaultResponseModeSelection verifies the
// code-leg of OIDC Core §3.1.2 default response_mode selection: a
// successful response_type=code authorization with no response_mode in
// the request encodes the response in the redirect's query string, not
// the fragment.
//
// v1.0's discovery advertises only response_types_supported=["code"];
// the implicit half of the spec rule (id_token / token defaulting to
// fragment) is recorded in the catalog row's behaviour block as not
// reachable at the wire because the OP rejects those response_type
// values upstream.
//
// Spec: OIDC Core 1.0 §3.1.2 (response_mode default).
func TestScenario_RMO_040_DefaultResponseModeSelection(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rmo-040"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rmo-040-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
		// Intentionally omit response_mode so the OP must apply the
		// default-selection rule from OIDC Core §3.1.2.
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatal("authorize callback missing code")
	}
	if flow.Location == nil {
		t.Fatal("captured callback Location is nil")
	}
	if flow.Location.RawFragment != "" || flow.Location.Fragment != "" {
		t.Errorf("response_type=code with no response_mode must default to query encoding; got fragment=%q in %s",
			flow.Location.Fragment, flow.Location.String())
	}
	// Spot-check that the canonical fields ride in the query string.
	q := flow.Location.Query()
	if got := q.Get("code"); got == "" {
		t.Error("code query parameter missing from default-mode redirect")
	}
	if got := q.Get("state"); got != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", got, scenariokit.DefaultState)
	}
}
