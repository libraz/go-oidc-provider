package scenariokit

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

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// DefaultPKCEVerifier is the canonical RFC 7636 §4.1 verifier
// scenariokit hands out when a test does not override it. The value is
// 64 chars from the unreserved alphabet (ALPHA / DIGIT / "-" / "." /
// "_" / "~"), comfortably inside the 43..128 spec bound. A fixed
// constant is preferred over per-call randomness so tests stay
// deterministic and keep the package free of crypto/rand (which is
// allow-listed and not part of scenariokit's exemption set).
const DefaultPKCEVerifier = "scenariokit-default-verifier-scenariokit-default-verifier-1234x"

// DefaultScope is the canonical OIDC scope set scenariokit attaches to
// /authorize requests when the caller leaves [AuthorizeParams.Scope]
// empty. The set matches the testkit's default client fixture so the
// happy-path flow needs no additional registration tweaks.
const DefaultScope = "openid profile email"

// DefaultSubject is the subject [SubjectAuthenticator] binds when
// scenariokit drives the interaction step without a caller-supplied
// override. Tests that assert on the "sub" claim can rely on this
// constant.
const DefaultSubject = "user-1"

// DefaultState is the canonical "state" parameter scenariokit emits.
// A constant value is fine in tests because each test owns its
// /authorize / /token round-trip end-to-end; cross-test collisions
// are not possible.
const DefaultState = "scenariokit-state"

// DefaultNonce is the canonical "nonce" parameter scenariokit emits.
// Same rationale as [DefaultState].
const DefaultNonce = "scenariokit-nonce"

// PKCEPair bundles a verifier with its SHA-256 / base64url challenge.
// The Method is always "S256" — RFC 7636 §4.2 keeps "plain" only as a
// legacy mode and the project rejects it project-wide.
type PKCEPair struct {
	Verifier  string
	Challenge string
	Method    string
}

// NewPKCEPair returns a [PKCEPair] derived from verifier. An empty
// value falls back to [DefaultPKCEVerifier].
func NewPKCEPair(verifier string) PKCEPair {
	if verifier == "" {
		verifier = DefaultPKCEVerifier
	}
	sum := sha256.Sum256([]byte(verifier))
	return PKCEPair{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		Method:    "S256",
	}
}

// AuthorizeParams captures the canonical /authorize query parameters
// for the code flow. Optional fields default to the testkit-friendly
// values described in each field's docstring.
type AuthorizeParams struct {
	// ClientID is the registered client_id. Required.
	ClientID string

	// RedirectURI is the redirect_uri the OP must echo on the
	// callback. Required; must match one of the client's registered
	// URIs.
	RedirectURI string

	// Scope is the space-delimited scope request. An empty value
	// falls back to [DefaultScope].
	Scope string

	// State is the RFC 6749 §4.1.1 "state" parameter. An empty value
	// falls back to [DefaultState].
	State string

	// Nonce is the OIDC Core 1.0 §3.1.2.1 "nonce" parameter. An empty
	// value falls back to [DefaultNonce].
	Nonce string

	// ResponseType is the response_type. An empty value falls back
	// to "code"; tests for hybrid flows pass an explicit override.
	ResponseType string

	// PKCE supplies the verifier / challenge pair. A zero-value
	// PKCEPair triggers [NewPKCEPair] with [DefaultPKCEVerifier].
	PKCE PKCEPair

	// Extra carries additional /authorize parameters the caller
	// wants stamped onto the request (for example "claims" or
	// "ui_locales"). Values are merged into the encoded query
	// after the canonical parameters; conflicting keys overwrite.
	Extra url.Values
}

// Values returns the canonical url.Values representation of params,
// applying defaults for empty fields and merging [AuthorizeParams.Extra]
// last.
func (p AuthorizeParams) Values() url.Values {
	pkce := p.PKCE
	if pkce.Verifier == "" || pkce.Challenge == "" {
		pkce = NewPKCEPair("")
	}
	v := url.Values{
		"client_id":             {p.ClientID},
		"response_type":         {firstNonEmpty(p.ResponseType, "code")},
		"redirect_uri":          {p.RedirectURI},
		"scope":                 {firstNonEmpty(p.Scope, DefaultScope)},
		"state":                 {firstNonEmpty(p.State, DefaultState)},
		"nonce":                 {firstNonEmpty(p.Nonce, DefaultNonce)},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
	for k, vs := range p.Extra {
		v[k] = append([]string(nil), vs...)
	}
	return v
}

// CodeFlowResult captures the redirect-URL parameters the OP delivers
// to the RP at the end of the authorize round-trip.
type CodeFlowResult struct {
	// Code is the "code" query parameter. Empty on the error path;
	// callers that test error responses inspect Error / ErrorDesc.
	Code string

	// State is the "state" parameter the OP echoed back. The caller
	// asserts equality against [AuthorizeParams.State].
	State string

	// Iss is the RFC 9207 "iss" parameter when the OP advertised
	// issuer-identification (the project default). Empty when the
	// OP did not stamp it.
	Iss string

	// Error is the OAuth wire error code on the error path.
	Error string

	// ErrorDesc is the optional "error_description" parameter on
	// the error path.
	ErrorDesc string

	// Location is the full redirect URL captured at the callback
	// step, preserved so callers can assert on the raw shape (e.g.
	// fragment vs query encoding for response_mode).
	Location *url.URL
}

// RunCodeFlow drives /authorize → /interaction (subject) →
// /interaction (consent if prompted) → callback against the OP backed
// by p, returning the parsed callback URL parameters. The function
// installs a cookie jar so the OP's session / CSRF cookies thread
// across hops.
//
// subject is the value submitted to the testkit's
// [testkit.SubjectAuthenticator]; an empty value falls back to
// [DefaultSubject]. The function fails the test fast on transport
// errors or unexpected hop statuses; non-final-status errors that the
// OP returned in-band (for example a 400 envelope on /interaction)
// surface as a test failure rather than a [CodeFlowResult] entry.
//
// Tests that need to inspect a specific intermediate step (e.g. to
// assert on a consent prompt's payload before approving) should
// drive the steps individually using net/http; this helper is the
// "happy-path one-shot" entry.
func RunCodeFlow(tb testing.TB, p *testkit.Provider, subject string, params AuthorizeParams) CodeFlowResult {
	tb.Helper()
	if subject == "" {
		subject = DefaultSubject
	}
	client := mustClient(tb, p)

	// Step 1: GET /authorize → 302 to /interaction/{uid}
	authorizeURL := p.Server.URL + "/oidc/auth?" + params.Values().Encode()
	authResp := mustGet(tb, client, authorizeURL)
	defer func() { _ = authResp.Body.Close() }()
	if authResp.StatusCode != http.StatusFound {
		tb.Fatalf("scenariokit: /authorize status=%d, want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		tb.Fatalf("scenariokit: /authorize Location: %v", err)
	}
	if redirected, ok := captureCallback(tb, params.RedirectURI, location); ok {
		// Authorize bounced straight to the RP — typically an error
		// response. Pass it through so the caller can inspect.
		return redirected
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		tb.Fatalf("scenariokit: /authorize Location=%s, want /oidc/interaction/...", location.String())
	}
	interactionURL := p.Server.URL + location.Path

	// Steps 2 and 3: run the interaction hops to their terminal response.
	finalResp := completeInteraction(tb, client, interactionURL, p.Issuer, subject)
	defer func() { _ = finalResp.Body.Close() }()
	if finalResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(finalResp.Body)
		tb.Fatalf("scenariokit: final interaction status=%d body=%s", finalResp.StatusCode, string(body))
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		tb.Fatalf("scenariokit: final Location: %v", err)
	}
	if result, ok := captureCallback(tb, params.RedirectURI, rpRedirect); ok {
		return result
	}
	tb.Fatalf("scenariokit: callback %s does not match redirect_uri %s", rpRedirect.String(), params.RedirectURI)
	return CodeFlowResult{}
}

// completeInteraction drives the interaction hops the OP inserts
// between /authorize and the terminal authorization response: GET the
// prompt (which mints the CSRF cookie and the state_ref), POST the
// subject submission, then approve consent when the OP asks for it.
//
// The returned response is the terminal one — a 302 back to the RP for
// the redirect response modes, a 200 HTML body under form_post — and
// the caller owns closing its Body.
func completeInteraction(tb testing.TB, client *http.Client, interactionURL, origin, subject string) *http.Response {
	tb.Helper()
	stepResp := mustGet(tb, client, interactionURL)
	defer func() { _ = stepResp.Body.Close() }()
	if stepResp.StatusCode != http.StatusOK {
		tb.Fatalf("scenariokit: GET %s status=%d", interactionURL, stepResp.StatusCode)
	}
	step := decodeJSON(tb, stepResp)
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		tb.Fatal("scenariokit: state_ref missing from interaction prompt")
	}
	csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if csrfCookie == nil {
		tb.Fatal("scenariokit: __Host-oidc_csrf cookie missing on interaction prompt")
	}

	// The OP's testkit SubjectAuthenticator binds whatever value lands
	// in the "subject" form field.
	postResp := postInteraction(tb, client, interactionURL, origin, csrfCookie, stateRef,
		map[string]string{testkit.SubjectFieldName: subject})
	return completeConsentIfPrompted(tb, client, interactionURL, origin, csrfCookie, postResp)
}

// captureCallback returns a populated [CodeFlowResult] when location
// targets redirectURI; otherwise it returns ok=false so the caller
// continues the round-trip. The split keeps [RunCodeFlow] readable
// even though /authorize and the final /interaction hop both produce
// the same kind of redirect.
func captureCallback(tb testing.TB, redirectURI string, location *url.URL) (CodeFlowResult, bool) {
	tb.Helper()
	want, err := url.Parse(redirectURI)
	if err != nil {
		tb.Fatalf("scenariokit: parse redirect_uri %q: %v", redirectURI, err)
	}
	if location.Scheme != want.Scheme || location.Host != want.Host || location.Path != want.Path {
		return CodeFlowResult{}, false
	}
	q := location.Query()
	return CodeFlowResult{
		Code:      q.Get("code"),
		State:     q.Get("state"),
		Iss:       q.Get("iss"),
		Error:     q.Get("error"),
		ErrorDesc: q.Get("error_description"),
		Location:  location,
	}, true
}

// ExchangeCodeRequest builds the /token POST body for the
// authorization_code grant. ClientSecret is consumed via HTTP Basic
// when both ClientID and ClientSecret are set; tests that exercise
// other client-auth methods (private_key_jwt, mtls) populate Extra
// with the appropriate parameters and leave ClientSecret empty.
type ExchangeCodeRequest struct {
	Code         string
	RedirectURI  string
	Verifier     string
	ClientID     string
	ClientSecret string
	Extra        url.Values
}

// TokenResponse captures the parsed /token JSON envelope. StatusCode
// is preserved so tests that intentionally drive an error path can
// assert on it.
type TokenResponse struct {
	StatusCode   int
	Raw          map[string]any
	AccessToken  string
	IDToken      string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string
}

// ExchangeCode POSTs req to /token and returns the parsed response.
// A non-2xx status does NOT fail the test — the caller asserts on
// StatusCode and Raw — so error-path scenarios use this helper to
// inspect the envelope shape. Transport errors and malformed JSON
// still fail the test.
func ExchangeCode(tb testing.TB, p *testkit.Provider, req ExchangeCodeRequest) TokenResponse {
	tb.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {req.Code},
		"redirect_uri":  {req.RedirectURI},
		"code_verifier": {req.Verifier},
	}
	for k, vs := range req.Extra {
		form[k] = append([]string(nil), vs...)
	}
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		tb.Fatalf("scenariokit: build /token request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if req.ClientID != "" && req.ClientSecret != "" {
		httpReq.SetBasicAuth(req.ClientID, req.ClientSecret)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		tb.Fatalf("scenariokit: POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("scenariokit: read /token body: %v", err)
	}
	out := TokenResponse{StatusCode: resp.StatusCode, Raw: map[string]any{}}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out.Raw); err != nil {
			tb.Fatalf("scenariokit: decode /token body %q: %v", string(body), err)
		}
	}
	out.AccessToken, _ = out.Raw["access_token"].(string)
	out.IDToken, _ = out.Raw["id_token"].(string)
	out.RefreshToken, _ = out.Raw["refresh_token"].(string)
	out.TokenType, _ = out.Raw["token_type"].(string)
	out.Scope, _ = out.Raw["scope"].(string)
	if expN, ok := out.Raw["expires_in"].(float64); ok {
		out.ExpiresIn = int(expN)
	}
	return out
}

// mustClient returns an [*http.Client] with a cookie jar, redirects
// disabled (so each hop can be inspected), and the testkit server's
// TLS root pool wired in.
func mustClient(tb testing.TB, p *testkit.Provider) *http.Client {
	tb.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		tb.Fatalf("scenariokit: cookiejar: %v", err)
	}
	return p.HTTPClient(jar)
}

// mustGet issues a GET against rawURL and fails the test on transport error.
func mustGet(tb testing.TB, client *http.Client, rawURL string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		tb.Fatalf("scenariokit: build GET %s: %v", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("scenariokit: GET %s: %v", rawURL, err)
	}
	return resp
}

// postInteraction submits a JSON {state_ref, values} envelope to the
// /interaction/{uid} endpoint. It threads the CSRF cookie / header
// pair the OP's CSRF middleware enforces and fails the test on
// transport error.
func postInteraction(tb testing.TB, client *http.Client, interactionURL, origin string, csrf *http.Cookie, stateRef string, values map[string]string) *http.Response {
	tb.Helper()
	body, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		tb.Fatalf("scenariokit: marshal interaction submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		interactionURL, bytes.NewReader(body))
	if err != nil {
		tb.Fatalf("scenariokit: build POST %s: %v", interactionURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(csrf)
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("scenariokit: POST %s: %v", interactionURL, err)
	}
	return resp
}

// completeConsentIfPrompted submits the built-in consent screen with
// every requested scope approved when prior is a consent prompt. The
// helper closes prior on dispatch and returns the chain's next
// response (typically the 302 redirect back to the RP). When prior is
// already a redirect or non-consent response, it is returned
// unchanged so callers keep a uniform Body close pattern.
func completeConsentIfPrompted(tb testing.TB, client *http.Client, interactionURL, origin string, csrf *http.Cookie, prior *http.Response) *http.Response {
	tb.Helper()
	consent, env, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		tb.Fatalf("scenariokit: inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	stateRef, _ := env["state_ref"].(string)
	if stateRef == "" {
		tb.Fatal("scenariokit: consent prompt missing state_ref")
	}
	// Per-step CSRF scope binding (interaction.go:178) re-issues the
	// __Host-oidc_csrf cookie on every step boundary, so the value
	// minted at the auth.* step does not verify against the consent.*
	// step. Pull the rotated cookie off the prior response.
	if rotated := findCookie(prior.Cookies(), "__Host-oidc_csrf"); rotated != nil {
		csrf = rotated
	}
	approved := approvedScopesFromPrompt(env)
	return testkit.PostConsentApproval(tb, client, interactionURL, origin, csrf.Value, stateRef, approved)
}

// approvedScopesFromPrompt extracts the requested scope names from
// the consent prompt envelope and returns them as a space-delimited
// string. Tests that intentionally drop a scope build their own
// subset and call [testkit.PostConsentApproval] directly.
func approvedScopesFromPrompt(env map[string]any) string {
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

// decodeJSON reads resp.Body as a JSON object map, failing the test on
// transport / decode error. Empty bodies decode to an empty map so the
// caller sees a stable zero value.
func decodeJSON(tb testing.TB, resp *http.Response) map[string]any {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("scenariokit: read body: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("scenariokit: decode body %s: %v", string(raw), err)
	}
	return out
}

// findCookie returns the cookie matching name, or nil. Used to thread
// the OP's CSRF cookie between the GET /interaction prompt and the
// matching POST submission.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// firstNonEmpty returns first when it is non-empty, otherwise fallback.
// It keeps [AuthorizeParams.Values] free of repetitive ternary
// expressions.
func firstNonEmpty(first, fallback string) string {
	if first != "" {
		return first
	}
	return fallback
}
