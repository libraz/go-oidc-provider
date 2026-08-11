package scenarios_test

// Catalog: test/scenarios/catalog/end_session.yaml (ES-NNN)
// Spec:
//   - OIDC RP-Initiated Logout 1.0
//   - OIDC Core 1.0 §2, §3.1.3.7
//   - OIDC Discovery 1.0 (`end_session_endpoint`)
//   - RFC 7519 (JWT)
//   - RFC 6749 §3.1.2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	esClientID    = "rp-end-session"
	esCallbackURI = "https://rp.testkit.invalid/callback"
	esPostLogout  = "https://rp.testkit.invalid/post-logout"
	esSubject     = "user-1"
)

// esIDTokenClaims is the canonical id_token-shaped claim set the
// /end_session handler accepts. The handler only checks signature,
// issuer, and audience (OIDC RP-Initiated Logout 1.0 §2 deliberately
// omits exp / iat freshness so a stale tab can still sign out), so
// the helper is comfortably below a real ID token's surface.
type esIDTokenClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat,omitempty"`
	Exp int64  `json:"exp,omitempty"`
}

// newESProvider stands up a testkit Provider with one client whose
// post-logout allowlist contains exactly esPostLogout.
func newESProvider(t *testing.T) (*testkit.Provider, *store.Client) {
	t.Helper()
	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      esClientID,
		RedirectURIs:            []string{esCallbackURI},
		PostLogoutRedirectURIs:  []string{esPostLogout},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
	})
	return tk, rp
}

// mintESIDToken returns a freshly signed id_token-shaped JWS the
// /end_session handler will accept. mutate, when non-nil, can override
// any claim before serialisation. The default iat / exp are anchored
// to the current wall clock so the handler's iat-age soft cap (30 days
// per internal/endsession.maxIDTokenHintAge) admits the token.
func mintESIDToken(t *testing.T, p *testkit.Provider, mutate func(*esIDTokenClaims)) string {
	t.Helper()
	now := time.Now().Unix()
	c := esIDTokenClaims{
		Iss: p.Issuer,
		Sub: esSubject,
		Aud: esClientID,
		Iat: now - 60,
		Exp: now + 3600,
	}
	if mutate != nil {
		mutate(&c)
	}
	tok, err := p.SignedJWT(c)
	if err != nil {
		t.Fatalf("SignedJWT: %v", err)
	}
	return tok
}

// mintESIDTokenWithForeignKey signs an id_token-shaped JWS with a
// freshly generated ES256 key whose kid matches the OP's active key
// — the OP keyset will route verification to the legitimate public key,
// signature verification fails because the bytes were produced by a
// different private key.
func mintESIDTokenWithForeignKey(t *testing.T, p *testkit.Provider, claims esIDTokenClaims) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       priv,
			KeyID:     p.SigningKey.KeyID, // collide with the OP's kid so .Find succeeds
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	signer, err := josev4.NewSigner(sk, (&josev4.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Serialize: %v", err)
	}
	return out
}

// esGet issues a GET /oidc/end_session against tk with the supplied
// query parameters. Redirects are NOT followed so the caller can
// inspect the Location and status.
func esGet(t *testing.T, tk *testkit.Provider, values url.Values) *http.Response {
	t.Helper()
	target := tk.Server.URL + "/oidc/end_session"
	if encoded := values.Encode(); encoded != "" {
		target += "?" + encoded
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", target, err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

// readESBody slurps resp.Body into a string and closes it.
func readESBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// TestScenario_ES_001_ConfirmationFormRenderedOnGetWithoutSession is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_001_ConfirmationFormRenderedOnGetWithoutSession(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-001 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_002_ConfirmationFormRenderedOnPostWithoutSession is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_002_ConfirmationFormRenderedOnPostWithoutSession(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-002 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_003_ExpiredIDTokenHintAcceptedForLogout pins the
// rule that v1.0 admits an id_token_hint with a past exp. The handler
// (internal/endsession/idtoken.go) deliberately does not enforce exp:
// the hint exists to identify the requesting client, and OIDC
// RP-Initiated Logout 1.0 §2 lets a stale tab log out. The handler
// DOES enforce a soft iat-age cap so we keep iat within the 30-day
// window while pushing exp deep into the past.
//
// Spec: OIDC RP-Initiated Logout 1.0 §2.
func TestScenario_ES_003_ExpiredIDTokenHintAcceptedForLogout(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, func(c *esIDTokenClaims) {
		c.Exp = time.Now().Unix() - 60 // expired by a minute
	})

	resp := esGet(t, tk, url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {esPostLogout},
	})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302; body=%s", resp.StatusCode, string(body))
	}
	loc := resp.Header.Get("Location")
	if loc != esPostLogout {
		t.Errorf("Location=%q want %q", loc, esPostLogout)
	}
}

// TestScenario_ES_004_RedirectViaIDTokenHint pins the happy path: a
// valid id_token_hint plus a registered post_logout_redirect_uri
// short-circuits the CSRF interstitial and yields a direct 302 to
// the registered URI.
//
// Spec: OIDC RP-Initiated Logout 1.0 §2.
func TestScenario_ES_004_RedirectViaIDTokenHint(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, nil)
	resp := esGet(t, tk, url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {esPostLogout},
	})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302; body=%s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Location"); got != esPostLogout {
		t.Errorf("Location=%q want %q", got, esPostLogout)
	}
}

// TestScenario_ES_005_RedirectViaClientID pins the no-hint resolution
// path. With only a client_id, v1.0 enforces the CSRF interstitial:
// GET renders the double-submit confirmation form (200 HTML), and
// only a POST that presents the matching __Host-oidc_logout_csrf
// cookie + logout_csrf form field proceeds to the 302 redirect.
//
// Spec: OIDC RP-Initiated Logout 1.0 §2.
func TestScenario_ES_005_RedirectViaClientID(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)

	// GET renders the confirmation page and stamps the CSRF cookie.
	resp := esGet(t, tk, url.Values{
		"client_id":                {esClientID},
		"post_logout_redirect_uri": {esPostLogout},
	})
	defer func() { _ = resp.Body.Close() }()
	body := readESBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Confirm sign-out") {
		t.Errorf("GET body missing confirmation marker: %s", body)
	}
	if !strings.Contains(body, `name="logout_csrf"`) {
		t.Errorf("GET body missing logout_csrf form field: %s", body)
	}
	var csrfCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-oidc_logout_csrf" && c.Value != "" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatalf("__Host-oidc_logout_csrf cookie not stamped on GET interstitial; cookies=%v", resp.Cookies())
	}

	// POST with the matching token proceeds to the 302.
	form := url.Values{
		"client_id":                {esClientID},
		"post_logout_redirect_uri": {esPostLogout},
		"logout_csrf":              {csrfCookie.Value},
	}
	target := tk.Server.URL + "/oidc/end_session"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST %s: %v", target, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The confirmation form is served from, and posts back to, the
	// issuer origin, so that is what a real browser sends. The test
	// server's loopback URL is a different origin and is rejected.
	req.Header.Set("Origin", tk.Issuer)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: csrfCookie.Value})
	postResp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer func() { _ = postResp.Body.Close() }()
	if postResp.StatusCode != http.StatusFound {
		bbody, _ := io.ReadAll(postResp.Body)
		t.Fatalf("POST status=%d want 302; body=%s", postResp.StatusCode, string(bbody))
	}
	if got := postResp.Header.Get("Location"); got != esPostLogout {
		t.Errorf("POST Location=%q want %q", got, esPostLogout)
	}
}

// TestScenario_ES_006_RedirectViaIDTokenHintAndClientID pins the
// consistent-pair path: id_token_hint and client_id supplied, the
// parameter equals the hint's aud, and the OP redirects 302 directly.
//
// Spec: OIDC RP-Initiated Logout 1.0 §2.
func TestScenario_ES_006_RedirectViaIDTokenHintAndClientID(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, nil)
	resp := esGet(t, tk, url.Values{
		"id_token_hint":            {hint},
		"client_id":                {esClientID},
		"post_logout_redirect_uri": {esPostLogout},
	})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302; body=%s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Location"); got != esPostLogout {
		t.Errorf("Location=%q want %q", got, esPostLogout)
	}
}

// TestScenario_ES_007_ClientIDMismatchWithIDTokenHintRejected pins the
// disagreement gate: when client_id and id_token_hint.aud differ, v1.0
// rejects with HTML 400 carrying the static description "client_id and
// id_token_hint disagree".
//
// Spec: OIDC RP-Initiated Logout 1.0 §2.
func TestScenario_ES_007_ClientIDMismatchWithIDTokenHintRejected(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, nil) // aud = esClientID
	resp := esGet(t, tk, url.Values{
		"id_token_hint": {hint},
		"client_id":     {"some-other-client"},
	})
	defer func() { _ = resp.Body.Close() }()
	body := readESBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "client_id and id_token_hint disagree") {
		t.Errorf("body missing disagreement description: %s", body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type=%q want text/html", got)
	}
}

// TestScenario_ES_008_UnknownClientIDRejected pins the no-client wire
// shape: a client_id parameter that resolves to no registered client
// produces a 400 HTML page carrying the static description
// "invalid client". v1.0 conflates the unknown-client wire shape onto
// the same envelope as id-token-hint failures so the response is not
// an existence oracle for client identifiers.
//
// Spec: OIDC Core 1.0 §3.1.2.2 / RFC 6749 §5.2.
func TestScenario_ES_008_UnknownClientIDRejected(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	resp := esGet(t, tk, url.Values{
		"client_id": {"client-does-not-exist"},
	})
	defer func() { _ = resp.Body.Close() }()
	body := readESBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "invalid client") {
		t.Errorf("body missing 'invalid client' description: %s", body)
	}
}

// TestScenario_ES_009_HMACHintWithExpiredSecretRejected is OOS — see
// catalog out_of_scope_reason.
func TestScenario_ES_009_HMACHintWithExpiredSecretRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-009 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_010_RequestEntitiesPopulated is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_010_RequestEntitiesPopulated(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-010 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_011_StatePassthroughOnRequest pins the `state`
// passthrough: an end_session call that supplies state alongside a
// valid id_token_hint and registered post_logout_redirect_uri must
// echo state verbatim onto the post-logout redirect's query.
//
// Spec: OIDC RP-Initiated Logout 1.0 §2 (`state`).
func TestScenario_ES_011_StatePassthroughOnRequest(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, nil)
	const wantState = "es-011-state"

	resp := esGet(t, tk, url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {esPostLogout},
		"state":                    {wantState},
	})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302; body=%s", resp.StatusCode, string(body))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("resp.Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != wantState {
		t.Errorf("redirect state=%q want %q (full Location=%s)", got, wantState, loc.String())
	}
	// Sanity: the redirect target host / path is unchanged from the registered URI.
	want, _ := url.Parse(esPostLogout)
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
		t.Errorf("redirect target shape %s does not match registered URI %s", loc.String(), esPostLogout)
	}
}

// TestScenario_ES_012_DefaultPostLogoutRedirect is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_012_DefaultPostLogoutRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-012 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_013_UnverifiedPostLogoutRedirectURIDropped is OOS —
// see catalog out_of_scope_reason.
func TestScenario_ES_013_UnverifiedPostLogoutRedirectURIDropped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-013 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_014_UnregisteredPostLogoutRedirectURIRejected pins
// the redirect-URI allowlist gate: an id_token_hint identifies a
// client, but the supplied post_logout_redirect_uri is not in that
// client's registered allowlist. v1.0 responds with HTML 400 carrying
// the static description "post_logout_redirect_uri is not registered".
//
// Spec: OIDC RP-Initiated Logout 1.0 §2.
func TestScenario_ES_014_UnregisteredPostLogoutRedirectURIRejected(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, nil)
	resp := esGet(t, tk, url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://attacker.example.com/post-logout"},
	})
	defer func() { _ = resp.Body.Close() }()
	body := readESBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "post_logout_redirect_uri is not registered") {
		t.Errorf("body missing not-registered description: %s", body)
	}
}

// TestScenario_ES_015_MalformedIDTokenHintRejected pins the parse-fail
// shape: an id_token_hint that is not a syntactically valid JWS yields
// HTML 400 carrying the static description "invalid id_token_hint".
// The description deliberately conflates parse / kid / signature
// failures so the wire is not a sub-cause oracle.
//
// Spec: RFC 7519 §7.2 / OIDC RP-Initiated Logout 1.0 §2.
func TestScenario_ES_015_MalformedIDTokenHintRejected(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	resp := esGet(t, tk, url.Values{
		"id_token_hint": {"this.is.not-a-valid-jwt"},
	})
	defer func() { _ = resp.Body.Close() }()
	body := readESBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "invalid id_token_hint") {
		t.Errorf("body missing invalid-hint description: %s", body)
	}
}

// TestScenario_ES_016_IDTokenHintAudienceUnknownRejected pins the
// aud-not-found behaviour: a JWT signed by the OP whose aud is not a
// registered client surfaces as the static "invalid client" 400 page.
// verifyIDTokenHint succeeds (the signature is valid) and hands the
// aud to resolveByClientID, which collapses ErrNotFound and any
// transport fault onto descClientNotFound (handler.go:329). The same
// description is reused for an unknown client_id parameter (ES-008),
// so the wire surface is not an existence oracle either way.
//
// Spec: OIDC Core 1.0 §3.1.3.7.
func TestScenario_ES_016_IDTokenHintAudienceUnknownRejected(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, func(c *esIDTokenClaims) {
		c.Aud = "client-not-registered"
	})
	resp := esGet(t, tk, url.Values{
		"id_token_hint": {hint},
	})
	defer func() { _ = resp.Body.Close() }()
	body := readESBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "invalid client") {
		t.Errorf("body missing 'invalid client' description: %s", body)
	}
}

// TestScenario_ES_017_IDTokenHintSignatureInvalidRejected pins the
// wrong-key signature path: a JWT carrying the OP's active kid but
// signed by a foreign private key fails verification, and the wire
// surface is again the conflated "invalid id_token_hint" 400.
//
// Spec: OIDC Core 1.0 §3.1.3.7 / RFC 7515 §5.2.
func TestScenario_ES_017_IDTokenHintSignatureInvalidRejected(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDTokenWithForeignKey(t, tk, esIDTokenClaims{
		Iss: tk.Issuer,
		Sub: esSubject,
		Aud: esClientID,
		Iat: 1700000000,
		Exp: 1700003600,
	})
	resp := esGet(t, tk, url.Values{
		"id_token_hint": {hint},
	})
	defer func() { _ = resp.Body.Close() }()
	body := readESBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "invalid id_token_hint") {
		t.Errorf("body missing invalid-hint description: %s", body)
	}
}

// TestScenario_ES_018_ConfirmWithoutStateRejected is OOS — see
// catalog out_of_scope_reason.
func TestScenario_ES_018_ConfirmWithoutStateRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-018 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_019_ConfirmXSRFMismatchRejected is OOS — see
// catalog out_of_scope_reason.
func TestScenario_ES_019_ConfirmXSRFMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-019 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_020_ConfirmEntitiesPopulated is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_020_ConfirmEntitiesPopulated(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-020 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_021_FullSessionDestroyAndGrantRevocation is OOS —
// see catalog out_of_scope_reason.
func TestScenario_ES_021_FullSessionDestroyAndGrantRevocation(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-021 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_022_PerClientLogoutWithRedirect is OOS — see
// catalog out_of_scope_reason.
func TestScenario_ES_022_PerClientLogoutWithRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-022 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_023_PerClientLogoutDefaultSuccessPage is OOS — see
// catalog out_of_scope_reason.
func TestScenario_ES_023_PerClientLogoutDefaultSuccessPage(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-023 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_024_StateForwardedToRP pins the state-on-redirect
// wire: state=foobar arriving with a valid id_token_hint and a
// registered post_logout_redirect_uri MUST be echoed verbatim on the
// 302 redirect's query (`?state=foobar`). v1.0 emits 302 (Found), not
// the upstream 303.
//
// Spec: OIDC RP-Initiated Logout 1.0 §2 (`state`).
func TestScenario_ES_024_StateForwardedToRP(t *testing.T) {
	t.Parallel()

	tk, _ := newESProvider(t)
	hint := mintESIDToken(t, tk, nil)
	const wantState = "foobar"
	resp := esGet(t, tk, url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {esPostLogout},
		"state":                    {wantState},
	})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302 (v1.0 emits Found, not 303); body=%s", resp.StatusCode, string(body))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("resp.Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != wantState {
		t.Errorf("redirect state=%q want %q", got, wantState)
	}
	want, _ := url.Parse(esPostLogout)
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
		t.Errorf("redirect target=%s does not match registered URI %s", loc.String(), esPostLogout)
	}
}

// TestScenario_ES_025_ConfirmWithoutPriorAuthorizations is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_025_ConfirmWithoutPriorAuthorizations(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-025 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_026_SuccessPageWithoutClient is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_026_SuccessPageWithoutClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-026 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_027_SuccessPageWithKnownClient is OOS — see catalog out_of_scope_reason.
func TestScenario_ES_027_SuccessPageWithKnownClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-027 (see catalog out_of_scope_reason)")
}

// TestScenario_ES_028_SuccessPageUnknownClientRejected is OOS — see
// catalog out_of_scope_reason.
func TestScenario_ES_028_SuccessPageUnknownClientRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ES-028 (see catalog out_of_scope_reason)")
}
