package scenarios_test

// Catalog: test/scenarios/catalog/pkce.yaml (PKCE-NNN)
// Spec:
//   - RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients
//   - RFC 6749 §4.1 — Authorization Code Grant
//   - OIDC Core 1.0 §3.1
//   - OAuth 2.1 §4.1.1
//   - RFC 8252 — OAuth 2.0 for Native Apps

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// pkceClientFixture is a confidential client pre-registered for each
// PKCE row. The OP's authorization-time PKCE checks fire on the
// request shape, not on the client type, so a confidential client
// suffices for PKCE-001..006 (which assert on the redirect-error
// shape) and for PKCE-011..016 (which round-trip through /token).
// PKCE-007 — the public-client downgrade guard — registers its own
// fixture with PublicClient=true.
type pkceClientFixture struct {
	clientID     string
	clientSecret string
	callback     string
}

func newPKCEClient(t *testing.T, suffix string) (*testkit.Provider, pkceClientFixture) {
	t.Helper()
	fix := pkceClientFixture{
		clientID:     "rp-pkce-" + suffix,
		clientSecret: "rp-pkce-" + suffix + "-secret", //nolint:gosec // test fixture: not a real credential.
		callback:     "https://rp.testkit.invalid/callback",
	}
	hash, err := op.HashClientSecret(fix.clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      fix.clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{fix.callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return tk, fix
}

// runAuthorizeRedirectError drives a single GET /authorize that the
// OP rejects redirect-safely and returns the parsed callback URL
// parameters. The helper is the redirect-error analogue of
// [scenariokit.RunCodeFlow]: when /authorize bounces straight back
// to the RP with error / error_description (PKCE-001..006), the OP
// never reaches the /interaction step, so this helper short-circuits
// the round-trip at step 1 and avoids the consent dance.
func runAuthorizeRedirectError(
	t *testing.T,
	tk *testkit.Provider,
	clientID, redirectURI, state string,
	values url.Values,
) (errCode, errDesc, gotState string, location *url.URL) {
	t.Helper()
	canonical := url.Values{
		"client_id":     {clientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"scope":         {scenariokit.DefaultScope},
		"state":         {state},
		"nonce":         {scenariokit.DefaultNonce},
	}
	for k, vs := range values {
		canonical[k] = append([]string(nil), vs...)
	}
	httpClient := &http.Client{
		Transport: tk.Server.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, tk.Server.URL+"/oidc/auth?"+canonical.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/authorize status=%d, want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	want, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("parse redirect_uri: %v", err)
	}
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
		t.Fatalf("/authorize Location=%s did not redirect to redirect_uri=%s; want a redirect-safe error", loc.String(), redirectURI)
	}
	q := loc.Query()
	return q.Get("error"), q.Get("error_description"), q.Get("state"), loc
}

// PKCE-001 (method-without-challenge) is out-of-scope: under the
// OP's default OIDC posture PKCE is opt-in, so an empty
// code_challenge silently disables PKCE for the request regardless
// of code_challenge_method.

// TestScenario_PKCE_002_ChallengeBelowMinLengthRejected checks that a
// code_challenge shorter than 43 base64url-no-pad characters is
// rejected with a redirect-safe invalid_request flagging the
// malformed challenge. The OP only accepts S256, whose output is
// exactly 43 chars; anything shorter is malformed.
//
// Spec: RFC 7636 §4.2.
func TestScenario_PKCE_002_ChallengeBelowMinLengthRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "002")
	const state = "pkce-002-state"

	gotErr, gotDesc, gotState, _ := runAuthorizeRedirectError(t, tk, fix.clientID, fix.callback, state, url.Values{
		"code_challenge":        {"short"},
		"code_challenge_method": {"S256"},
	})
	if gotErr != "invalid_request" {
		t.Errorf("error=%q want invalid_request", gotErr)
	}
	if !strings.Contains(gotDesc, "code_challenge") {
		t.Errorf("error_description=%q want it to mention code_challenge", gotDesc)
	}
	if gotState != state {
		t.Errorf("state=%q want %q", gotState, state)
	}
}

// TestScenario_PKCE_003_ChallengeAboveMaxLengthRejected checks that a
// code_challenge longer than 128 characters is rejected with a
// redirect-safe invalid_request flagging the malformed challenge.
// The OP only accepts S256 (exactly 43 base64url-no-pad chars); any
// other length is malformed.
//
// Spec: RFC 7636 §4.2.
func TestScenario_PKCE_003_ChallengeAboveMaxLengthRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "003")
	const state = "pkce-003-state"

	overlong := strings.Repeat("A", 200)
	gotErr, gotDesc, gotState, _ := runAuthorizeRedirectError(t, tk, fix.clientID, fix.callback, state, url.Values{
		"code_challenge":        {overlong},
		"code_challenge_method": {"S256"},
	})
	if gotErr != "invalid_request" {
		t.Errorf("error=%q want invalid_request", gotErr)
	}
	if !strings.Contains(gotDesc, "code_challenge") {
		t.Errorf("error_description=%q want it to mention code_challenge", gotDesc)
	}
	if gotState != state {
		t.Errorf("state=%q want %q", gotState, state)
	}
}

// TestScenario_PKCE_004_ChallengeInvalidCharsetRejected checks that a
// code_challenge whose length is correct but whose alphabet contains
// characters outside the base64url set (e.g. "&") is rejected with
// a redirect-safe invalid_request flagging the malformed challenge.
// The OP enforces base64url-no-pad on the wire.
//
// Spec: RFC 7636 §4.2.
func TestScenario_PKCE_004_ChallengeInvalidCharsetRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "004")
	const state = "pkce-004-state"

	// 43 chars exactly, but with "&" interleaved so the parser rejects
	// the alphabet. The "&" inside a query value is encoded as "%26"
	// by url.Values, so the OP receives the literal byte and runs the
	// alphabet check against it.
	bad := strings.Repeat("A", 21) + "&" + strings.Repeat("A", 21)
	if len(bad) != 43 {
		t.Fatalf("bad challenge length=%d, want 43 (test fixture invariant)", len(bad))
	}
	gotErr, gotDesc, gotState, _ := runAuthorizeRedirectError(t, tk, fix.clientID, fix.callback, state, url.Values{
		"code_challenge":        {bad},
		"code_challenge_method": {"S256"},
	})
	if gotErr != "invalid_request" {
		t.Errorf("error=%q want invalid_request", gotErr)
	}
	if !strings.Contains(gotDesc, "code_challenge") {
		t.Errorf("error_description=%q want it to mention code_challenge", gotDesc)
	}
	if gotState != state {
		t.Errorf("state=%q want %q", gotState, state)
	}
}

// TestScenario_PKCE_005_ChallengeMethodNotSupportedRejected checks
// that a code_challenge_method outside the supported set ("S256")
// is rejected with a redirect-safe invalid_request naming the
// required method. The OP only accepts S256 (FAPI 2.0 / OAuth 2.1
// / RFC 9700 forbid the legacy "plain" mode).
//
// Spec: RFC 7636 §4.3.
func TestScenario_PKCE_005_ChallengeMethodNotSupportedRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "005")
	const state = "pkce-005-state"

	pkce := scenariokit.NewPKCEPair("")
	gotErr, gotDesc, gotState, _ := runAuthorizeRedirectError(t, tk, fix.clientID, fix.callback, state, url.Values{
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"bar"},
	})
	if gotErr != "invalid_request" {
		t.Errorf("error=%q want invalid_request", gotErr)
	}
	if !strings.Contains(gotDesc, "S256") {
		t.Errorf("error_description=%q want it to name S256", gotDesc)
	}
	if gotState != state {
		t.Errorf("state=%q want %q", gotState, state)
	}
}

// TestScenario_PKCE_006_PlainMethodDisabledRejected checks that
// code_challenge_method=plain is rejected unconditionally, regardless
// of profile. RFC 7636 §4.3 catalogues "plain" as a supported value,
// but FAPI 2.0 / OAuth 2.1 / RFC 9700 forbid it; the project's
// posture is "S256 only" and the redirect carries invalid_request
// naming the required method.
//
// Spec: RFC 7636 §4.3 / OAuth 2.1 §4.1.1.
func TestScenario_PKCE_006_PlainMethodDisabledRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "006")
	const state = "pkce-006-state"

	pkce := scenariokit.NewPKCEPair("")
	gotErr, gotDesc, gotState, _ := runAuthorizeRedirectError(t, tk, fix.clientID, fix.callback, state, url.Values{
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"plain"},
	})
	if gotErr != "invalid_request" {
		t.Errorf("error=%q want invalid_request", gotErr)
	}
	if !strings.Contains(gotDesc, "S256") {
		t.Errorf("error_description=%q want it to name S256 (project policy: plain rejected)", gotDesc)
	}
	if gotState != state {
		t.Errorf("state=%q want %q", gotState, state)
	}
}

// TestScenario_PKCE_007_PublicClientCodeRequiresPKCE checks the
// /token-side downgrade guard from RFC 9700 §2.1.1: a public client
// (TokenEndpointAuthMethod="none") that successfully obtained a
// non-PKCE authorization code (legacy OIDC posture, no profile
// mandates PKCE) cannot redeem the code. The /token response is 400
// invalid_grant with "PKCE is required for public clients (RFC 9700
// §2.1.1)"; no tokens are issued.
//
// Spec: RFC 9700 §2.1.1 / OAuth 2.1 §4.1.1.
func TestScenario_PKCE_007_PublicClientCodeRequiresPKCE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-pkce-007"
		callback = "https://rp.testkit.invalid/callback"
	)
	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
	})

	// Drive /authorize with the canonical code_challenge / method
	// fields blanked so the OP issues a non-PKCE code. Extra
	// overrides the canonical entries (see [AuthorizeParams.Values]).
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		Extra: url.Values{
			"code_challenge":        {""},
			"code_challenge_method": {""},
		},
	})
	if flow.Code == "" {
		t.Fatalf("non-PKCE authorize must succeed under the legacy posture: %+v", flow)
	}

	// Public clients authenticate with no client_secret. Submit the
	// code without a code_verifier — the downgrade guard fires.
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:        flow.Code,
		RedirectURI: callback,
		Extra:       url.Values{"client_id": {clientID}},
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v want 400", tok.StatusCode, tok.Raw)
	}
	gotErr, _ := tok.Raw["error"].(string)
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", gotErr)
	}
	desc, _ := tok.Raw["error_description"].(string)
	if !strings.Contains(strings.ToLower(desc), "pkce") {
		t.Errorf("error_description=%q want it to mention PKCE", desc)
	}
	if tok.AccessToken != "" || tok.IDToken != "" || tok.RefreshToken != "" {
		t.Errorf("downgrade guard must not mint tokens: %+v", tok.Raw)
	}
}

// PKCE-008 (hybrid public-client) and PKCE-009 (implicit-only) are
// out-of-scope: implicit / hybrid response_type is intentionally
// not supported by the OP (only response_type=code is advertised).

// PKCE-010 (stored-challenge persistence) is out-of-scope: internal
// storage shape is not observable through the public surface;
// persistence is exercised end-to-end by PKCE-011 and PKCE-013.

// TestScenario_PKCE_011_VerifierMatchesS256ChallengeSucceeds checks
// the happy path: a code_verifier whose SHA-256 base64url-no-pad
// digest equals the stored code_challenge under method=S256 redeems
// the code for an access_token + id_token.
//
// Spec: RFC 7636 §4.6.
func TestScenario_PKCE_011_VerifierMatchesS256ChallengeSucceeds(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "011")
	pkce := scenariokit.NewPKCEPair("")

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    fix.clientID,
		RedirectURI: fix.callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  fix.callback,
		Verifier:     pkce.Verifier,
		ClientID:     fix.clientID,
		ClientSecret: fix.clientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v want 200", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Error("access_token missing")
	}
	if tok.IDToken == "" {
		t.Error("id_token missing")
	}
}

// TestScenario_PKCE_012_TokenGrantWithoutVerifierRejected checks that
// a code minted with a stored code_challenge cannot be redeemed
// without a code_verifier: pkce.Verify treats the empty verifier as
// a format violation, the wire layer collapses every token-side PKCE
// failure onto invalid_grant ("PKCE verification failed").
//
// Spec: RFC 7636 §4.6.
func TestScenario_PKCE_012_TokenGrantWithoutVerifierRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "012")
	pkce := scenariokit.NewPKCEPair("")

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    fix.clientID,
		RedirectURI: fix.callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  fix.callback,
		Verifier:     "", // omit
		ClientID:     fix.clientID,
		ClientSecret: fix.clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v want 400", tok.StatusCode, tok.Raw)
	}
	gotErr, _ := tok.Raw["error"].(string)
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", gotErr)
	}
	if tok.AccessToken != "" || tok.IDToken != "" {
		t.Errorf("missing-verifier exchange must not mint tokens: %+v", tok.Raw)
	}
}

// TestScenario_PKCE_013_VerifierHashMismatchRejected checks that a
// well-formed code_verifier whose SHA-256 digest does NOT match the
// stored challenge is rejected with 400 invalid_grant. Two distinct
// PKCE pairs are generated; the authorize step uses the first
// challenge, the /token step the second verifier, so the hash
// comparison fails despite each value being individually valid.
//
// Spec: RFC 7636 §4.6.
func TestScenario_PKCE_013_VerifierHashMismatchRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "013")
	authPair := scenariokit.NewPKCEPair("alpha-alpha-alpha-alpha-alpha-alpha-alpha-alphaA")
	otherPair := scenariokit.NewPKCEPair("bravo-bravo-bravo-bravo-bravo-bravo-bravo-bravoB")
	if authPair.Challenge == otherPair.Challenge {
		t.Fatalf("test fixture invariant: pair challenges collided")
	}

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    fix.clientID,
		RedirectURI: fix.callback,
		PKCE:        authPair,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  fix.callback,
		Verifier:     otherPair.Verifier,
		ClientID:     fix.clientID,
		ClientSecret: fix.clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v want 400", tok.StatusCode, tok.Raw)
	}
	gotErr, _ := tok.Raw["error"].(string)
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", gotErr)
	}
	if tok.AccessToken != "" || tok.IDToken != "" {
		t.Errorf("hash-mismatch exchange must not mint tokens: %+v", tok.Raw)
	}
}

// TestScenario_PKCE_014_VerifierBelowMinLengthRejected checks that a
// code_verifier shorter than 43 characters is rejected at /token
// with 400 invalid_grant. The wire layer collapses every token-side
// PKCE failure (format / mismatch / unsupported method) onto
// invalid_grant per RFC 7636 §4.6 — the violation is a property of
// the redeemed grant, not of the request shape, so invalid_grant is
// the correct wire code.
//
// Spec: RFC 7636 §4.1.
func TestScenario_PKCE_014_VerifierBelowMinLengthRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "014")
	pkce := scenariokit.NewPKCEPair("")

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    fix.clientID,
		RedirectURI: fix.callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  fix.callback,
		Verifier:     "tooshort", // 8 chars, well below the 43-char minimum
		ClientID:     fix.clientID,
		ClientSecret: fix.clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v want 400", tok.StatusCode, tok.Raw)
	}
	gotErr, _ := tok.Raw["error"].(string)
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", gotErr)
	}
	if tok.AccessToken != "" || tok.IDToken != "" {
		t.Errorf("short-verifier exchange must not mint tokens: %+v", tok.Raw)
	}
}

// TestScenario_PKCE_015_VerifierAboveMaxLengthRejected checks that a
// code_verifier longer than 128 characters is rejected at /token
// with 400 invalid_grant. The 43..128 unreserved-character bound is
// pinned in RFC 7636 §4.1; token-side PKCE failures collapse onto
// invalid_grant per RFC 7636 §4.6.
//
// Spec: RFC 7636 §4.1.
func TestScenario_PKCE_015_VerifierAboveMaxLengthRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "015")
	pkce := scenariokit.NewPKCEPair("")

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    fix.clientID,
		RedirectURI: fix.callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	overlong := strings.Repeat("A", 200)
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  fix.callback,
		Verifier:     overlong,
		ClientID:     fix.clientID,
		ClientSecret: fix.clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v want 400", tok.StatusCode, tok.Raw)
	}
	gotErr, _ := tok.Raw["error"].(string)
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", gotErr)
	}
	if tok.AccessToken != "" || tok.IDToken != "" {
		t.Errorf("long-verifier exchange must not mint tokens: %+v", tok.Raw)
	}
}

// TestScenario_PKCE_016_VerifierInvalidCharsetRejected checks that a
// code_verifier whose length is in bounds but whose alphabet
// contains characters outside the RFC 7636 §4.1 unreserved set
// (ALPHA / DIGIT / "-" / "." / "_" / "~") is rejected at /token
// with 400 invalid_grant. Token-side PKCE failures collapse onto
// invalid_grant per RFC 7636 §4.6.
//
// Spec: RFC 7636 §4.1.
func TestScenario_PKCE_016_VerifierInvalidCharsetRejected(t *testing.T) {
	t.Parallel()

	tk, fix := newPKCEClient(t, "016")
	pkce := scenariokit.NewPKCEPair("")

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    fix.clientID,
		RedirectURI: fix.callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// 64-char verifier with a non-unreserved byte ("&") in the
	// middle. The length is in bounds; the alphabet check fires.
	bad := strings.Repeat("A", 31) + "&" + strings.Repeat("A", 32)
	if len(bad) < 43 || len(bad) > 128 {
		t.Fatalf("bad verifier length=%d, want 43..128 (test fixture invariant)", len(bad))
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  fix.callback,
		Verifier:     bad,
		ClientID:     fix.clientID,
		ClientSecret: fix.clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v want 400", tok.StatusCode, tok.Raw)
	}
	gotErr, _ := tok.Raw["error"].(string)
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", gotErr)
	}
	if tok.AccessToken != "" || tok.IDToken != "" {
		t.Errorf("bad-charset exchange must not mint tokens: %+v", tok.Raw)
	}
}

// PKCE-017 (state preservation generic) is out-of-scope: subsumed
// by PKCE-002..006, each of which asserts state round-trip
// explicitly on the redirect-error path.
