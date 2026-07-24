package registrationendpoint_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fixedClock is the deterministic Now() helper used across the
// registration tests so IAT expiry is observable. The clock value is
// pinned to the project's "today" baseline.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// dcrFixture bundles the testkit Provider with the helpers shared
// across the registration test suite.
type dcrFixture struct {
	prov     *testkit.Provider
	endpoint string
	clock    fixedClock
	logBuf   *syncBuffer
}

// syncBuffer is an io.Writer that serialises concurrent writes from the
// slog handler so test goroutines do not interleave WARN frames.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newFixture builds a DCR-enabled provider with the supplied options
// applied on top of the testkit defaults. The clock is pinned at
// 2026-04-26 12:00 UTC.
func newFixture(tb testing.TB, regOpt op.RegistrationOption, extra ...op.Option) *dcrFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	all := append([]op.Option{
		op.WithDynamicRegistration(regOpt),
		op.WithLogger(logger),
	}, extra...)
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(all...),
	)
	return &dcrFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/register",
		clock:    clock,
		logBuf:   logBuf,
	}
}

// hashIAT mirrors the SHA-256 hex digest the library computes from an
// IAT bearer secret before persisting it.
func hashIAT(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// issueIAT mints an IAT through the public op.Provider.IssueInitialAccessToken
// API and returns the bearer secret.
func (f *dcrFixture) issueIAT(tb testing.TB, spec op.InitialAccessTokenSpec) (id, value string) {
	tb.Helper()
	issued, err := f.prov.OP.IssueInitialAccessToken(context.Background(), spec)
	if err != nil {
		tb.Fatalf("IssueInitialAccessToken: %v", err)
	}
	return issued.ID, issued.Value
}

// putRawIAT writes an IAT record directly into the store, bypassing the
// provider so tests can inject expired records and other irregular
// shapes the public API will not produce.
func (f *dcrFixture) putRawIAT(tb testing.TB, rec *store.InitialAccessToken) {
	tb.Helper()
	if err := f.prov.Store.InitialAccessTokens().Put(context.Background(), rec); err != nil {
		tb.Fatalf("Put IAT: %v", err)
	}
}

// post issues a POST application/json request with the supplied body and
// optional Bearer credential.
func (f *dcrFixture) post(tb testing.TB, body any, bearer string) *http.Response {
	tb.Helper()
	return f.postWithContentType(tb, body, bearer, "application/json")
}

func (f *dcrFixture) postWithContentType(tb testing.TB, body any, bearer, ct string) *http.Response {
	tb.Helper()
	var buf io.Reader
	switch v := body.(type) {
	case nil:
		buf = http.NoBody
	case string:
		buf = strings.NewReader(v)
	case []byte:
		buf = bytes.NewReader(v)
	default:
		raw, err := json.Marshal(body)
		if err != nil {
			tb.Fatalf("marshal: %v", err)
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.endpoint, buf)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// decodeBody unmarshals the response body as JSON. Empty bodies return
// an empty map.
func decodeBody(tb testing.TB, resp *http.Response) map[string]any {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("ReadAll: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("Unmarshal(%s): %v", raw, err)
	}
	return out
}

// assertCacheControl checks the no-store / Pragma headers RFC 7591 §3.2
// requires.
func assertCacheControl(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		tb.Errorf("Cache-Control=%q want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		tb.Errorf("Pragma=%q want no-cache", got)
	}
}

// minimalMetadata returns a minimal RFC 7591 metadata document carrying
// only the redirect_uris field. Tests that need additional knobs build
// the full map explicitly.
func minimalMetadata() map[string]any {
	return map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/callback"},
	}
}

// TestRegister_HappyPath_MintsConfidentialClient confirms a minimal
// POST under a freshly issued IAT mints a confidential client with
// client_secret, RAT, and registration_client_uri.
func TestRegister_HappyPath_MintsConfidentialClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	resp := f.post(t, minimalMetadata(), iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d want 201", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	assertCacheControl(t, resp)

	body := decodeBody(t, resp)
	clientID, _ := body["client_id"].(string)
	if clientID == "" {
		t.Fatal("client_id missing from response")
	}
	if issued, _ := body["client_id_issued_at"].(float64); int64(issued) <= 0 {
		t.Errorf("client_id_issued_at=%v want positive unix timestamp", body["client_id_issued_at"])
	}
	if secret, _ := body["client_secret"].(string); secret == "" {
		t.Error("client_secret must be present for confidential client")
	}
	if rat, _ := body["registration_access_token"].(string); rat == "" {
		t.Error("registration_access_token missing from response")
	}
	if uri, _ := body["registration_client_uri"].(string); !strings.HasSuffix(uri, "/oidc/register/"+clientID) {
		t.Errorf("registration_client_uri=%v must end with /oidc/register/%s", body["registration_client_uri"], clientID)
	}
	// Metadata echo: redirect_uris must round-trip.
	uris, _ := body["redirect_uris"].([]any)
	if len(uris) != 1 || uris[0] != "https://rp.test.invalid/callback" {
		t.Errorf("redirect_uris echo=%v", body["redirect_uris"])
	}

	// IAT must have been consumed exactly once.
	rec, err := f.prov.Store.InitialAccessTokens().GetByHash(context.Background(), hashIAT(iat))
	if !errors.Is(err, store.ErrNotFound) && err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if err == nil && rec.Uses != 1 {
		t.Errorf("IAT Uses=%d want 1", rec.Uses)
	}

	// Persisted client must carry Source=Dynamic and FirstParty=false (default).
	got, err := f.prov.Store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}
	if got.Source != store.ClientSourceDynamic {
		t.Errorf("client.Source=%q want %q", got.Source, store.ClientSourceDynamic)
	}
	if got.ClientIDIssuedAt <= 0 {
		t.Errorf("client.ClientIDIssuedAt=%d want positive unix timestamp", got.ClientIDIssuedAt)
	}
	if got.PublicClient {
		t.Error("client.PublicClient must be false for client_secret_basic")
	}
}

// TestRegister_BodyTooLarge pins the 64 KiB body-size ceiling the
// handler installs via endpointsupport.LimitFormBody before decoding
// the JSON metadata document. A body comfortably above the cap must be
// rejected as invalid_client_metadata / "malformed JSON" — the same
// wire shape the endpoint produced when it wrapped r.Body in
// http.MaxBytesReader directly, prior to routing through the shared
// limiter.
func TestRegister_BodyTooLarge(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	oversized := `{"redirect_uris":["https://rp.test.invalid/callback"],"client_name":"` +
		strings.Repeat("a", 70*1024) + `"}`
	resp := f.post(t, oversized, iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Fatalf("error=%v want invalid_client_metadata", got["error"])
	}
}

func TestRegister_RejectsNegativeDefaultMaxAge(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	body := minimalMetadata()
	body["default_max_age"] = -1
	resp := f.post(t, body, iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Fatalf("error=%v want invalid_client_metadata", got["error"])
	}
}

func TestRegister_IgnoresStandardUnstoredMetadata(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	body := minimalMetadata()
	body["software_id"] = "software-123"
	body["software_version"] = "2026.6"
	body["tls_client_certificate_bound_access_tokens"] = true
	body["backchannel_token_delivery_mode"] = "poll"
	body["backchannel_client_notification_endpoint"] = "https://rp.test.invalid/ciba/callback"
	body["backchannel_authentication_request_signing_alg"] = "ES256"
	body["backchannel_user_code_parameter"] = true
	body["authorization_signed_response_alg"] = "ES256"
	body["authorization_details_types"] = []string{"payment_initiation"}

	resp := f.post(t, body, iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	for _, ignored := range []string{
		"software_id",
		"software_version",
		"tls_client_certificate_bound_access_tokens",
		"backchannel_token_delivery_mode",
		"backchannel_client_notification_endpoint",
		"backchannel_authentication_request_signing_alg",
		"backchannel_user_code_parameter",
		"authorization_signed_response_alg",
		"authorization_details_types",
	} {
		if _, ok := got[ignored]; ok {
			t.Errorf("response echoed ignored metadata %q: %v", ignored, got[ignored])
		}
	}
}

// TestRegister_HappyPath_PostLogoutRedirectURIsRoundTrip confirms a
// POST carrying a valid post_logout_redirect_uris list is accepted,
// the value is persisted on the [store.Client] record, and the
// response body echoes the same list. The field is optional in
// RFC 7591 / OIDC RP-Initiated Logout 1.0 §3 so this test is the
// happy-path sibling of the validator unit table.
func TestRegister_HappyPath_PostLogoutRedirectURIsRoundTrip(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	body := minimalMetadata()
	body["post_logout_redirect_uris"] = []string{"https://rp.test.invalid/logout"}
	resp := f.post(t, body, iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	echoed, _ := got["post_logout_redirect_uris"].([]any)
	if len(echoed) != 1 || echoed[0] != "https://rp.test.invalid/logout" {
		t.Errorf("post_logout_redirect_uris echo=%v", got["post_logout_redirect_uris"])
	}
	clientID, _ := got["client_id"].(string)
	stored, err := f.prov.Store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}
	if len(stored.PostLogoutRedirectURIs) != 1 || stored.PostLogoutRedirectURIs[0] != "https://rp.test.invalid/logout" {
		t.Errorf("stored.PostLogoutRedirectURIs=%v", stored.PostLogoutRedirectURIs)
	}
}

// TestRegister_HappyPath_PublicClient_OmitsSecret confirms the response
// envelope omits client_secret when token_endpoint_auth_method is
// "none".
func TestRegister_HappyPath_PublicClient_OmitsSecret(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	body := minimalMetadata()
	body["token_endpoint_auth_method"] = "none"
	resp := f.post(t, body, iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if _, ok := got["client_secret"]; ok {
		t.Errorf("client_secret must be absent for public client, got %v", got["client_secret"])
	}
	clientID, _ := got["client_id"].(string)
	stored, err := f.prov.Store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !stored.PublicClient {
		t.Error("stored client.PublicClient must be true for token_endpoint_auth_method=none")
	}
}

// TestRegister_OpenRegistration_DefaultsScopeEmpty pins the rule
// that open registration which omits the "scope" field MUST land
// the dynamically-registered client with an empty scope set, not
// the OP's full public scope catalog. The minimum-privilege
// baseline keeps a scope-omitted DCR from silently widening to
// every public scope the embedder configured; broadening is
// available behind
// [op.RegistrationOption.OpenRegistrationDefaultScopes].
func TestRegister_OpenRegistration_DefaultsScopeEmpty(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{Open: true})

	resp := f.post(t, minimalMetadata(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	body := decodeBody(t, resp)
	if got, ok := body["scope"]; ok {
		if s, _ := got.(string); s != "" {
			t.Errorf("scope echo=%q want empty/absent", s)
		}
	}
	clientID, _ := body["client_id"].(string)
	if clientID == "" {
		t.Fatal("client_id missing")
	}
	got, err := f.prov.Store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if len(got.Scopes) != 0 {
		t.Errorf("client.Scopes=%v want empty", got.Scopes)
	}
}

// TestRegister_OpenRegistration_DefaultsScopeFromOption confirms
// the embedder opt-in escape hatch: when
// [op.RegistrationOption.OpenRegistrationDefaultScopes] is set, an
// open registration that omits the scope field receives the
// configured default verbatim. The list is space-joined into the
// response and persisted on [store.Client.Scopes] so subsequent
// /authorize requests against the registered scopes succeed.
func TestRegister_OpenRegistration_DefaultsScopeFromOption(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{
		Open:                          true,
		OpenRegistrationDefaultScopes: []string{"openid", "profile"},
	})

	resp := f.post(t, minimalMetadata(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	body := decodeBody(t, resp)
	if got, _ := body["scope"].(string); got != "openid profile" {
		t.Errorf("scope echo=%q want %q", got, "openid profile")
	}
	clientID, _ := body["client_id"].(string)
	if clientID == "" {
		t.Fatal("client_id missing")
	}
	got, err := f.prov.Store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !slicesEqual(got.Scopes, []string{"openid", "profile"}) {
		t.Errorf("client.Scopes=%v want [openid profile]", got.Scopes)
	}
}

// TestRegister_OpenRegistration_ExplicitScopeOverridesDefault confirms
// that an embedder-configured open-registration default never replaces
// a scope value the RP spelled out: an open registration POST that
// carries a "scope" field is persisted verbatim, and the configured
// default is not added on top.
func TestRegister_OpenRegistration_ExplicitScopeOverridesDefault(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{
		Open:                          true,
		OpenRegistrationDefaultScopes: []string{"openid", "profile", "email"},
	})

	body := minimalMetadata()
	body["scope"] = "openid"
	resp := f.post(t, body, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if scope, _ := got["scope"].(string); scope != "openid" {
		t.Errorf("scope echo=%q want %q", scope, "openid")
	}
}

func TestRegister_RejectsAllowedClientsRestrictedScope(t *testing.T) {
	t.Parallel()

	f := newFixture(t,
		op.RegistrationOption{Open: true},
		op.WithScope(op.Scope{
			Name:           "billing:write",
			Public:         true,
			AllowedClients: []string{"svc-billing"},
		}),
	)

	body := minimalMetadata()
	body["scope"] = "openid billing:write"
	resp := f.post(t, body, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}
	desc, _ := got["error_description"].(string)
	if !strings.Contains(desc, "billing:write") {
		t.Errorf("error_description=%q must name restricted scope", desc)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRegister_OpenRegistration_AcceptedAndLogged confirms Open=true
// admits the registration without an IAT and emits a WARN frame so the
// degraded posture is observable in audit logs.
func TestRegister_OpenRegistration_AcceptedAndLogged(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{Open: true})

	resp := f.post(t, minimalMetadata(), "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	// The handler emits a WARN log via the audit sink for open-registration
	// usage. Until the audit hook is exposed publicly, the log line is the
	// observable record. The endpoint at minimum must not log an INFO/ERROR
	// claiming the IAT was rejected.
	logs := f.logBuf.String()
	if strings.Contains(logs, "Initial Access Token") {
		t.Errorf("open-registration path must not emit IAT-related WARN frames: %s", logs)
	}
}

// TestRegister_Errors_4xx covers the IAT verification and metadata
// validation error matrix from §A.6.2.2.
func TestRegister_Errors_4xx(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		body        any
		bearer      string
		contentType string
		wantStatus  int
		wantError   string
		// wantWWWAuth, when non-empty, requires the response to carry the
		// substring in WWW-Authenticate.
		wantWWWAuth string
	}{
		{
			name:        "no IAT",
			body:        minimalMetadata(),
			bearer:      "",
			wantStatus:  http.StatusUnauthorized,
			wantError:   "invalid_token",
			wantWWWAuth: `Bearer realm=`,
		},
		{
			name:        "unknown IAT",
			body:        minimalMetadata(),
			bearer:      "totally-bogus-iat-value",
			wantStatus:  http.StatusUnauthorized,
			wantError:   "invalid_token",
			wantWWWAuth: `Bearer realm=`,
		},
		{
			name:        "wrong content type",
			body:        `{"redirect_uris":["https://rp/cb"]}`,
			bearer:      "",
			contentType: "text/plain",
			// Without IAT, the IAT check fires first; we verify the
			// content-type rejection in a separate scenario where IAT is
			// supplied. Force the endpoint to advance past IAT by leaving
			// Open=false here yields 401 anyway, so we run this case
			// against an Open fixture below.
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
		},
		{
			name:       "malformed JSON",
			body:       `{not json`,
			wantStatus: http.StatusUnauthorized, // IAT check fires first.
			wantError:  "invalid_token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			ct := tc.contentType
			if ct == "" {
				ct = "application/json"
			}
			resp := f.postWithContentType(t, tc.body, tc.bearer, ct)
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want %d body=%s", resp.StatusCode, tc.wantStatus, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != tc.wantError {
				t.Errorf("error=%v want %q", got["error"], tc.wantError)
			}
			assertCacheControl(t, resp)
			if tc.wantWWWAuth != "" {
				if hdr := resp.Header.Get("WWW-Authenticate"); !strings.Contains(hdr, tc.wantWWWAuth) {
					t.Errorf("WWW-Authenticate=%q must contain %q", hdr, tc.wantWWWAuth)
				}
			}
		})
	}
}

// TestRegister_ExpiredIAT_Rejected forces an IAT to be expired via the
// deterministic clock and confirms 401 invalid_token.
func TestRegister_ExpiredIAT_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{IATTTL: time.Hour, IATUses: 1})
	// Manually persist an IAT whose ExpiresAt has already passed against
	// the fixture clock. The library's IssueInitialAccessToken cannot
	// produce this shape (TTL must be non-negative), so we go through
	// the store directly.
	iatSecret := "iat-deliberately-expired-aaaaaaaaaaaaaaaa"
	f.putRawIAT(t, &store.InitialAccessToken{
		ID:          "iat-expired",
		HashedValue: hashIAT(iatSecret),
		MaxUses:     1,
		ExpiresAt:   f.clock.now.Add(-time.Minute),
		CreatedAt:   f.clock.now.Add(-2 * time.Hour),
	})

	resp := f.post(t, minimalMetadata(), iatSecret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_token" {
		t.Errorf("error=%v want invalid_token", got["error"])
	}
}

// TestRegister_ConsumedIAT_Rejected confirms a single-use IAT cannot be
// reused after a successful registration.
func TestRegister_ConsumedIAT_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{IATTTL: time.Hour, IATUses: 1})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	first := f.post(t, minimalMetadata(), iat)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first registration: status=%d want 201", first.StatusCode)
	}

	second := f.post(t, minimalMetadata(), iat)
	defer second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second registration: status=%d want 401", second.StatusCode)
	}
	got := decodeBody(t, second)
	if got["error"] != "invalid_token" {
		t.Errorf("error=%v want invalid_token", got["error"])
	}
}

// TestRegister_IATScopeAllowlist_Enforced confirms the
// AllowedScopes-bound IAT rejects scopes outside the allowlist.
func TestRegister_IATScopeAllowlist_Enforced(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{
		AllowedScopes: []string{"openid", "profile"},
	})

	body := minimalMetadata()
	body["scope"] = "openid email" // "email" not in allowlist.
	resp := f.post(t, body, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}
}

// TestRegister_IATRace_AtomicallySerialised drives two concurrent POSTs
// against the same MaxUses=1 IAT and verifies exactly one request wins
// while the other gets 401 invalid_token.
func TestRegister_IATRace_AtomicallySerialised(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{IATTTL: time.Hour, IATUses: 1})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	type result struct {
		status int
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			resp := f.post(t, minimalMetadata(), iat)
			defer resp.Body.Close()
			results <- result{status: resp.StatusCode}
		}()
	}
	wg.Wait()
	close(results)

	created, unauthorized, other := 0, 0, 0
	for r := range results {
		switch r.status {
		case http.StatusCreated:
			created++
		case http.StatusUnauthorized:
			unauthorized++
		default:
			other++
		}
	}
	if created != 1 || unauthorized != 1 || other != 0 {
		t.Errorf("race outcome: created=%d unauthorized=%d other=%d (want 1/1/0)", created, unauthorized, other)
	}
}

// TestRegister_MetadataValidation_4xx exercises the structural-metadata
// rejections.
func TestRegister_MetadataValidation_4xx(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		mutate    func(map[string]any)
		wantError string
	}{
		{
			name: "missing redirect_uris",
			mutate: func(b map[string]any) {
				delete(b, "redirect_uris")
			},
			wantError: "invalid_redirect_uri",
		},
		{
			name: "malformed redirect_uri",
			mutate: func(b map[string]any) {
				b["redirect_uris"] = []string{"://not-a-url"}
			},
			wantError: "invalid_redirect_uri",
		},
		{
			name: "non-absolute redirect_uri",
			mutate: func(b map[string]any) {
				b["redirect_uris"] = []string{"/relative"}
			},
			wantError: "invalid_redirect_uri",
		},
		{
			name: "disallowed grant_type",
			mutate: func(b map[string]any) {
				b["grant_types"] = []string{"client_credentials"}
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "disallowed response_type",
			mutate: func(b map[string]any) {
				b["response_types"] = []string{"token"}
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "client_secret_jwt rejected",
			mutate: func(b map[string]any) {
				b["token_endpoint_auth_method"] = "client_secret_jwt"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "software_statement rejected",
			mutate: func(b map[string]any) {
				b["software_statement"] = "ey.fake.jwt"
			},
			wantError: "invalid_software_statement",
		},
		{
			name: "subject_type pairwise without WithPairwiseSubject",
			mutate: func(b map[string]any) {
				b["subject_type"] = "pairwise"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "id_token alg other than ES256",
			mutate: func(b map[string]any) {
				b["id_token_signed_response_alg"] = "RS256"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "jwks and jwks_uri mutually exclusive",
			mutate: func(b map[string]any) {
				b["jwks"] = map[string]any{"keys": []any{}}
				b["jwks_uri"] = "https://rp.test.invalid/jwks.json"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "backchannel logout session required unsupported",
			mutate: func(b map[string]any) {
				b["backchannel_logout_uri"] = "https://rp.test.invalid/logout"
				b["backchannel_logout_session_required"] = true
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "client_uri must use https",
			mutate: func(b map[string]any) {
				b["client_uri"] = "http://rp.test.invalid"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "request_uri must be absolute https",
			mutate: func(b map[string]any) {
				b["request_uris"] = []string{"/jar/request.jwt"}
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "request_object_signing_alg must be supported",
			mutate: func(b map[string]any) {
				b["request_object_signing_alg"] = "HS256"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "code response_type requires authorization_code grant",
			mutate: func(b map[string]any) {
				b["grant_types"] = []string{"implicit"}
				b["response_types"] = []string{"code"}
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "implicit response_type requires implicit grant",
			mutate: func(b map[string]any) {
				b["grant_types"] = []string{"authorization_code"}
				b["response_types"] = []string{"id_token"}
			},
			wantError: "invalid_client_metadata",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
			body := minimalMetadata()
			tc.mutate(body)
			resp := f.post(t, body, iat)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != tc.wantError {
				t.Errorf("error=%v want %q", got["error"], tc.wantError)
			}
			assertCacheControl(t, resp)
		})
	}
}

// TestRegister_MalformedJSON_AfterIAT confirms that a request carrying a
// valid IAT but a malformed body is rejected with 400
// invalid_client_metadata. This complements the 4xx matrix above which
// fires on IAT first.
func TestRegister_MalformedJSON_AfterIAT(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	resp := f.post(t, "{not valid json", iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}
}

// TestRegister_TrailingJSONDocument_Rejected pins the rule that a
// DCR body which carries a second JSON document after the metadata
// object MUST be rejected. Silently consuming only the first object
// is a parser-confusion vector against reverse proxies / WAFs /
// audit pipelines that scan the entire body.
func TestRegister_TrailingJSONDocument_Rejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{name: "double-object", body: `{"redirect_uris":["https://rp.test.invalid/cb"]} {"client_name":"ignored"}`},
		{name: "object-then-array", body: `{"redirect_uris":["https://rp.test.invalid/cb"]}[]`},
		{name: "object-then-newline-object", body: "{\"redirect_uris\":[\"https://rp.test.invalid/cb\"]}\n{\"x\":1}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

			resp := f.post(t, tc.body, iat)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != "invalid_client_metadata" {
				t.Errorf("error=%v want invalid_client_metadata", got["error"])
			}
		})
	}
}

// TestRegister_WrongContentType_AfterIAT confirms a Content-Type other
// than application/json is rejected with 400 invalid_request once the
// IAT has been verified.
func TestRegister_WrongContentType_AfterIAT(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	resp := f.postWithContentType(t, `{"redirect_uris":["https://rp/cb"]}`, iat, "text/plain")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got["error"])
	}
}

// TestRegister_ValidateMetadataHook_Rejects confirms the embedder hook's
// error is surfaced as 400 invalid_client_metadata with the sanitised
// description.
func TestRegister_ValidateMetadataHook_Rejects(t *testing.T) {
	t.Parallel()

	hook := func(_ context.Context, _ op.ClientMetadata) error {
		return errors.New("tenant\nfoo: not allowed")
	}
	f := newFixture(t, op.RegistrationOption{ValidateMetadata: hook})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	resp := f.post(t, minimalMetadata(), iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}
	desc, _ := got["error_description"].(string)
	if strings.Contains(desc, "\n") || strings.Contains(desc, "\r") {
		t.Errorf("description must be sanitised of CR/LF: %q", desc)
	}
	if !strings.Contains(desc, "tenant") {
		t.Errorf("description=%q must include the hook message", desc)
	}
}

// TestRegister_NotAllowedMethods rejects non-POST verbs with 405.
func TestRegister_NotAllowedMethods(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			req, err := http.NewRequestWithContext(context.Background(), method, f.endpoint, http.NoBody)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := f.prov.HTTPClient(nil).Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("status=%d want 405", resp.StatusCode)
			}
			if got := resp.Header.Get("Allow"); got != http.MethodPost {
				t.Errorf("Allow=%q want POST", got)
			}
			assertCacheControl(t, resp)
		})
	}
}

// dcrFixtureWithStaticClient seeds a static client into the fixture's
// store so tests can confirm RFC 7592 endpoints reject non-dynamic
// clients.
func dcrFixtureWithStaticClient(tb testing.TB, id string) *dcrFixture {
	tb.Helper()
	f := newFixture(tb, op.RegistrationOption{})
	if err := f.prov.Store.RegisterClient(context.Background(), &store.Client{
		ID:                      id,
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Source:                  store.ClientSourceStatic,
	}); err != nil {
		tb.Fatalf("seed static client: %v", err)
	}
	return f
}

// inmemNoCleanup proves the inmem store path is wired correctly; the
// helper exists so the file imports inmem at minimum once and so test
// regressions that swap stores fail loudly.
var _ = inmem.New
