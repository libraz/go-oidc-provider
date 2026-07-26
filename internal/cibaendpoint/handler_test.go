package cibaendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fakeResolver is a deterministic [cibaendpoint.HintResolver] for the
// test suite. Set Subject for the success path, Err for the failure
// path.
type fakeResolver struct {
	subject string
	err     error
}

func (f fakeResolver) Resolve(_ context.Context, _ ciba.HintKind, _ string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.subject, nil
}

const (
	testClientID     = "client-ciba"
	testClientSecret = "shh-its-a-secret"
)

// Wire codes the handler emits. Mirrored verbatim from
// internal/cibaendpoint/error.go because the test package cannot
// reach the unexported constants.
const (
	wireInvalidRequest        = "invalid_request"
	wireInvalidScope          = "invalid_scope"
	wireUnauthorizedClient    = "unauthorized_client"
	wireUnknownUserID         = "unknown_user_id"
	wireInvalidBindingMessage = "invalid_binding_message"
	wireLoginRequired         = "login_required"
	wireInvalidClient         = "invalid_client"
)

// successBody is the §7.3 backchannel-authentication response shape
// the test decodes. Mirrors the unexported handler value verbatim.
type successBody struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  int64  `json:"interval"`
}

// fixedClock yields a deterministic Now() reading.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// newTestStore seeds an [inmem.Store] with a single confidential
// client registered for the CIBA grant.
func newTestStore(t *testing.T, c fixedClock) *inmem.Store {
	return newTestStoreWithResources(t, c)
}

// newTestStoreWithResources seeds the test store and additionally
// registers the supplied resource indicators on the client's
// Resources allowlist. The CIBA endpoint enforces that allowlist on
// the resource= form parameter, so tests that exercise the resource
// pipeline must seed the values they intend to send.
func newTestStoreWithResources(t *testing.T, c fixedClock, resources ...string) *inmem.Store {
	t.Helper()
	s := inmem.New(inmem.WithClock(c))
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	if err := s.RegisterClient(context.Background(), &store.Client{
		ID:                      testClientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"urn:openid:params:grant-type:ciba"},
		Scopes:                  []string{"openid", "profile", "email"},
		Resources:               append([]string(nil), resources...),
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	return s
}

// newDeps builds a [cibaendpoint.Deps] tied to s. Tests override
// individual fields after the call when they need a non-default
// behaviour.
func newDeps(s *inmem.Store, c fixedClock) cibaendpoint.Deps {
	return cibaendpoint.Deps{
		Issuer:       "https://op.example",
		Clients:      s,
		CIBARequests: s.CIBARequests(),
		Clock:        c,
		HintResolver: fakeResolver{subject: "user-123"},
	}
}

func newCIBATestStoreWithScopes(t *testing.T, c fixedClock, scopes []string) *inmem.Store {
	t.Helper()
	s := inmem.New(inmem.WithClock(c))
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	if err := s.RegisterClient(context.Background(), &store.Client{
		ID:                      testClientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"urn:openid:params:grant-type:ciba"},
		Scopes:                  append([]string(nil), scopes...),
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	return s
}

// newRequest builds a /bc-authorize POST. The caller threads
// extra parameters via form (passing nil applies the canonical
// minimal-success body). Client authentication rides on HTTP
// Basic so the seeded "client_secret_basic" registration matches
// the parsed credential method.
func newRequest(form url.Values) *http.Request {
	if form == nil {
		form = url.Values{}
		form.Set("scope", "openid")
		form.Set("login_hint", "user@example")
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testClientSecret)
	return req
}

func decodeError(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v: %s", err, body)
	}
	return env.Error
}

func TestServe_ScopeAllowedClientsRejected(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	store := newCIBATestStoreWithScopes(t, clock, []string{"openid", "billing:write"})
	deps := newDeps(store, clock)
	deps.Scopes = scoperegistry.New([]scoperegistry.Entry{
		{Name: "billing:write", Public: true, AllowedClients: []string{"svc-billing"}},
	})
	form := url.Values{}
	form.Set("scope", "openid billing:write")
	form.Set("login_hint", "user@example")
	rec := httptest.NewRecorder()

	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidScope {
		t.Fatalf("error = %q, want %q", got, wireInvalidScope)
	}
}

// TestServe_NilSubstoreDoesNotPanic exercises the defence-in-depth
// guard: the package-level Handler can be constructed with a nil
// CIBARequests substore (op.New rejects this configuration, but a
// caller who bypassed op.New still must not crash the process).
// The handler MUST surface 500 server_error rather than panic on
// the eventual Save call.
func TestServe_NilSubstoreDoesNotPanic(t *testing.T) {
	t.Parallel()
	deps := cibaendpoint.Deps{
		Issuer:       "https://op.example",
		Clients:      newTestStore(t, fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}),
		CIBARequests: nil,
		Clock:        fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)},
		HintResolver: fakeResolver{subject: "user-123"},
	}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != "server_error" {
		t.Fatalf("error = %q, want server_error", got)
	}
}

func TestServe_RejectsNonPOST(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/bc-authorize", nil)
	cibaendpoint.Handler(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("Allow header = %q, want POST", rec.Header().Get("Allow"))
	}
}

func TestServe_RejectsNonForm(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/bc-authorize", strings.NewReader(`{"scope":"openid"}`))
	req.Header.Set("Content-Type", "application/json")
	cibaendpoint.Handler(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

func TestServe_RejectsUnknownClient(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	rec := httptest.NewRecorder()
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "user@example")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("unknown-client", testClientSecret)
	cibaendpoint.Handler(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidClient {
		t.Fatalf("error = %q, want %q", got, wireInvalidClient)
	}
}

func TestServe_RejectsClientWithoutCIBAGrant(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	if err := s.RegisterClient(context.Background(), &store.Client{
		ID:                      testClientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid"},
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	deps := newDeps(s, clock)
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireUnauthorizedClient {
		t.Fatalf("error = %q, want %q", got, wireUnauthorizedClient)
	}
}

func TestServe_RejectsHintCombinationZero(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

func TestServe_RejectsHintCombinationMultiple(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("id_token_hint", "ey...")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

func TestServe_UnknownUser(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.HintResolver = fakeResolver{err: cibaendpoint.ErrUnknownUser}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireUnknownUserID {
		t.Fatalf("error = %q, want %q", got, wireUnknownUserID)
	}
}

func TestServe_HintResolutionFailure(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.HintResolver = fakeResolver{err: errors.New("backend exploded")}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireLoginRequired {
		t.Fatalf("error = %q, want %q", got, wireLoginRequired)
	}
}

func TestServe_RejectsMissingScope(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("login_hint", "alice")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

func TestServe_RejectsScopeMissingOpenID(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "profile")
	form.Set("login_hint", "alice")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidScope {
		t.Fatalf("error = %q, want %q", got, wireInvalidScope)
	}
}

func TestServe_RejectsBindingMessageTooLong(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("binding_message", strings.Repeat("a", 51))
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidBindingMessage {
		t.Fatalf("error = %q, want %q", got, wireInvalidBindingMessage)
	}
}

func TestServe_RejectsBindingMessageControlChar(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("binding_message", "pay\nnow")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidBindingMessage {
		t.Fatalf("error = %q, want %q", got, wireInvalidBindingMessage)
	}
}

func TestServe_RejectsRequestedExpiryNonNumeric(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("requested_expiry", "abc")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

func TestServe_HappyPath(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid profile")
	form.Set("login_hint", "alice")
	form.Set("binding_message", `hello & <welcome> "friend"`)
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.AuthReqID) <= 16 {
		t.Fatalf("auth_req_id = %q, want > 16 chars", body.AuthReqID)
	}
	if body.ExpiresIn != int64(ciba.DefaultExpiresIn.Seconds()) {
		t.Fatalf("expires_in = %d, want %d", body.ExpiresIn, int64(ciba.DefaultExpiresIn.Seconds()))
	}
	if body.Interval != int64(ciba.DefaultInterval.Seconds()) {
		t.Fatalf("interval = %d, want %d", body.Interval, int64(ciba.DefaultInterval.Seconds()))
	}
	rec2, err := s.CIBARequests().FindByAuthReqID(context.Background(), body.AuthReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if rec2.Subject != "user-123" {
		t.Fatalf("subject = %q, want user-123", rec2.Subject)
	}
	if rec2.BindingMessage != `hello & <welcome> "friend"` {
		t.Fatalf("binding_message = %q, want raw (unescaped) round-trip through validation + store", rec2.BindingMessage)
	}
	if rec2.Status != store.CIBARequestStatusPending {
		t.Fatalf("status = %v, want pending", rec2.Status)
	}
}

func TestServe_HonoursRequestedExpiryClamp(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.MaxExpiresIn = 600 * time.Second
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("requested_expiry", "7200")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ExpiresIn != 600 {
		t.Fatalf("expires_in = %d, want 600", body.ExpiresIn)
	}
}

// TestServe_RejectsDuplicateSingleValuedParams pins the RFC 6749
// §3.2 "MUST NOT include more than once" rule for the CIBA Core 1.0
// §7.1 single-valued parameters. /authorize and /token enforce this
// at parse time; /bc-authorize previously accepted duplicates by
// silently picking one. The handler now rejects with 400
// invalid_request before classifying the hint or parsing scope so
// the wire contract matches the other OAuth endpoints uniformly.
//
// "resource" is intentionally omitted from this table — RFC 8707 §2
// permits the resource indicator to repeat on the wire. The handler
// rejects multi-resource with invalid_target (the issuance pipeline
// honours a single audience entry); see [TestServe_RejectsMultiResource].
func TestServe_RejectsDuplicateSingleValuedParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		param string
		other string
	}{
		{name: "login_hint", param: "login_hint", other: "bob"},
		{name: "binding_message", param: "binding_message", other: "stop"},
		{name: "acr_values", param: "acr_values", other: "urn:mace:incommon:iap:silver"},
		{name: "requested_expiry", param: "requested_expiry", other: "120"},
		{name: "id_token_hint", param: "id_token_hint", other: "ey..."},
		{name: "login_hint_token", param: "login_hint_token", other: "ey..."},
		{name: "user_code", param: "user_code", other: "5678"},
		{name: "client_notification_token", param: "client_notification_token", other: "tok-2"},
		{name: "request", param: "request", other: "ey..."},
	}
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newTestStore(t, clock)
			deps := newDeps(s, clock)
			form := url.Values{}
			form.Set("scope", "openid")
			form.Set("login_hint", "alice")
			// Override single-value defaults the helper seeded so the
			// duplicate is the only ambiguity in the request.
			if tc.param == "login_hint" {
				form.Del("login_hint")
			}
			form.Add(tc.param, "first")
			form.Add(tc.param, tc.other)
			rec := httptest.NewRecorder()
			cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
				t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
			}
		})
	}
}

func TestServe_RejectsClientNotificationToken(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("client_notification_token", "client-callback-token")

	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error=%q want %q", got, wireInvalidRequest)
	}
}

// TestServe_RejectsDuplicateScope pins that the space-delimited
// "scope" parameter is single-occurrence on the wire even though
// each occurrence is itself a list. RFC 6749 §3.3 mandates the
// space-delimited representation; admitting two scope= entries would
// require the OP to choose a merge policy, which the spec does not
// define. Reject uniformly.
func TestServe_RejectsDuplicateScope(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Add("scope", "openid")
	form.Add("scope", "openid profile")
	form.Set("login_hint", "alice")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

// TestServe_FAPICIBARejectsRequestedExpiryAboveTenMinutes pins the
// FAPI-CIBA-ID1 §5 / FAPI 2.0 §3.1.9 hard-reject posture: under the
// FAPI-CIBA profile the ten-minute auth_req_id lifetime cap is a
// MUST, so any requested_expiry above 600s surfaces as 400
// invalid_request with a description naming the cap rather than
// being clamped silently. CIBA-044.
func TestServe_FAPICIBARejectsRequestedExpiryAboveTenMinutes(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.FAPICIBAProfileActive = true
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("requested_expiry", "601")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
	if !strings.Contains(rec.Body.String(), "FAPI-CIBA 10-minute cap") {
		t.Fatalf("body must name the FAPI-CIBA cap; got %s", rec.Body.String())
	}
}

// TestServe_FAPICIBAAcceptsRequestedExpiryAtBoundary pins the
// inclusive boundary of the FAPI-CIBA cap: requested_expiry=600 is
// the maximum permitted under the profile and MUST succeed.
// CIBA-044 boundary.
func TestServe_FAPICIBAAcceptsRequestedExpiryAtBoundary(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.FAPICIBAProfileActive = true
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("requested_expiry", "600")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ExpiresIn != 600 {
		t.Fatalf("expires_in = %d, want 600", body.ExpiresIn)
	}
}

// TestServe_VanillaCIBAClampsRequestedExpiry pins the non-FAPI
// posture: with the FAPI-CIBA profile inactive, requested_expiry
// above the configured MaxExpiresIn is clamped silently rather than
// rejected. The clamp is the legacy CIBA Core §7.1 behaviour and
// MUST stay intact for vanilla deployments. CIBA-044 negative.
func TestServe_VanillaCIBAClampsRequestedExpiry(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.MaxExpiresIn = 600 * time.Second
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("requested_expiry", "86400")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ExpiresIn != 600 {
		t.Fatalf("expires_in = %d, want 600 (clamped)", body.ExpiresIn)
	}
}

// TestServe_RejectsACRValueNotAdvertised pins the OIDC Core 1.0
// §3.1.2.1 + CIBA Core §7.1 acr_values gate: when the OP advertises
// `acr_values_supported`, any client-requested value outside that
// list MUST be rejected with 400 invalid_request. Without the gate
// a client can drive the issued id_token's `acr` claim to an
// arbitrary string the operator never enrolled. CIBA-045.
func TestServe_RejectsACRValueNotAdvertised(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.ACRValuesSupported = []string{"urn:mace:incommon:iap:bronze"}
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("acr_values", "urn:not-supported")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
	if !strings.Contains(rec.Body.String(), "acr_values_supported") {
		t.Fatalf("body must name the advertised list; got %s", rec.Body.String())
	}
}

// TestServe_AcceptsACRValueAdvertised pins the positive arm of the
// acr_values gate: a value present in [Deps.ACRValuesSupported] is
// accepted and stamped onto the persisted record. CIBA-045 positive.
func TestServe_AcceptsACRValueAdvertised(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	deps.ACRValuesSupported = []string{"urn:mace:incommon:iap:bronze"}
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("acr_values", "urn:mace:incommon:iap:bronze")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	persisted, err := s.CIBARequests().FindByAuthReqID(context.Background(), body.AuthReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if len(persisted.ACRValues) != 1 || persisted.ACRValues[0] != "urn:mace:incommon:iap:bronze" {
		t.Fatalf("persisted ACRValues = %v, want [urn:mace:incommon:iap:bronze]", persisted.ACRValues)
	}
}

// TestServe_RejectsUserCodeWhenUnsupported pins the discovery
// consistency gate for `backchannel_user_code_parameter_supported`:
// the default discovery shape advertises the parameter as
// unsupported, and CIBA Core 1.0 §7.1 mandates the client refrain
// from sending parameters the OP has not advertised. Any non-empty
// `user_code` MUST therefore surface as 400 invalid_request.
// CIBA-046.
func TestServe_RejectsUserCodeWhenUnsupported(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("user_code", "12345678")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
	if !strings.Contains(rec.Body.String(), "user_code parameter is not supported") {
		t.Fatalf("body must name the user_code rejection reason; got %s", rec.Body.String())
	}
}

// TestServe_AcceptsAbsentUserCode pins the negative arm of the
// user_code gate: a request without the parameter (or with an empty
// value) MUST proceed. CIBA-046 positive.
func TestServe_AcceptsAbsentUserCode(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestServe_RejectsMultiResource pins the issuance contract: the
// CIBA pipeline honours a single audience entry, so multi-resource
// requests are refused at the parse step with invalid_target rather
// than silently truncated downstream. The check fires before
// allowlist matching, so even two registered audiences are
// rejected.
func TestServe_RejectsMultiResource(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStoreWithResources(t, clock,
		"https://api-a.example", "https://api-b.example")
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Add("resource", "https://api-a.example/")
	form.Add("resource", "https://api-b.example/")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != "invalid_target" {
		t.Fatalf("error = %q, want invalid_target", got)
	}
}

// TestServe_AdmitsRegisteredResource verifies that a single resource
// indicator that matches the client's registered Resources allowlist
// flows through the parse step and is persisted on the CIBA record
// in canonical form.
func TestServe_AdmitsRegisteredResource(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStoreWithResources(t, clock, "https://api.example")
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("resource", "https://api.example/")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	persisted, err := s.CIBARequests().FindByAuthReqID(context.Background(), body.AuthReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if len(persisted.Resource) != 1 || persisted.Resource[0] != "https://api.example" {
		t.Fatalf("persisted Resource = %v, want [https://api.example]", persisted.Resource)
	}
}

// TestServe_RejectsUnregisteredResource pins that a request carrying
// a resource that is not in the client's Resources allowlist is
// refused with invalid_target — even if the value is a syntactically
// valid absolute URI.
func TestServe_RejectsUnregisteredResource(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStoreWithResources(t, clock, "https://api-allowed.example")
	deps := newDeps(s, clock)
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice")
	form.Set("resource", "https://api-other.example/")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != "invalid_target" {
		t.Fatalf("error = %q, want invalid_target", got)
	}
}
