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
	wireInvalidRequestObject  = "invalid_request_object"
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
	form.Set("binding_message", "hello & welcome")
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
	if rec2.BindingMessage != "hello &amp; welcome" {
		t.Fatalf("binding_message = %q, want HTML-escaped", rec2.BindingMessage)
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
