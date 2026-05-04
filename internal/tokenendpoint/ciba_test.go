package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// cibaFixture seeds an in-memory store with a CIBA-grant client and
// builds the [tokenendpoint.Deps] under test. The substore field is
// left nil by default so callers exercising the
// "unsupported_grant_type" branch can omit it; helpers that need the
// substore call [withCIBAStore].
type cibaFixture struct {
	deps   tokenendpoint.Deps
	store  *inmem.Store
	clock  fixedClock
	client *store.Client
	secret string
}

const cibaTestClientID = "client-ciba-tokenendpoint"

// newCIBAFixture builds a fixture pinned to a deterministic clock.
// The CIBARequests substore is pre-wired by default; tests that
// exercise the nil-substore branch zero out the field after the
// call.
func newCIBAFixture(t *testing.T) *cibaFixture {
	t.Helper()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash("ciba-secret")
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      cibaTestClientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"urn:openid:params:grant-type:ciba", "refresh_token"},
		Scopes:                  []string{"openid", "profile"},
	}
	if err := s.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	entry, err := keys.GenerateES256("ciba-test-kid")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	deps := tokenendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       s,
		Codes:         s.AuthorizationCodes(),
		RefreshTokens: s.RefreshTokens(),
		Grants:        s.Grants(),
		UserStore:     s.Users(),
		Keys:          keySet,
		Clock:         clock,
		AccessTokens:  s.AccessTokens(),
		CIBARequests:  s.CIBARequests(),
	}
	return &cibaFixture{
		deps:   deps,
		store:  s,
		clock:  clock,
		client: client,
		secret: "ciba-secret",
	}
}

// seedCIBARequest persists a [store.CIBARequest] directly. The
// helper fills in defaults so each test only sets the fields it
// cares about.
func (f *cibaFixture) seedCIBARequest(t *testing.T, rec *store.CIBARequest) {
	t.Helper()
	if rec.ClientID == "" {
		rec.ClientID = f.client.ID
	}
	if rec.IssuedAt.IsZero() {
		rec.IssuedAt = f.clock.now
	}
	if rec.ExpiresAt.IsZero() {
		rec.ExpiresAt = f.clock.now.Add(10 * time.Minute)
	}
	if rec.Interval == 0 {
		rec.Interval = ciba.DefaultInterval
	}
	if rec.Status == 0 {
		rec.Status = store.CIBARequestStatusPending
	}
	if err := f.store.CIBARequests().Save(context.Background(), rec); err != nil {
		t.Fatalf("CIBARequests.Save: %v", err)
	}
}

// post issues a /token POST against [tokenendpoint.Handler] with
// the supplied form. The client is authenticated via Basic auth
// using the fixture's seeded credentials.
func (f *cibaFixture) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ID, f.secret)
	rec := httptest.NewRecorder()
	tokenendpoint.Handler(f.deps).ServeHTTP(rec, req)
	return rec
}

func cibaDecodeError(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v: %s", err, body)
	}
	return env.Error
}

func TestHandleCIBA_NilSubstore_RejectsUnsupportedGrantType(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.deps.CIBARequests = nil
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "anything")
	rec := f.post(t, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "unsupported_grant_type" {
		t.Fatalf("error = %q, want unsupported_grant_type", got)
	}
}

func TestHandleCIBA_PendingPoll_AuthorizationPending(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-pending",
		Scope:  []string{"openid"},
		Status: store.CIBARequestStatusPending,
	})
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-pending")
	rec := f.post(t, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "authorization_pending" {
		t.Fatalf("error = %q, want authorization_pending", got)
	}
}

func TestHandleCIBA_DeniedRecord_AccessDenied(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-denied",
		Scope:  []string{"openid"},
		Status: store.CIBARequestStatusPending,
	})
	if err := f.store.CIBARequests().Deny(context.Background(), "auth-req-denied", "user_denied"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-denied")
	rec := f.post(t, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "access_denied" {
		t.Fatalf("error = %q, want access_denied", got)
	}
}

func TestHandleCIBA_ConsumedRecord_ExpiredToken(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-consumed",
		Scope:  []string{"openid"},
		Status: store.CIBARequestStatusPending,
	})
	// Approve then consume to land in the Consumed state.
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-consumed", "user-1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := f.store.CIBARequests().Consume(context.Background(), "auth-req-consumed"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-consumed")
	rec := f.post(t, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "expired_token" {
		t.Fatalf("error = %q, want expired_token", got)
	}
}

func TestHandleCIBA_ApprovedRecord_HappyPath(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-ok",
		Scope:  []string{"openid", "profile"},
		Status: store.CIBARequestStatusPending,
	})
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-ok", "user-42"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-ok")
	rec := f.post(t, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Scope       string `json:"scope"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.AccessToken == "" {
		t.Fatalf("access_token is empty")
	}
	if body.IDToken == "" {
		t.Fatalf("id_token is empty")
	}
	if body.Scope != "openid profile" {
		t.Fatalf("scope = %q, want %q", body.Scope, "openid profile")
	}
	if body.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", body.TokenType)
	}
}

func TestHandleCIBA_PollAbuseLockout(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:           "auth-req-abuse",
		Scope:        []string{"openid"},
		Status:       store.CIBARequestStatusPending,
		Interval:     ciba.DefaultInterval,
		LastPolledAt: ptrTime(f.clock.now.Add(-1 * time.Millisecond)),
	})
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-abuse")
	// Drive enough slow_down responses to saturate the strike counter.
	for range int(ciba.MaxPollViolations) {
		// Re-seed LastPolledAt to a value inside the slow_down floor
		// so each poll counts as a violation.
		_ = f.store.CIBARequests().RecordPoll(context.Background(), "auth-req-abuse", f.clock.now.Add(-1*time.Millisecond))
		rec := f.post(t, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
		if got := cibaDecodeError(t, rec.Body.Bytes()); got != "slow_down" {
			t.Fatalf("error = %q, want slow_down", got)
		}
	}
	// The next poll should observe the locked record.
	_ = f.store.CIBARequests().RecordPoll(context.Background(), "auth-req-abuse", f.clock.now.Add(-1*time.Millisecond))
	rec := f.post(t, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "access_denied" {
		t.Fatalf("error = %q, want access_denied (record should be locked)", got)
	}
}

// ptrTime returns &t. The helper exists so the seedCIBARequest
// call sites stay readable; LastPolledAt is *time.Time so an
// embedder can distinguish "never polled" from "polled at the
// epoch".
func ptrTime(t time.Time) *time.Time { return &t }
