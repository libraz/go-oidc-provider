package tokenendpoint_test

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

	"github.com/libraz/go-oidc-provider/internal/audit"
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

func TestHandleCIBA_ConsumedRecord_InvalidGrant(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-consumed",
		Scope:  []string{"openid"},
		Status: store.CIBARequestStatusPending,
	})
	// Approve then consume to land in the Consumed state.
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-consumed", "user-1", time.Time{}); err != nil {
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
	// CIBA Core §11 reserves expired_token for TTL elapse only;
	// auth_req_id replay maps to invalid_grant per RFC 6749 §5.2,
	// which is what OFCS' fapi-ciba CIBA-11 assertion expects.
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant", got)
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
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-ok", "user-42", time.Time{}); err != nil {
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

// TestHandleCIBA_PollAbuseLockoutThresholdOverride confirms a
// caller-supplied [Deps.CIBAMaxPollViolations] takes precedence over
// the library default. The override exists so conformance harnesses
// (e.g. the OFCS fapi-ciba multiple-call-to-token-endpoint module)
// can exercise the slow_down ladder more times than the default cap
// permits without prematurely tripping the access_denied lockout.
func TestHandleCIBA_PollAbuseLockoutThresholdOverride(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	// Raise the cap above the default so two extra slow_down responses
	// land before the lockout fires; the test then confirms the next
	// poll past the override does fire.
	const overrideCap uint8 = ciba.MaxPollViolations + 2
	f.deps.CIBAMaxPollViolations = overrideCap
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:           "auth-req-override",
		Scope:        []string{"openid"},
		Status:       store.CIBARequestStatusPending,
		Interval:     ciba.DefaultInterval,
		LastPolledAt: ptrTime(f.clock.now.Add(-1 * time.Millisecond)),
	})
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-override")
	for range int(overrideCap) {
		_ = f.store.CIBARequests().RecordPoll(context.Background(), "auth-req-override", f.clock.now.Add(-1*time.Millisecond))
		rec := f.post(t, form)
		if got := cibaDecodeError(t, rec.Body.Bytes()); got != "slow_down" {
			t.Fatalf("error = %q, want slow_down (override cap=%d)", got, overrideCap)
		}
	}
	// One more poll past the override threshold should now lock out.
	_ = f.store.CIBARequests().RecordPoll(context.Background(), "auth-req-override", f.clock.now.Add(-1*time.Millisecond))
	rec := f.post(t, form)
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "access_denied" {
		t.Fatalf("error = %q, want access_denied after override cap exceeded", got)
	}
}

// ptrTime returns &t. The helper exists so the seedCIBARequest
// call sites stay readable; LastPolledAt is *time.Time so an
// embedder can distinguish "never polled" from "polled at the
// epoch".
func ptrTime(t time.Time) *time.Time { return &t }

// recordPollFailingStore wraps an in-memory [store.CIBARequestStore]
// and forces every [store.CIBARequestStore.RecordPoll] call to fail
// with [errInjectedRecordPoll]. The remaining methods delegate to the
// inner substore so the rest of the poll flow behaves exactly like
// the production path. The test that consumes this stub asserts that
// the poll decision still proceeds (fail-open) and that the failure
// is observable as a warn-level audit event.
type recordPollFailingStore struct {
	inner store.CIBARequestStore
}

var errInjectedRecordPoll = errors.New("injected: RecordPoll fault")

func (s recordPollFailingStore) Save(ctx context.Context, req *store.CIBARequest) error {
	return s.inner.Save(ctx, req)
}

func (s recordPollFailingStore) FindByAuthReqID(ctx context.Context, id string) (*store.CIBARequest, error) {
	return s.inner.FindByAuthReqID(ctx, id)
}

func (s recordPollFailingStore) Approve(ctx context.Context, id, subject string, authTime time.Time) error {
	return s.inner.Approve(ctx, id, subject, authTime)
}

func (s recordPollFailingStore) Deny(ctx context.Context, id, reason string) error {
	return s.inner.Deny(ctx, id, reason)
}

func (s recordPollFailingStore) RecordPoll(_ context.Context, _ string, _ time.Time) error {
	return errInjectedRecordPoll
}

func (s recordPollFailingStore) IncrementPollViolation(ctx context.Context, id string) (uint8, error) {
	return s.inner.IncrementPollViolation(ctx, id)
}

func (s recordPollFailingStore) Consume(ctx context.Context, id string) (*store.CIBARequest, error) {
	return s.inner.Consume(ctx, id)
}

// recordingEmitter captures every emitted [audit.Event] in order so
// tests can assert on the warn-level audit record produced by a
// failing RecordPoll. The struct is intentionally not goroutine-safe
// — every test that consumes it drives a single request from the
// foreground.
type recordingEmitter struct {
	events []audit.Event
}

func (e *recordingEmitter) Emit(_ context.Context, ev audit.Event) {
	e.events = append(e.events, ev)
}

// TestHandleCIBA_RecordPollFault_EmitsWarn pins the M3 invariant: a
// transient substore fault on RecordPoll MUST surface as a warn-
// level audit event without short-circuiting the poll decision.
// The fixture wraps the production CIBARequestStore in a stub that
// forces RecordPoll to fail; the wire response is unchanged
// (authorization_pending against a Pending record) and the audit
// stream carries a [ciba.AuditPollObservationFailed] record stamped
// at warn level so SOC tooling can spot a quiet outage that defeats
// the slow_down ladder.
func TestHandleCIBA_RecordPollFault_EmitsWarn(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-poll-fault",
		Scope:  []string{"openid"},
		Status: store.CIBARequestStatusPending,
	})
	emitter := &recordingEmitter{}
	f.deps.Audit = emitter
	f.deps.CIBARequests = recordPollFailingStore{inner: f.store.CIBARequests()}

	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-poll-fault")
	rec := f.post(t, form)

	// (a) the poll decision still proceeds — Pending records yield
	// authorization_pending; the persistence fault MUST NOT change
	// the wire shape.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := cibaDecodeError(t, rec.Body.Bytes()); got != "authorization_pending" {
		t.Fatalf("error = %q, want authorization_pending", got)
	}

	// (b) a warn-level audit entry was emitted naming the failed
	// observation. Search rather than indexing because the handler
	// also emits AuditTokenRejected for the wire response.
	var found *audit.Event
	for i := range emitter.events {
		ev := emitter.events[i]
		if ev.Name == ciba.AuditPollObservationFailed {
			found = &ev
			break
		}
	}
	if found == nil {
		t.Fatalf("expected audit event %q; got %v", ciba.AuditPollObservationFailed, eventNames(emitter.events))
	}
	if found.Level != audit.LevelWarn {
		t.Errorf("event level = %v, want LevelWarn", found.Level)
	}
	if found.ClientID != f.client.ID {
		t.Errorf("event client_id = %q, want %q", found.ClientID, f.client.ID)
	}
	gotErr, _ := found.Extras["error"].(string)
	if gotErr == "" {
		t.Errorf("extras.error empty; want stringified store error")
	}
}

// TestHandleCIBA_IDTokenStampsAuthTime pins the auth_time wiring:
// the wall-clock value the substore stamped at Approve flows
// through the grant-side Authorized struct and onto the issued
// id_token's auth_time claim. The substore-zero arm is covered by
// TestHandleCIBA_RequireAuthTime_MissingAuthTimeFails.
func TestHandleCIBA_IDTokenStampsAuthTime(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	authTime := f.clock.now.Add(-30 * time.Second).UTC()
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-at",
		Scope:  []string{"openid"},
		Status: store.CIBARequestStatusPending,
	})
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-at", "user-7", authTime); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-at")
	rec := f.post(t, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	claims := decodeIDTokenClaims(t, body.IDToken)
	got, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time absent or wrong type: %v", claims["auth_time"])
	}
	if int64(got) != authTime.Unix() {
		t.Errorf("auth_time = %d, want %d", int64(got), authTime.Unix())
	}
}

// TestHandleCIBA_RequireAuthTime_MissingAuthTimeFails pins the
// gate that protects clients that set RequireAuthTime: when the
// substore returns a zero AuthTime (legacy record / embedder did
// not pass one) the issuance path MUST refuse to mint the id_token
// rather than emit a claim-less response that satisfies the
// per-client "auth_time required" contract by silent omission.
func TestHandleCIBA_RequireAuthTime_MissingAuthTimeFails(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	updated := *f.client
	updated.RequireAuthTime = true
	if err := f.store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:     "auth-req-need-at",
		Scope:  []string{"openid"},
		Status: store.CIBARequestStatusPending,
	})
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-need-at", "user-x", time.Time{}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-need-at")
	rec := f.post(t, form)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleCIBA_IDTokenStampsACRWithoutAMR pins the acr/amr
// contract on the CIBA-issued id_token: when the persisted record
// carries one or more requested ACR values, the issued id_token
// stamps acr from the first entry and MUST NOT synthesise amr
// from the same slice. acr names the authentication context class
// (OIDC Core 1.0 §2) and amr names the authentication methods
// used; the two are not synonyms, and the substore does not yet
// retain a real authentication-method signal so amr stays absent.
func TestHandleCIBA_IDTokenStampsACRWithoutAMR(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:        "auth-req-acr",
		Scope:     []string{"openid"},
		Status:    store.CIBARequestStatusPending,
		ACRValues: []string{"urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"},
	})
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-acr", "user-42", time.Time{}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-acr")
	rec := f.post(t, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.IDToken == "" {
		t.Fatalf("id_token missing: %s", rec.Body.String())
	}
	claims := decodeIDTokenClaims(t, body.IDToken)
	if got, _ := claims["acr"].(string); got != "urn:mace:incommon:iap:bronze" {
		t.Errorf("acr = %q, want urn:mace:incommon:iap:bronze", got)
	}
	if _, present := claims["amr"]; present {
		t.Errorf("amr MUST be absent (substore does not retain authentication methods); got %v", claims["amr"])
	}
}

// eventNames flattens an [audit.Event] slice to its Name fields.
// The helper exists so a failing assertion on a missing event can
// print a compact list of what WAS emitted instead of dumping the
// full audit struct.
func eventNames(events []audit.Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.Name)
	}
	return out
}
