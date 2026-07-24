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
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// devCodeGrantURN is the wire form of the device_code grant. Mirrors
// the constant style used by the CIBA fixture in this package.
const devCodeGrantURN = "urn:ietf:params:oauth:grant-type:device_code"

const devCodeTestClientID = "client-devicecode-tokenendpoint"

// deviceCodeFixture seeds an in-memory store with a device_code-grant
// client and builds the [tokenendpoint.Deps] under test. Mirrors
// [cibaFixture] in ciba_test.go.
type deviceCodeFixture struct {
	deps   tokenendpoint.Deps
	store  *inmem.Store
	clock  fixedClock
	client *store.Client
	secret string
}

// newDeviceCodeFixture builds a fixture pinned to a deterministic
// clock with the DeviceCodes substore pre-wired.
func newDeviceCodeFixture(t *testing.T) *deviceCodeFixture {
	t.Helper()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash("devicecode-secret")
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      devCodeTestClientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{devCodeGrantURN, "refresh_token"},
		Scopes:                  []string{"openid", "profile"},
	}
	if err := s.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	entry, err := keys.GenerateES256("devicecode-test-kid")
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
		DeviceCodes:   s.DeviceCodes(),
	}
	return &deviceCodeFixture{ //nolint:gosec // G101: test fixture secret, not a real credential.
		deps:   deps,
		store:  s,
		clock:  clock,
		client: client,
		secret: "devicecode-secret",
	}
}

// seedDeviceCode persists a [store.DeviceCode] directly. The helper
// fills in defaults so each test only sets the fields it cares about.
func (f *deviceCodeFixture) seedDeviceCode(t *testing.T, rec *store.DeviceCode) {
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
		rec.Interval = devicecode.DefaultInterval
	}
	if rec.Status == 0 {
		rec.Status = store.DeviceCodeStatusPending
	}
	if err := f.store.DeviceCodes().Save(context.Background(), rec); err != nil {
		t.Fatalf("DeviceCodes.Save: %v", err)
	}
}

// post issues a /token POST against [tokenendpoint.Handler] with the
// supplied form. The client is authenticated via Basic auth using the
// fixture's seeded credentials.
func (f *deviceCodeFixture) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ID, f.secret)
	rec := httptest.NewRecorder()
	tokenendpoint.Handler(f.deps).ServeHTTP(rec, req)
	return rec
}

func deviceCodeDecodeError(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v: %s", err, body)
	}
	return env.Error
}

// recordPollFailingDeviceCodeStore wraps an in-memory
// [store.DeviceCodeStore] and forces every RecordPoll call to fail
// with [errInjectedDeviceCodeRecordPoll]. The remaining methods
// delegate to the inner substore so the rest of the poll flow behaves
// exactly like the production path. Mirrors [recordPollFailingStore]
// in ciba_test.go for the device-flow surface.
type recordPollFailingDeviceCodeStore struct {
	inner store.DeviceCodeStore
}

// failFirstAccessTokenRegistry injects the persist-after-sign fault that used
// to occur after Device/CIBA Consume. It lets both grant tests prove that the
// approval remains retryable now that assembly runs before the consume CAS.
type failFirstAccessTokenRegistry struct {
	inner store.AccessTokenRegistry
	fail  bool
}

var errInjectedAccessTokenRegister = errors.New("injected: access token Register fault")

func (s *failFirstAccessTokenRegistry) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	if s.fail {
		s.fail = false
		return errInjectedAccessTokenRegister
	}
	return s.inner.Register(ctx, rec)
}

func (s *failFirstAccessTokenRegistry) Find(ctx context.Context, jti string) (*store.AccessTokenRecord, error) {
	return s.inner.Find(ctx, jti)
}

func (s *failFirstAccessTokenRegistry) RevokeByJTI(ctx context.Context, jti string) error {
	return s.inner.RevokeByJTI(ctx, jti)
}

func (s *failFirstAccessTokenRegistry) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	return s.inner.RevokeByGrant(ctx, grantID)
}

func (s *failFirstAccessTokenRegistry) GC(ctx context.Context, cutoff time.Time) (int, error) {
	return s.inner.GC(ctx, cutoff)
}

var errInjectedDeviceCodeRecordPoll = errors.New("injected: RecordPoll fault")

func (s recordPollFailingDeviceCodeStore) Save(ctx context.Context, code *store.DeviceCode) error {
	return s.inner.Save(ctx, code)
}

func (s recordPollFailingDeviceCodeStore) FindByDeviceCode(ctx context.Context, deviceCode string) (*store.DeviceCode, error) {
	return s.inner.FindByDeviceCode(ctx, deviceCode)
}

func (s recordPollFailingDeviceCodeStore) FindByUserCode(ctx context.Context, userCode string) (*store.DeviceCode, error) {
	return s.inner.FindByUserCode(ctx, userCode)
}

func (s recordPollFailingDeviceCodeStore) Approve(ctx context.Context, deviceCode, subject string, authTime time.Time) error {
	return s.inner.Approve(ctx, deviceCode, subject, authTime)
}

func (s recordPollFailingDeviceCodeStore) ApproveByUserCode(ctx context.Context, userCode, subject string, authTime time.Time) error {
	return s.inner.ApproveByUserCode(ctx, userCode, subject, authTime)
}

func (s recordPollFailingDeviceCodeStore) Deny(ctx context.Context, deviceCode, reason string) error {
	return s.inner.Deny(ctx, deviceCode, reason)
}

func (s recordPollFailingDeviceCodeStore) DenyByUserCode(ctx context.Context, userCode, reason string) error {
	return s.inner.DenyByUserCode(ctx, userCode, reason)
}

func (s recordPollFailingDeviceCodeStore) Revoke(ctx context.Context, deviceCode, reason string) error {
	return s.inner.Revoke(ctx, deviceCode, reason)
}

func (s recordPollFailingDeviceCodeStore) RecordPoll(_ context.Context, _ string, _ time.Time, _ time.Duration) error {
	return errInjectedDeviceCodeRecordPoll
}

func (s recordPollFailingDeviceCodeStore) IncrementUserCodeStrike(ctx context.Context, deviceCode string) (uint8, error) {
	return s.inner.IncrementUserCodeStrike(ctx, deviceCode)
}

func (s recordPollFailingDeviceCodeStore) IncrementUserCodeStrikeByUserCode(ctx context.Context, userCode string) (uint8, error) {
	return s.inner.IncrementUserCodeStrikeByUserCode(ctx, userCode)
}

func (s recordPollFailingDeviceCodeStore) IncrementPollViolation(ctx context.Context, deviceCode string) (uint8, error) {
	return s.inner.IncrementPollViolation(ctx, deviceCode)
}

func (s recordPollFailingDeviceCodeStore) Consume(ctx context.Context, deviceCode string) (*store.DeviceCode, error) {
	return s.inner.Consume(ctx, deviceCode)
}

// deviceCodeRecordingEmitter captures every emitted [audit.Event] in
// order so tests can assert on the warn-level audit record produced
// by a failing RecordPoll.
type deviceCodeRecordingEmitter struct {
	events []audit.Event
}

func (e *deviceCodeRecordingEmitter) Emit(_ context.Context, ev audit.Event) {
	e.events = append(e.events, ev)
}

// TestHandleDeviceCode_RecordPollFault_EmitsWarn pins the symmetry
// invariant with the CIBA grant's applyCIBAPollDecision: a transient
// substore fault on RecordPoll MUST surface as a warn-level audit
// event without short-circuiting the poll decision. The fixture wraps
// the production DeviceCodeStore in a stub that forces RecordPoll to
// fail; the wire response is unchanged (authorization_pending against
// a Pending record) and the audit stream carries a
// [devicecode.AuditPollObservationFailed] record stamped at warn
// level so SOC tooling can spot a quiet outage that defeats the
// slow_down ladder.
func TestHandleDeviceCode_RecordPollFault_EmitsWarn(t *testing.T) {
	t.Parallel()
	f := newDeviceCodeFixture(t)
	f.seedDeviceCode(t, &store.DeviceCode{
		ID:       "device-code-poll-fault",
		UserCode: "AAAA-BBBB",
		Scope:    []string{"openid"},
		Status:   store.DeviceCodeStatusPending,
	})
	emitter := &deviceCodeRecordingEmitter{}
	f.deps.Audit = emitter
	f.deps.DeviceCodes = recordPollFailingDeviceCodeStore{inner: f.store.DeviceCodes()}

	form := url.Values{}
	form.Set("grant_type", devCodeGrantURN)
	form.Set("device_code", "device-code-poll-fault")
	rec := f.post(t, form)

	// (a) the poll decision still proceeds — Pending records yield
	// authorization_pending; the persistence fault MUST NOT change
	// the wire shape.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := deviceCodeDecodeError(t, rec.Body.Bytes()); got != "authorization_pending" {
		t.Fatalf("error = %q, want authorization_pending", got)
	}

	// (b) a warn-level audit entry was emitted naming the failed
	// observation. Search rather than indexing because the handler
	// also emits AuditTokenRejected for the wire response.
	var found *audit.Event
	for i := range emitter.events {
		ev := emitter.events[i]
		if ev.Name == devicecode.AuditPollObservationFailed {
			found = &ev
			break
		}
	}
	if found == nil {
		names := make([]string, 0, len(emitter.events))
		for _, ev := range emitter.events {
			names = append(names, ev.Name)
		}
		t.Fatalf("expected audit event %q; got %v", devicecode.AuditPollObservationFailed, names)
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

func TestHandleDeviceCode_IssuanceFaultLeavesApprovalRetryable(t *testing.T) {
	t.Parallel()
	f := newDeviceCodeFixture(t)
	const deviceCode = "device-code-issuance-retry"
	f.seedDeviceCode(t, &store.DeviceCode{ID: deviceCode, UserCode: "ABCD-EFGH", Scope: []string{"openid"}})
	if err := f.store.DeviceCodes().Approve(context.Background(), deviceCode, "user-42", time.Time{}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	f.deps.RevocationStrategy = store.RevocationStrategyJTIRegistry
	f.deps.AccessTokens = &failFirstAccessTokenRegistry{inner: f.store.AccessTokens(), fail: true}

	form := url.Values{"grant_type": {devCodeGrantURN}, "device_code": {deviceCode}}
	if rec := f.post(t, form); rec.Code != http.StatusInternalServerError {
		t.Fatalf("first status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	stored, err := f.store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("Find after issuance fault: %v", err)
	}
	if stored.Status != store.DeviceCodeStatusApproved {
		t.Fatalf("status after issuance fault = %v, want Approved", stored.Status)
	}

	// The first request recorded a poll observation. Advance only the handler
	// clock past the RFC 8628 interval before retrying the same approval.
	f.deps.Clock = fixedClock{now: f.clock.now.Add(devicecode.DefaultInterval)}
	f.deps.AccessTokens = f.store.AccessTokens()
	if rec := f.post(t, form); rec.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}
