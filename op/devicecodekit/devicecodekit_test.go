package devicecodekit_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/devicecodekit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// makePendingRecord seeds a Pending device-authorization row and returns
// the device_code the substore now knows it as. Tests reuse the helper
// so the boilerplate of populating ExpiresAt / Status stays in one
// place.
func makePendingRecord(t *testing.T, ds store.DeviceCodeStore, deviceCode, userCode string) {
	t.Helper()
	rec := &store.DeviceCode{
		ID:        deviceCode,
		UserCode:  userCode,
		ClientID:  "client-1",
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Status:    store.DeviceCodeStatusPending,
	}
	if err := ds.Save(context.Background(), rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// TestVerifyUserCode_MatchAdvancesRecord pins the happy path: a
// canonical user_code submission returns matched=true with no strike
// recorded. The record stays in Pending so the embedder can call
// Approve on the next step.
func TestVerifyUserCode_MatchAdvancesRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-match-1", "ABCDEFGH")

	deps := &devicecodekit.Deps{DeviceCodes: ds}
	matched, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-match-1", "ABCDEFGH")
	if err != nil {
		t.Fatalf("VerifyUserCode: %v", err)
	}
	if !matched {
		t.Fatalf("matched = false, want true")
	}
	rec, err := ds.FindByDeviceCode(ctx, "dev-match-1")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if rec.UserCodeStrikes != 0 {
		t.Errorf("Strikes = %d, want 0 on a successful match", rec.UserCodeStrikes)
	}
	if rec.Status != store.DeviceCodeStatusPending {
		t.Errorf("Status = %v, want Pending after a successful match", rec.Status)
	}
}

// TestVerifyUserCode_NormalisesSubmission pins that the helper accepts
// a submission with hyphens / spaces / lowercase and matches against
// the canonical stored value. Without normalisation a user typing
// "abcd-efgh" would never hit the stored "ABCDEFGH".
func TestVerifyUserCode_NormalisesSubmission(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-norm-1", "ABCDEFGH")

	deps := &devicecodekit.Deps{DeviceCodes: ds}
	matched, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-norm-1", "abcd-efgh")
	if err != nil {
		t.Fatalf("VerifyUserCode: %v", err)
	}
	if !matched {
		t.Fatalf("matched = false on a hyphenated lowercase submission; want true")
	}
}

func TestUserCodeKeyedApprovalPathDoesNotNeedDeviceCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-user-code-only", "ABCDEFGH")
	deps := &devicecodekit.Deps{DeviceCodes: ds}

	matched, err := devicecodekit.VerifyUserCodeByUserCode(ctx, deps, "abcd-efgh", "ABCDEFGH")
	if err != nil {
		t.Fatalf("VerifyUserCodeByUserCode: %v", err)
	}
	if !matched {
		t.Fatal("matched=false want true")
	}
	authTime := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	if err := devicecodekit.ApproveUserCode(ctx, deps, "ABCDEFGH", "subject-1", authTime); err != nil {
		t.Fatalf("ApproveUserCode: %v", err)
	}
	rec, err := ds.Consume(ctx, "dev-user-code-only")
	if err != nil {
		t.Fatalf("Consume after user_code approval: %v", err)
	}
	if rec.Subject != "subject-1" || !rec.AuthTime.Equal(authTime) {
		t.Fatalf("approved record = %+v, want subject/authTime from ApproveUserCode", rec)
	}
}

func TestVerifyUserCodeByUserCode_MismatchUsesStrikeGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-user-code-strike", "ABCDEFGH")
	deps := &devicecodekit.Deps{DeviceCodes: ds}

	for i := 1; i <= int(devicecodekit.MaxUserCodeStrikes); i++ {
		matched, err := devicecodekit.VerifyUserCodeByUserCode(ctx, deps, "ABCDEFGH", "ZZZZ9999")
		if err != nil {
			t.Fatalf("VerifyUserCodeByUserCode strike %d: %v", i, err)
		}
		if matched {
			t.Fatalf("strike %d matched=true, want false", i)
		}
	}
	rec, err := ds.FindByDeviceCode(ctx, "dev-user-code-strike")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if rec.Status != store.DeviceCodeStatusDenied {
		t.Fatalf("Status=%v want Denied", rec.Status)
	}
	if rec.DenyReason != devicecodekit.DenyReasonUserCodeLockout {
		t.Fatalf("DenyReason=%q want %q", rec.DenyReason, devicecodekit.DenyReasonUserCodeLockout)
	}
}

// TestVerifyUserCode_FourMismatchesStayPending pins the brute-force
// gate's pre-lockout window: four wrong submissions advance the
// strike counter but the record stays Pending. The embedder may
// still surface a meaningful "N attempts remaining" UX.
func TestVerifyUserCode_FourMismatchesStayPending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-strike-1", "ABCDEFGH")

	deps := &devicecodekit.Deps{DeviceCodes: ds}
	for i := 1; i <= 4; i++ {
		matched, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-strike-1", "WRONG"+strconv.Itoa(i))
		if err != nil {
			t.Fatalf("strike %d: VerifyUserCode err = %v", i, err)
		}
		if matched {
			t.Fatalf("strike %d: matched = true, want false", i)
		}
		rec, err := ds.FindByDeviceCode(ctx, "dev-strike-1")
		if err != nil {
			t.Fatalf("strike %d: FindByDeviceCode: %v", i, err)
		}
		if int(rec.UserCodeStrikes) != i {
			t.Errorf("strike %d: Strikes = %d, want %d", i, rec.UserCodeStrikes, i)
		}
		if rec.Status != store.DeviceCodeStatusPending {
			t.Errorf("strike %d: Status = %v, want Pending", i, rec.Status)
		}
	}
}

// TestVerifyUserCode_FifthMismatchTransitionsDenied pins the lockout
// transition: when the post-increment strike count reaches
// MaxUserCodeStrikes the record transitions to Denied with reason
// DenyReasonUserCodeLockout. The wire posture on the polling channel
// (next /token poll returns access_denied) follows from the
// substore's Denied → access_denied mapping.
func TestVerifyUserCode_FifthMismatchTransitionsDenied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-lock-1", "ABCDEFGH")

	deps := &devicecodekit.Deps{DeviceCodes: ds}
	for i := 1; i <= 5; i++ {
		_, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-lock-1", "WRONG"+strconv.Itoa(i))
		if err != nil {
			t.Fatalf("strike %d: %v", i, err)
		}
	}
	rec, err := ds.FindByDeviceCode(ctx, "dev-lock-1")
	if err != nil {
		t.Fatalf("FindByDeviceCode after lockout: %v", err)
	}
	if int(rec.UserCodeStrikes) != int(devicecodekit.MaxUserCodeStrikes) {
		t.Errorf("Strikes after lockout = %d, want %d", rec.UserCodeStrikes, devicecodekit.MaxUserCodeStrikes)
	}
	if rec.Status != store.DeviceCodeStatusDenied {
		t.Errorf("Status after lockout = %v, want Denied", rec.Status)
	}
	if rec.DenyReason != devicecodekit.DenyReasonUserCodeLockout {
		t.Errorf("DenyReason = %q, want %q", rec.DenyReason, devicecodekit.DenyReasonUserCodeLockout)
	}
}

// TestVerifyUserCode_AfterLockoutReturnsAlreadyDecided pins that
// further submissions after lockout DO NOT increment the strike
// counter or fire the deny again. The helper returns
// (false, ErrAlreadyDecided) so the embedder can render "this code
// is no longer accepted" without burning extra strikes that would
// be observable through audit.
func TestVerifyUserCode_AfterLockoutReturnsAlreadyDecided(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-after-lock-1", "ABCDEFGH")

	deps := &devicecodekit.Deps{DeviceCodes: ds}
	for i := 1; i <= 5; i++ {
		_, _ = devicecodekit.VerifyUserCode(ctx, deps, "dev-after-lock-1", "WRONG"+strconv.Itoa(i))
	}
	// Sixth submission against a Denied record.
	matched, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-after-lock-1", "ABCDEFGH")
	if !errors.Is(err, devicecodekit.ErrAlreadyDecided) {
		t.Fatalf("err = %v, want ErrAlreadyDecided", err)
	}
	if matched {
		t.Errorf("matched = true on a Denied record; want false")
	}
	// Strikes did not advance past the ceiling.
	rec, err := ds.FindByDeviceCode(ctx, "dev-after-lock-1")
	if err != nil {
		t.Fatalf("FindByDeviceCode after extra submission: %v", err)
	}
	if int(rec.UserCodeStrikes) != int(devicecodekit.MaxUserCodeStrikes) {
		t.Errorf("Strikes after extra submission = %d, want %d (no further increments)",
			rec.UserCodeStrikes, devicecodekit.MaxUserCodeStrikes)
	}
}

// TestVerifyUserCode_UnknownDeviceCodeReturnsSentinel pins the boundary
// translation: a missing record collapses to ErrUnknownDeviceCode so
// the verification page can render a single "session expired" message
// without inspecting the substore's internal shape.
func TestVerifyUserCode_UnknownDeviceCodeReturnsSentinel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	deps := &devicecodekit.Deps{DeviceCodes: s.DeviceCodes()}
	matched, err := devicecodekit.VerifyUserCode(ctx, deps, "no-such-device", "ABCDEFGH")
	if !errors.Is(err, devicecodekit.ErrUnknownDeviceCode) {
		t.Fatalf("err = %v, want ErrUnknownDeviceCode", err)
	}
	if matched {
		t.Errorf("matched = true on missing record; want false")
	}
}

// TestVerifyUserCode_MalformedSubmissionRecordsStrike pins that a
// malformed submission (wrong length, non-Crockford characters)
// records a strike rather than short-circuiting. A brute-force loop
// that probes outside the alphabet must hit the lockout on the same
// budget as a loop that probes well-formed values.
func TestVerifyUserCode_MalformedSubmissionRecordsStrike(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-malformed-1", "ABCDEFGH")

	deps := &devicecodekit.Deps{DeviceCodes: ds}
	matched, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-malformed-1", "??")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if matched {
		t.Errorf("matched = true on malformed submission; want false")
	}
	rec, err := ds.FindByDeviceCode(ctx, "dev-malformed-1")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if rec.UserCodeStrikes != 1 {
		t.Errorf("Strikes after malformed submission = %d, want 1", rec.UserCodeStrikes)
	}
}

// TestVerifyUserCode_NilDepsReturnsInvalidArgument pins the boundary
// guard: a nil Deps (or a Deps without a substore) returns
// ErrInvalidArgument without touching the substore. The error is
// programmer-facing; callers MUST surface it as a 500.
func TestVerifyUserCode_NilDepsReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	if _, err := devicecodekit.VerifyUserCode(ctx, nil, "dev", "ABCDEFGH"); !errors.Is(err, devicecodekit.ErrInvalidArgument) {
		t.Errorf("nil deps: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := devicecodekit.VerifyUserCode(ctx, &devicecodekit.Deps{}, "dev", "ABCDEFGH"); !errors.Is(err, devicecodekit.ErrInvalidArgument) {
		t.Errorf("empty deps: err = %v, want ErrInvalidArgument", err)
	}
}

// TestVerifyUserCode_ConcurrentSubmissionsHonourCeiling pins the
// race-safe behaviour the verification page relies on under load.
// Twenty goroutines submit a wrong code in parallel; the substore's
// per-record CAS serialises the strike-counter increments and the
// helper transitions the record exactly once. The final state is
// Denied with strikes saturated at MaxUserCodeStrikes.
func TestVerifyUserCode_ConcurrentSubmissionsHonourCeiling(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-race-1", "ABCDEFGH")

	deps := &devicecodekit.Deps{DeviceCodes: ds}
	const submitters = 20
	var (
		wg             sync.WaitGroup
		matchedCount   atomic.Int64
		alreadyDecided atomic.Int64
	)
	wg.Add(submitters)
	for range submitters {
		go func() {
			defer wg.Done()
			matched, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-race-1", "WRONG")
			if matched {
				matchedCount.Add(1)
			}
			if errors.Is(err, devicecodekit.ErrAlreadyDecided) {
				alreadyDecided.Add(1)
			}
		}()
	}
	wg.Wait()

	if matchedCount.Load() != 0 {
		t.Errorf("matchedCount = %d, want 0 (no submission carried the canonical code)", matchedCount.Load())
	}
	rec, err := ds.FindByDeviceCode(ctx, "dev-race-1")
	if err != nil {
		t.Fatalf("FindByDeviceCode after race: %v", err)
	}
	if rec.Status != store.DeviceCodeStatusDenied {
		t.Errorf("Status after race = %v, want Denied", rec.Status)
	}
	// At least 5 strikes landed (the ceiling); inmem's strike substore
	// may saturate without overflowing thanks to the helper's
	// 255-cap. The lockout transition fires on the 5th strike;
	// subsequent strikes that race the lockout are absorbed by the
	// store's Pending → Denied conflict path and fold into the
	// "already decided" return shape.
	if int(rec.UserCodeStrikes) < int(devicecodekit.MaxUserCodeStrikes) {
		t.Errorf("Strikes after race = %d, want at least %d", rec.UserCodeStrikes, devicecodekit.MaxUserCodeStrikes)
	}
}

// TestRevoke_PendingRecordTransitionsDenied pins the happy path: a
// Pending record transitions to Denied with the supplied reason and
// the audit emitter receives a device_code.revoked event.
func TestRevoke_PendingRecordTransitionsDenied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-rev-1", "ABCDEFGH")

	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: ds, Audit: emitter}
	if err := devicecodekit.Revoke(ctx, deps, "dev-rev-1", devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	rec, err := ds.FindByDeviceCode(ctx, "dev-rev-1")
	if err != nil {
		t.Fatalf("FindByDeviceCode after revoke: %v", err)
	}
	if rec.Status != store.DeviceCodeStatusDenied {
		t.Errorf("Status = %v, want Denied", rec.Status)
	}
	if rec.DenyReason != devicecodekit.DenyReasonUserRevokedDevice {
		t.Errorf("DenyReason = %q, want %q", rec.DenyReason, devicecodekit.DenyReasonUserRevokedDevice)
	}
	if !emitter.containsName("device_code.revoked") {
		t.Errorf("audit stream missing device_code.revoked: %v", emitter.names())
	}
	for _, ev := range emitter.events {
		if ev.Name != "device_code.revoked" {
			continue
		}
		if _, ok := ev.Extras["device_code_id"]; ok {
			t.Fatalf("audit extras leaked raw device_code_id: %v", ev.Extras)
		}
		if got := ev.Extras["device_code_hash"]; got == "" {
			t.Fatalf("audit extras missing device_code_hash: %v", ev.Extras)
		}
	}
}

// TestRevoke_AlreadyApprovedReturnsAlreadyDecided pins the gate on
// non-Pending records: a record that has already been Approved (or
// Denied / Consumed) cannot be revoked through this helper. The
// embedder MUST cascade-revoke through the AccessTokenRegistry on
// the audit signal of the original transition; running Revoke a
// second time is a no-op-with-error.
func TestRevoke_AlreadyApprovedReturnsAlreadyDecided(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-rev-2", "ABCDEFGH")
	if err := ds.Approve(ctx, "dev-rev-2", "user-1", time.Time{}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: ds, Audit: emitter}
	err := devicecodekit.Revoke(ctx, deps, "dev-rev-2", devicecodekit.DenyReasonUserRevokedDevice)
	if !errors.Is(err, devicecodekit.ErrAlreadyDecided) {
		t.Fatalf("err = %v, want ErrAlreadyDecided", err)
	}
	if emitter.containsName("device_code.revoked") {
		t.Errorf("audit stream emitted device_code.revoked despite no-op call: %v", emitter.names())
	}
}

// TestRevoke_UnknownDeviceCodeReturnsSentinel pins the missing-record
// path: the helper returns ErrUnknownDeviceCode without emitting an
// audit event so a probing attacker cannot generate audit noise by
// firing Revoke at random device_codes.
func TestRevoke_UnknownDeviceCodeReturnsSentinel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: s.DeviceCodes(), Audit: emitter}
	err := devicecodekit.Revoke(ctx, deps, "no-such-device", "user_revoked_device")
	if !errors.Is(err, devicecodekit.ErrUnknownDeviceCode) {
		t.Fatalf("err = %v, want ErrUnknownDeviceCode", err)
	}
	if emitter.containsName("device_code.revoked") {
		t.Errorf("audit stream emitted device_code.revoked on missing record: %v", emitter.names())
	}
}

// TestRevoke_NilDepsReturnsInvalidArgument pins the boundary guard.
func TestRevoke_NilDepsReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if err := devicecodekit.Revoke(ctx, nil, "dev", "user_denied"); !errors.Is(err, devicecodekit.ErrInvalidArgument) {
		t.Errorf("nil deps: err = %v, want ErrInvalidArgument", err)
	}
	if err := devicecodekit.Revoke(ctx, &devicecodekit.Deps{}, "", "user_denied"); !errors.Is(err, devicecodekit.ErrInvalidArgument) {
		t.Errorf("empty deviceCode: err = %v, want ErrInvalidArgument", err)
	}
}

// TestRevoke_CascadesAccessTokenRevocation confirms that revoking a
// device authorization revokes every access token issued from that
// device_code — the tokens carry the device_code's ID as their GrantID,
// so RevokeByGrant retires them — while leaving tokens from unrelated
// grants untouched. The audit event reports the count.
func TestRevoke_CascadesAccessTokenRevocation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	reg := s.AccessTokens()
	makePendingRecord(t, ds, "dev-casc-1", "ABCDEFGH")

	now := time.Now()
	for _, jti := range []string{"at-casc-a", "at-casc-b"} {
		if err := reg.Register(ctx, store.AccessTokenRecord{
			JTI:       jti,
			GrantID:   "dev-casc-1",
			ClientID:  "client-1",
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Register %s: %v", jti, err)
		}
	}
	if err := reg.Register(ctx, store.AccessTokenRecord{
		JTI:       "at-other",
		GrantID:   "other-grant",
		ClientID:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register at-other: %v", err)
	}

	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: ds, AccessTokens: reg, Audit: emitter}
	if err := devicecodekit.Revoke(ctx, deps, "dev-casc-1", devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, jti := range []string{"at-casc-a", "at-casc-b"} {
		rec, err := reg.Find(ctx, jti)
		if err != nil {
			t.Fatalf("Find %s: %v", jti, err)
		}
		if rec == nil || !rec.Revoked {
			t.Errorf("access token %s not revoked: %+v", jti, rec)
		}
	}
	other, err := reg.Find(ctx, "at-other")
	if err != nil {
		t.Fatalf("Find at-other: %v", err)
	}
	if other == nil || other.Revoked {
		t.Errorf("unrelated access token must not be revoked: %+v", other)
	}

	var gotCount any
	for _, ev := range emitter.events {
		if ev.Name == "device_code.revoked" {
			gotCount = ev.Extras["revoked_access_tokens"]
		}
	}
	if gotCount != 2 {
		t.Errorf("revoked_access_tokens = %v, want 2", gotCount)
	}
}

// TestRevoke_NilRegistrySkipsCascade confirms that when no
// AccessTokenRegistry is wired the revoke still denies the authorization
// and emits the audit event, without a revoked_access_tokens count.
func TestRevoke_NilRegistrySkipsCascade(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-casc-nil", "ABCDEFGH")

	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: ds, Audit: emitter}
	if err := devicecodekit.Revoke(ctx, deps, "dev-casc-nil", devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	rec, err := ds.FindByDeviceCode(ctx, "dev-casc-nil")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if rec.Status != store.DeviceCodeStatusDenied {
		t.Errorf("Status = %v, want Denied", rec.Status)
	}
	for _, ev := range emitter.events {
		if ev.Name == "device_code.revoked" {
			if _, ok := ev.Extras["revoked_access_tokens"]; ok {
				t.Errorf("nil registry must not report revoked_access_tokens: %v", ev.Extras)
			}
		}
	}
}
