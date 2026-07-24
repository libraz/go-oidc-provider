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

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

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

func TestRevoke_StateTable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     store.DeviceCodeStatus
		wantStatus store.DeviceCodeStatus
		wantErr    error
	}{
		{"pending", store.DeviceCodeStatusPending, store.DeviceCodeStatusDenied, nil},
		{"approved", store.DeviceCodeStatusApproved, store.DeviceCodeStatusDenied, nil},
		{"denied", store.DeviceCodeStatusDenied, store.DeviceCodeStatusDenied, nil},
		{"consumed", store.DeviceCodeStatusConsumed, store.DeviceCodeStatusConsumed, nil},
		{"expired", store.DeviceCodeStatusPending, store.DeviceCodeStatusPending, devicecodekit.ErrUnknownDeviceCode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			now := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
			s := inmem.New(inmem.WithClock(fixedClock{now: now}))
			ds := s.DeviceCodes()
			id := "dev-revoke-" + tt.name
			rec := &store.DeviceCode{
				ID:        id,
				UserCode:  "ABCDEFGH",
				ClientID:  "client-1",
				Status:    store.DeviceCodeStatusPending,
				IssuedAt:  now,
				ExpiresAt: now.Add(10 * time.Minute),
			}
			if tt.name == "expired" {
				rec.ExpiresAt = now.Add(-time.Minute)
			}
			if err := ds.Save(ctx, rec); err != nil {
				t.Fatalf("Save: %v", err)
			}
			switch tt.status {
			case store.DeviceCodeStatusPending:
				// No setup transition.
			case store.DeviceCodeStatusApproved:
				if err := ds.Approve(ctx, id, "user-1", time.Time{}); err != nil {
					t.Fatalf("Approve: %v", err)
				}
			case store.DeviceCodeStatusDenied:
				if err := ds.Deny(ctx, id, "original_denial"); err != nil {
					t.Fatalf("Deny: %v", err)
				}
			case store.DeviceCodeStatusConsumed:
				if err := ds.Approve(ctx, id, "user-1", time.Time{}); err != nil {
					t.Fatalf("Approve: %v", err)
				}
				if _, err := ds.Consume(ctx, id); err != nil {
					t.Fatalf("Consume: %v", err)
				}
			}

			emitter := &captureEmitter{}
			deps := &devicecodekit.Deps{
				DeviceCodes:        ds,
				Audit:              emitter,
				RevocationStrategy: store.RevocationStrategyNone,
			}
			err := devicecodekit.Revoke(ctx, deps, id, devicecodekit.DenyReasonUserRevokedDevice)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Revoke error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if emitter.containsName("device_code.revoked") {
					t.Fatalf("audit emitted on failed revoke: %v", emitter.names())
				}
				return
			}
			got, err := ds.FindByDeviceCode(ctx, id)
			if err != nil {
				t.Fatalf("FindByDeviceCode: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("Status = %v, want %v", got.Status, tt.wantStatus)
			}
			if tt.wantStatus == store.DeviceCodeStatusDenied && tt.status != store.DeviceCodeStatusDenied &&
				got.DenyReason != devicecodekit.DenyReasonUserRevokedDevice {
				t.Fatalf("DenyReason = %q, want %q", got.DenyReason, devicecodekit.DenyReasonUserRevokedDevice)
			}
			if !emitter.containsName("device_code.revoked") {
				t.Fatalf("audit stream missing device_code.revoked: %v", emitter.names())
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
		})
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

// TestRevoke_CascadesJTIRegistryAccessTokens confirms the explicit
// per-JTI strategy revokes every JWT shadow row issued from the
// device_code while leaving unrelated grants untouched.
func TestRevoke_CascadesJTIRegistryAccessTokens(t *testing.T) {
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
	deps := &devicecodekit.Deps{
		DeviceCodes:        ds,
		AccessTokens:       reg,
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
		Audit:              emitter,
	}
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

func TestRevoke_CascadesTombstoneOpaqueAndRefreshCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := inmem.New(inmem.WithClock(fixedClock{now: now}))
	ds := s.DeviceCodes()
	grantID := "dev-cascade-all"
	if err := ds.Save(ctx, &store.DeviceCode{
		ID:        grantID,
		UserCode:  "ABCDEFGH",
		ClientID:  "client-1",
		Status:    store.DeviceCodeStatusPending,
		IssuedAt:  now,
		ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("Save device code: %v", err)
	}
	if err := ds.Approve(ctx, grantID, "user-1", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := ds.Consume(ctx, grantID); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI:       "jwt-shadow",
		GrantID:   grantID,
		ClientID:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register JWT shadow: %v", err)
	}
	if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID:        "opaque-device-token",
		GrantID:   grantID,
		ClientID:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save opaque access token: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        "refresh-device-token",
		GrantID:   grantID,
		ClientID:  "client-1",
		Subject:   "user-1",
		Origin:    store.RefreshOriginDeviceCode,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save refresh token: %v", err)
	}

	deps := &devicecodekit.Deps{
		DeviceCodes:        ds,
		AccessTokens:       s.AccessTokens(),
		OpaqueAccessTokens: s.OpaqueAccessTokens(),
		RefreshTokens:      s.RefreshTokens(),
		GrantRevocations:   s.GrantRevocations(),
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
		AccessTokenTTL:     15 * time.Minute,
		Clock:              fixedClock{now: now},
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := devicecodekit.Revoke(ctx, deps, grantID, devicecodekit.DenyReasonUserRevokedDevice); err != nil {
			t.Fatalf("Revoke attempt %d: %v", attempt, err)
		}
	}

	device, err := ds.FindByDeviceCode(ctx, grantID)
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if device.Status != store.DeviceCodeStatusConsumed {
		t.Fatalf("device status = %v, want Consumed", device.Status)
	}
	revoked, err := s.GrantRevocations().IsRevoked(ctx, grantID, "jwt-jti", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("grant tombstone did not revoke the JWT access-token lineage")
	}
	jwtShadow, err := s.AccessTokens().Find(ctx, "jwt-shadow")
	if err != nil {
		t.Fatalf("Find JWT shadow: %v", err)
	}
	if jwtShadow == nil || jwtShadow.Revoked {
		t.Fatalf("JTI shadow changed under tombstone strategy: %+v", jwtShadow)
	}
	opaque, err := s.OpaqueAccessTokens().Find(ctx, "opaque-device-token")
	if err != nil {
		t.Fatalf("Find opaque access token: %v", err)
	}
	if !opaque.Revoked {
		t.Fatal("opaque access token was not revoked")
	}
	refresh, err := s.RefreshTokens().Find(ctx, "refresh-device-token")
	if err != nil {
		t.Fatalf("Find refresh token: %v", err)
	}
	if !refresh.Revoked {
		t.Fatal("refresh token was not revoked")
	}
}

func TestRevoke_MissingJWTBackendFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		strategy store.AccessTokenRevocationStrategy
	}{
		{"grant_tombstone", store.RevocationStrategyGrantTombstone},
		{"jti_registry", store.RevocationStrategyJTIRegistry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := inmem.New()
			ds := s.DeviceCodes()
			id := "dev-missing-backend-" + tt.name
			makePendingRecord(t, ds, id, "ABCDEFGH")
			if err := ds.Approve(ctx, id, "user-1", time.Time{}); err != nil {
				t.Fatalf("Approve: %v", err)
			}
			if _, err := ds.Consume(ctx, id); err != nil {
				t.Fatalf("Consume: %v", err)
			}
			now := time.Date(2026, 7, 24, 13, 0, 0, 0, time.UTC)
			opaqueID := "opaque-" + tt.name
			if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
				ID:        opaqueID,
				GrantID:   id,
				ClientID:  "client-1",
				IssuedAt:  now,
				ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatalf("Save opaque access token: %v", err)
			}
			refreshID := "refresh-" + tt.name
			if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
				ID:        refreshID,
				GrantID:   id,
				ClientID:  "client-1",
				Subject:   "user-1",
				Origin:    store.RefreshOriginDeviceCode,
				CreatedAt: now,
				ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatalf("Save refresh token: %v", err)
			}

			emitter := &captureEmitter{}
			err := devicecodekit.Revoke(ctx, &devicecodekit.Deps{
				DeviceCodes:        ds,
				Audit:              emitter,
				OpaqueAccessTokens: s.OpaqueAccessTokens(),
				RefreshTokens:      s.RefreshTokens(),
				RevocationStrategy: tt.strategy,
			}, id, devicecodekit.DenyReasonUserRevokedDevice)
			if !errors.Is(err, devicecodekit.ErrMissingRevocationBackend) {
				t.Fatalf("Revoke error = %v, want ErrMissingRevocationBackend", err)
			}
			rec, findErr := ds.FindByDeviceCode(ctx, id)
			if findErr != nil {
				t.Fatalf("FindByDeviceCode: %v", findErr)
			}
			if rec.Status != store.DeviceCodeStatusConsumed {
				t.Fatalf("Status = %v, want Consumed", rec.Status)
			}
			opaque, findErr := s.OpaqueAccessTokens().Find(ctx, opaqueID)
			if findErr != nil || !opaque.Revoked {
				t.Fatalf("opaque cascade after JWT config error = (%+v, %v), want revoked", opaque, findErr)
			}
			refresh, findErr := s.RefreshTokens().Find(ctx, refreshID)
			if findErr != nil || !refresh.Revoked {
				t.Fatalf("refresh cascade after JWT config error = (%+v, %v), want revoked", refresh, findErr)
			}
			var cascadeComplete any
			for _, ev := range emitter.events {
				if ev.Name == "device_code.revoked" {
					cascadeComplete = ev.Extras["cascade_complete"]
				}
			}
			if cascadeComplete != false {
				t.Fatalf("cascade_complete = %v, want false", cascadeComplete)
			}
		})
	}
}

// TestRevoke_ExplicitNoneSkipsJWTCascade confirms that the explicit
// stateless strategy still denies the authorization and emits the audit
// event without a revoked_access_tokens count.
func TestRevoke_ExplicitNoneSkipsJWTCascade(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	makePendingRecord(t, ds, "dev-casc-nil", "ABCDEFGH")

	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{
		DeviceCodes:        ds,
		Audit:              emitter,
		RevocationStrategy: store.RevocationStrategyNone,
	}
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
