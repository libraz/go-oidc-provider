package devicecodekit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/devicecodekit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The verification page's two user-driven outcomes are catalogued
// events, and until now only one of them reached the audit stream: the
// brute-force lockout raised device_code.verification.denied, while a
// user approving or declining raised nothing. An audit log that records
// every rejection and no approval cannot answer who authorised a
// device, which is the question a device-flow audit exists for.

// verificationNow is the instant the fixtures below pin the store's
// clock to. The records they seed carry a ten-minute lifetime measured
// from it, so the helper under test resolves them by user_code rather
// than skipping a record the real clock would already have expired.
var verificationNow = time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)

// newVerificationStore returns an in-memory store whose clock is
// pinned, so the seeded records stay live for the whole test.
func newVerificationStore() *inmem.Store {
	return inmem.New(inmem.WithClock(fixedClock{now: verificationNow}))
}

// newPendingDeviceCode seeds one Pending record and returns the store
// handle alongside the user_code the verification-page helpers key on.
func newPendingDeviceCode(tb testing.TB, s *inmem.Store, id, userCode string) store.DeviceCodeStore {
	tb.Helper()

	ctx := context.Background()
	now := verificationNow
	ds := s.DeviceCodes()
	if err := ds.Save(ctx, &store.DeviceCode{
		ID:        id,
		UserCode:  userCode,
		ClientID:  "client-1",
		Status:    store.DeviceCodeStatusPending,
		IssuedAt:  now,
		ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		tb.Fatalf("Save: %v", err)
	}
	return ds
}

func TestApproveUserCode_EmitsVerificationApproved(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := newVerificationStore()
	newPendingDeviceCode(t, s, "dev-approve-audit", "ABCDEFGH")
	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: s.DeviceCodes(), Audit: emitter}

	if err := devicecodekit.ApproveUserCode(ctx, deps, "ABCDEFGH", "user-1", time.Time{}); err != nil {
		t.Fatalf("ApproveUserCode: %v", err)
	}
	if !emitter.containsName("device_code.verification.approved") {
		t.Fatalf("approval left no audit record: %v", emitter.names())
	}
	events := emitter.snapshot()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want exactly 1: %v", len(events), emitter.names())
	}
	if got := events[0].ActorID; got != "user-1" {
		t.Errorf("ActorID = %q, want the approving subject %q", got, "user-1")
	}
}

// TestApproveUserCode_SecondApprovalIsNotAudited pins the emission to
// the substore's compare-and-swap rather than to the call: a repeat
// approval loses the swap, so the log must show one approval per
// record however many times the page is submitted.
func TestApproveUserCode_SecondApprovalIsNotAudited(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := newVerificationStore()
	newPendingDeviceCode(t, s, "dev-approve-twice", "ABCDEFGH")
	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: s.DeviceCodes(), Audit: emitter}

	if err := devicecodekit.ApproveUserCode(ctx, deps, "ABCDEFGH", "user-1", time.Time{}); err != nil {
		t.Fatalf("first ApproveUserCode: %v", err)
	}
	if err := devicecodekit.ApproveUserCode(ctx, deps, "ABCDEFGH", "user-1", time.Time{}); !errors.Is(err, devicecodekit.ErrAlreadyDecided) {
		t.Fatalf("second ApproveUserCode: err = %v, want ErrAlreadyDecided", err)
	}
	if got := len(emitter.snapshot()); got != 1 {
		t.Errorf("emitted %d events for one record, want 1: %v", got, emitter.names())
	}
}

func TestDenyUserCode_EmitsVerificationDeniedWithReason(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := newVerificationStore()
	newPendingDeviceCode(t, s, "dev-deny-audit", "ABCDEFGH")
	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: s.DeviceCodes(), Audit: emitter}

	if err := devicecodekit.DenyUserCode(ctx, deps, "ABCDEFGH", "user_denied"); err != nil {
		t.Fatalf("DenyUserCode: %v", err)
	}
	events := emitter.snapshot()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want exactly 1: %v", len(events), emitter.names())
	}
	if events[0].Name != "device_code.verification.denied" {
		t.Fatalf("event = %q, want device_code.verification.denied", events[0].Name)
	}
	// The lockout raises the same name, so the reason is the only
	// thing separating a user declining from the OP locking the
	// record. A denial logged without it is indistinguishable from a
	// brute-force lockout after the fact.
	if got := events[0].Extras["reason"]; got != "user_denied" {
		t.Errorf("reason extra = %v, want %q", got, "user_denied")
	}
}

// TestVerificationHelpers_MissingRecordIsNotAudited keeps the pair
// consistent with the rest of the kit: a helper that reports
// ErrUnknownDeviceCode must not let someone probing user_codes at
// random write entries into the audit stream.
func TestVerificationHelpers_MissingRecordIsNotAudited(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := newVerificationStore()
	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{DeviceCodes: s.DeviceCodes(), Audit: emitter}

	if err := devicecodekit.ApproveUserCode(ctx, deps, "ZZZZZZZZ", "user-1", time.Time{}); !errors.Is(err, devicecodekit.ErrUnknownDeviceCode) {
		t.Fatalf("ApproveUserCode: err = %v, want ErrUnknownDeviceCode", err)
	}
	if err := devicecodekit.DenyUserCode(ctx, deps, "ZZZZZZZZ", "user_denied"); !errors.Is(err, devicecodekit.ErrUnknownDeviceCode) {
		t.Fatalf("DenyUserCode: err = %v, want ErrUnknownDeviceCode", err)
	}
	if got := emitter.names(); len(got) != 0 {
		t.Errorf("probing an absent user_code produced audit noise: %v", got)
	}
}
