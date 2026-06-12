package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file holds the DeviceCodeStore contract sub-tests (RFC 8628).
// They pin the device-authorization state machine — Save → approve /
// deny → poll → consume, plus the brute-force and slow_down counters —
// identically across every backend that hosts the substore.

// requireDeviceCodes skips the current test when the backend does not
// provide a [store.DeviceCodeStore]. Partial-coverage backends (e.g. a
// volatile cache that hosts only Sessions) return nil here, and the
// harness treats the substore as out of scope rather than panicking.
func requireDeviceCodes(t *testing.T, s store.Store) store.DeviceCodeStore {
	t.Helper()
	dc := s.DeviceCodes()
	if dc == nil {
		t.Skipf("backend %T does not provide a DeviceCodeStore", s)
	}
	return dc
}

func newDeviceCode(now time.Time, id, userCode string) *store.DeviceCode {
	return &store.DeviceCode{
		ID:        id,
		ClientID:  "client",
		UserCode:  userCode,
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		Status:    store.DeviceCodeStatusPending,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
}

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var deviceCodeCases = []subtest{
	{"SaveFind", deviceCodeSaveFind},
	{"FindByUserCodeHidesDeviceCode", deviceCodeFindByUserCode},
	{"UserCodeApprovalPath", deviceCodeUserCodeApprovalPath},
	{"ApproveConsumeOnce", deviceCodeApproveConsumeOnce},
	{"ApproveConflictAfterDeny", deviceCodeApproveConflictAfterDeny},
	{"ConsumeConflictWhenDenied", deviceCodeConsumeConflictWhenDenied},
	{"RecordPollEscalatesInterval", deviceCodeRecordPollEscalates},
	{"StrikesIncrement", deviceCodeStrikesIncrement},
	{"PollViolationsIncrement", deviceCodePollViolationsIncrement},
	{"Expired", deviceCodeExpired},
	{"DuplicateUserCode", deviceCodeDuplicateUserCode},
	{"TransitionMissing", deviceCodeTransitionMissing},
}

func deviceCodeUserCodeApprovalPath(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-uc-approve", "AAAA-0099")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if strikes, err := dc.IncrementUserCodeStrikeByUserCode(ctx, "AAAA-0099"); err != nil || strikes != 1 {
		t.Fatalf("IncrementUserCodeStrikeByUserCode = %d, %v; want 1, nil", strikes, err)
	}
	if err := dc.ApproveByUserCode(ctx, "AAAA-0099", "sub-user-code", b.Now()); err != nil {
		t.Fatalf("ApproveByUserCode: %v", err)
	}
	got, err := dc.FindByDeviceCode(ctx, "dc-uc-approve")
	if err != nil {
		t.Fatalf("FindByDeviceCode after ApproveByUserCode: %v", err)
	}
	if got.Status != store.DeviceCodeStatusApproved || got.Subject != "sub-user-code" || got.UserCodeStrikes != 1 {
		t.Fatalf("unexpected record after user_code approval: %+v", got)
	}
	if err := dc.DenyByUserCode(ctx, "AAAA-0099", "late-deny"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("DenyByUserCode after approve: want ErrConflict, got %v", err)
	}
}

func deviceCodeSaveFind(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-1", "AAAA-0001")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := dc.FindByDeviceCode(ctx, "dc-1")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.ID != "dc-1" || got.UserCode != "AAAA-0001" || got.Status != store.DeviceCodeStatusPending {
		t.Fatalf("unexpected record: %+v", got)
	}
}

func deviceCodeFindByUserCode(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-uc", "AAAA-0002")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := dc.FindByUserCode(ctx, "AAAA-0002")
	if err != nil {
		t.Fatalf("FindByUserCode: %v", err)
	}
	// The user_code lookup must never leak the wire device_code: a
	// malicious verification page could otherwise poll on the device's
	// behalf.
	if got.ID != "" {
		t.Fatalf("FindByUserCode leaked device_code: ID=%q", got.ID)
	}
	if got.UserCode != "AAAA-0002" {
		t.Fatalf("unexpected user_code: %q", got.UserCode)
	}
	if _, err := dc.FindByUserCode(ctx, "ZZZZ-9999"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByUserCode missing: want ErrNotFound, got %v", err)
	}
}

func deviceCodeApproveConsumeOnce(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-ac", "AAAA-0003")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := dc.Approve(ctx, "dc-ac", "sub-1", b.Now()); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err := dc.FindByDeviceCode(ctx, "dc-ac")
	if err != nil {
		t.Fatalf("FindByDeviceCode after approve: %v", err)
	}
	if got.Status != store.DeviceCodeStatusApproved || got.Subject != "sub-1" {
		t.Fatalf("approve did not stamp record: %+v", got)
	}
	first, err := dc.Consume(ctx, "dc-ac")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if first.Status != store.DeviceCodeStatusConsumed || first.ID != "dc-ac" {
		t.Fatalf("Consume returned unexpected record: %+v", first)
	}
	if _, err := dc.Consume(ctx, "dc-ac"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

func deviceCodeApproveConflictAfterDeny(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-cf", "AAAA-0004")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := dc.Deny(ctx, "dc-cf", "user_denied"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := dc.Approve(ctx, "dc-cf", "sub-1", b.Now()); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Approve after Deny: want ErrConflict, got %v", err)
	}
}

func deviceCodeConsumeConflictWhenDenied(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-dn", "AAAA-0005")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := dc.Deny(ctx, "dc-dn", "user_denied"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if _, err := dc.Consume(ctx, "dc-dn"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Consume denied: want ErrConflict, got %v", err)
	}
}

func deviceCodeRecordPollEscalates(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-poll", "AAAA-0006")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := dc.RecordPoll(ctx, "dc-poll", b.Now(), 10*time.Second); err != nil {
		t.Fatalf("RecordPoll escalate: %v", err)
	}
	got, err := dc.FindByDeviceCode(ctx, "dc-poll")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.Interval != 10*time.Second {
		t.Fatalf("interval did not escalate: got %v", got.Interval)
	}
	if got.LastPolledAt == nil {
		t.Fatal("RecordPoll did not stamp LastPolledAt")
	}
	// A non-escalating poll must leave the elevated interval intact so a
	// device cannot re-arm the gate by passing a smaller value.
	if err := dc.RecordPoll(ctx, "dc-poll", b.Now(), 3*time.Second); err != nil {
		t.Fatalf("RecordPoll no-escalate: %v", err)
	}
	got, err = dc.FindByDeviceCode(ctx, "dc-poll")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.Interval != 10*time.Second {
		t.Fatalf("interval regressed: got %v", got.Interval)
	}
}

func deviceCodeStrikesIncrement(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-strk", "AAAA-0007")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for want := uint8(1); want <= 3; want++ {
		got, err := dc.IncrementUserCodeStrike(ctx, "dc-strk")
		if err != nil {
			t.Fatalf("IncrementUserCodeStrike: %v", err)
		}
		if got != want {
			t.Fatalf("strike count: want %d, got %d", want, got)
		}
	}
	if _, err := dc.IncrementUserCodeStrike(ctx, "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("IncrementUserCodeStrike missing: want ErrNotFound, got %v", err)
	}
}

func deviceCodePollViolationsIncrement(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-viol", "AAAA-0008")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for want := uint8(1); want <= 2; want++ {
		got, err := dc.IncrementPollViolation(ctx, "dc-viol")
		if err != nil {
			t.Fatalf("IncrementPollViolation: %v", err)
		}
		if got != want {
			t.Fatalf("violation count: want %d, got %d", want, got)
		}
	}
	if _, err := dc.IncrementPollViolation(ctx, "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("IncrementPollViolation missing: want ErrNotFound, got %v", err)
	}
}

func deviceCodeExpired(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	rec := newDeviceCode(b.Now(), "dc-exp", "AAAA-0009")
	rec.ExpiresAt = b.Now().Add(-time.Hour)
	if err := dc.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := dc.FindByDeviceCode(ctx, "dc-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByDeviceCode expired: want ErrNotFound, got %v", err)
	}
	if _, err := dc.FindByUserCode(ctx, "AAAA-0009"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByUserCode expired: want ErrNotFound, got %v", err)
	}
	if err := dc.Approve(ctx, "dc-exp", "sub-1", b.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Approve expired: want ErrNotFound, got %v", err)
	}
	if _, err := dc.Consume(ctx, "dc-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume expired: want ErrNotFound, got %v", err)
	}
	if err := dc.RecordPoll(ctx, "dc-exp", b.Now(), 5*time.Second); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RecordPoll expired: want ErrNotFound, got %v", err)
	}
	if _, err := dc.IncrementUserCodeStrike(ctx, "dc-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("IncrementUserCodeStrike expired: want ErrNotFound, got %v", err)
	}
}

func deviceCodeDuplicateUserCode(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-u1", "AAAA-0010")); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-u2", "AAAA-0010"))
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate user_code Save: want ErrAlreadyExists, got %v", err)
	}
}

func deviceCodeTransitionMissing(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Approve(ctx, "absent", "sub-1", b.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Approve missing: want ErrNotFound, got %v", err)
	}
	if err := dc.Deny(ctx, "absent", "user_denied"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Deny missing: want ErrNotFound, got %v", err)
	}
	if _, err := dc.Consume(ctx, "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume missing: want ErrNotFound, got %v", err)
	}
}
