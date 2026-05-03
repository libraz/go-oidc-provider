package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// makeDeviceCode is a small fixture builder for the DeviceCodeStore
// tests. The defaults lean on the inmem store's default Clock so
// expiry checks fire predictably.
func makeDeviceCode(id, userCode string, status store.DeviceCodeStatus, expiresAt time.Time) *store.DeviceCode {
	return &store.DeviceCode{
		ID:        id,
		UserCode:  userCode,
		ClientID:  "client-1",
		Scope:     []string{"openid"},
		Resource:  []string{"https://api.example.com"},
		Interval:  5 * time.Second,
		IssuedAt:  time.Now(),
		ExpiresAt: expiresAt,
		Status:    status,
	}
}

func TestDeviceCodes_SaveFindRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("dev-001-raw", "ABCDEFGH", store.DeviceCodeStatusPending, time.Now().Add(10*time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := ds.FindByDeviceCode(ctx, "dev-001-raw")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.ID != "dev-001-raw" {
		t.Errorf("ID = %q, want raw value echoed back", got.ID)
	}
	if got.UserCode != "ABCDEFGH" {
		t.Errorf("UserCode = %q, want ABCDEFGH", got.UserCode)
	}
	if got.Status != store.DeviceCodeStatusPending {
		t.Errorf("Status = %v, want Pending", got.Status)
	}
	byUser, err := ds.FindByUserCode(ctx, "ABCDEFGH")
	if err != nil {
		t.Fatalf("FindByUserCode: %v", err)
	}
	if byUser.ID != "" {
		t.Errorf("FindByUserCode.ID = %q, want empty (raw device_code MUST NOT leak via user_code lookup)", byUser.ID)
	}
}

func TestDeviceCodes_SaveDuplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("dup-id", "CODE-001", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	if err := ds.Save(ctx, rec); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("Save duplicate: want ErrAlreadyExists, got %v", err)
	}
	conflict := makeDeviceCode("different-id", "CODE-001", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, conflict); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("Save user_code collision: want ErrAlreadyExists, got %v", err)
	}
}

func TestDeviceCodes_ApproveDenyConsume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("ap-id", "AP-CODE", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := ds.Approve(ctx, "ap-id", "user-42"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := ds.Approve(ctx, "ap-id", "user-42"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("double Approve: want ErrConflict, got %v", err)
	}
	consumed, err := ds.Consume(ctx, "ap-id")
	if err != nil {
		t.Fatalf("Consume after Approve: %v", err)
	}
	if consumed.Subject != "user-42" {
		t.Errorf("Consume.Subject = %q, want user-42", consumed.Subject)
	}
	if consumed.Status != store.DeviceCodeStatusConsumed {
		t.Errorf("Consume.Status = %v, want Consumed", consumed.Status)
	}
	if _, err := ds.Consume(ctx, "ap-id"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Errorf("double Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

func TestDeviceCodes_ConsumePendingReturnsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("pending-id", "PEND-001", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := ds.Consume(ctx, "pending-id"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("Consume of Pending record: want ErrConflict, got %v", err)
	}
}

func TestDeviceCodes_DenyTransition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("deny-id", "DENY-001", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := ds.Deny(ctx, "deny-id", "user_denied"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, err := ds.FindByDeviceCode(ctx, "deny-id")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.Status != store.DeviceCodeStatusDenied {
		t.Errorf("Status = %v, want Denied", got.Status)
	}
	if got.DenyReason != "user_denied" {
		t.Errorf("DenyReason = %q, want user_denied", got.DenyReason)
	}
	if err := ds.Deny(ctx, "deny-id", "again"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("double Deny: want ErrConflict, got %v", err)
	}
}

func TestDeviceCodes_StrikeAccumulation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("strike-id", "STRIKE-1", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for i := 1; i <= 5; i++ {
		got, err := ds.IncrementUserCodeStrike(ctx, "strike-id")
		if err != nil {
			t.Fatalf("IncrementUserCodeStrike #%d: %v", i, err)
		}
		if int(got) != i {
			t.Errorf("IncrementUserCodeStrike #%d returned %d, want %d", i, got, i)
		}
	}
}

func TestDeviceCodes_RecordPoll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("poll-id", "POLL-001", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	when := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	if err := ds.RecordPoll(ctx, "poll-id", when); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	got, err := ds.FindByDeviceCode(ctx, "poll-id")
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.LastPolledAt == nil {
		t.Fatal("LastPolledAt is nil after RecordPoll")
	}
	if !got.LastPolledAt.Equal(when) {
		t.Errorf("LastPolledAt = %v, want %v", *got.LastPolledAt, when)
	}
}

func TestDeviceCodes_Expired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	// ExpiresAt strictly before now → reads return ErrNotFound.
	rec := makeDeviceCode("exp-id", "EXP-001", store.DeviceCodeStatusPending, time.Now().Add(-time.Hour))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := ds.FindByDeviceCode(ctx, "exp-id"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired FindByDeviceCode: want ErrNotFound, got %v", err)
	}
	if _, err := ds.FindByUserCode(ctx, "EXP-001"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired FindByUserCode: want ErrNotFound, got %v", err)
	}
}
