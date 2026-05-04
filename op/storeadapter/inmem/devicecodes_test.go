package inmem_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
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
	authTime := time.Now().UTC().Truncate(time.Second)
	if err := ds.Approve(ctx, "ap-id", "user-42", authTime); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := ds.Approve(ctx, "ap-id", "user-42", authTime); !errors.Is(err, store.ErrConflict) {
		t.Errorf("double Approve: want ErrConflict, got %v", err)
	}
	consumed, err := ds.Consume(ctx, "ap-id")
	if err != nil {
		t.Fatalf("Consume after Approve: %v", err)
	}
	if consumed.Subject != "user-42" {
		t.Errorf("Consume.Subject = %q, want user-42", consumed.Subject)
	}
	if !consumed.AuthTime.Equal(authTime) {
		t.Errorf("Consume.AuthTime = %v, want %v", consumed.AuthTime, authTime)
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
	if err := ds.RecordPoll(ctx, "poll-id", when, rec.Interval); err != nil {
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

// TestDeviceCodes_RecordPollPersistsSlowDownLadder pins the
// RFC 8628 §3.5 invariant: a poll that triggers slow_down MUST
// raise the persisted Interval so subsequent polls observe the
// elevated bar, and a non-slow_down poll MUST NOT lower the
// existing Interval back down. Without this guarantee a malicious
// device could keep hammering at the original cadence by ignoring
// the elevated value the OP returned in audit only.
func TestDeviceCodes_RecordPollPersistsSlowDownLadder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()
	rec := makeDeviceCode("ladder-id", "LADDER-1", store.DeviceCodeStatusPending, time.Now().Add(time.Minute))
	if err := ds.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// First slow_down: 5s → 10s.
	t1 := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	if err := ds.RecordPoll(ctx, "ladder-id", t1, 10*time.Second); err != nil {
		t.Fatalf("RecordPoll #1: %v", err)
	}
	got, err := ds.FindByDeviceCode(ctx, "ladder-id")
	if err != nil {
		t.Fatalf("FindByDeviceCode #1: %v", err)
	}
	if got.Interval != 10*time.Second {
		t.Errorf("after first slow_down: Interval = %v, want 10s", got.Interval)
	}

	// Second slow_down: 10s → 20s.
	t2 := t1.Add(time.Second)
	if err := ds.RecordPoll(ctx, "ladder-id", t2, 20*time.Second); err != nil {
		t.Fatalf("RecordPoll #2: %v", err)
	}
	got, err = ds.FindByDeviceCode(ctx, "ladder-id")
	if err != nil {
		t.Fatalf("FindByDeviceCode #2: %v", err)
	}
	if got.Interval != 20*time.Second {
		t.Errorf("after second slow_down: Interval = %v, want 20s", got.Interval)
	}

	// Non-slow_down poll: passing the existing Interval verbatim MUST
	// NOT regress the bar. The library's call site passes rec.Interval
	// on every non-slow_down decision, so this case is the common one.
	t3 := t2.Add(30 * time.Second)
	if err := ds.RecordPoll(ctx, "ladder-id", t3, 20*time.Second); err != nil {
		t.Fatalf("RecordPoll #3: %v", err)
	}
	got, err = ds.FindByDeviceCode(ctx, "ladder-id")
	if err != nil {
		t.Fatalf("FindByDeviceCode #3: %v", err)
	}
	if got.Interval != 20*time.Second {
		t.Errorf("after non-escalating poll: Interval = %v, want 20s (no regression)", got.Interval)
	}
	if got.LastPolledAt == nil || !got.LastPolledAt.Equal(t3) {
		t.Errorf("after non-escalating poll: LastPolledAt = %v, want %v", got.LastPolledAt, t3)
	}

	// Defensive: a smaller value (e.g. an embedder bug) does not
	// downgrade the bar. The contract documents this as no-op on the
	// Interval field.
	t4 := t3.Add(30 * time.Second)
	if err := ds.RecordPoll(ctx, "ladder-id", t4, 1*time.Second); err != nil {
		t.Fatalf("RecordPoll #4: %v", err)
	}
	got, err = ds.FindByDeviceCode(ctx, "ladder-id")
	if err != nil {
		t.Fatalf("FindByDeviceCode #4: %v", err)
	}
	if got.Interval != 20*time.Second {
		t.Errorf("after sub-bar value: Interval = %v, want 20s (no downgrade)", got.Interval)
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

// TestDeviceCodes_Concurrent stresses the DeviceCodeStore state
// machine under -race. The shape mirrors a busy device-flow OP:
// many independent /device_authorization records persist in parallel,
// the user-facing verify URL races the device polling /token, and
// Approve/Deny race for each record. The per-record CAS in
// devicecodes.go is the synchronisation point under test; this test
// fails if the lock discipline drifts.
func TestDeviceCodes_Concurrent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	ds := s.DeviceCodes()

	const records = 64
	expires := time.Now().Add(time.Hour)
	for i := range records {
		rec := makeDeviceCode(concurrentDeviceID(i), concurrentUserCode(i), store.DeviceCodeStatusPending, expires)
		if err := ds.Save(ctx, rec); err != nil {
			t.Fatalf("Save[%d]: %v", i, err)
		}
	}

	var (
		wg       sync.WaitGroup
		consumed atomic.Int64
		conflict atomic.Int64
	)
	for i := range records {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				_, _ = ds.FindByDeviceCode(ctx, concurrentDeviceID(i))
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				_, _ = ds.FindByUserCode(ctx, concurrentUserCode(i))
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			// IncrementUserCodeStrike acts on the user_code, not the
			// device_code; it exercises the same locking discipline
			// as the other transitions.
			_, _ = ds.IncrementUserCodeStrike(ctx, concurrentUserCode(i))
			_, _ = ds.IncrementUserCodeStrike(ctx, concurrentUserCode(i))
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ds.Approve(ctx, concurrentDeviceID(i), "user-"+concurrentDeviceID(i), time.Time{})
			switch {
			case err == nil:
			case errors.Is(err, store.ErrConflict):
				conflict.Add(1)
			default:
				t.Errorf("Approve[%d]: %v", i, err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ds.Deny(ctx, concurrentDeviceID(i), "concurrent-deny")
			switch {
			case err == nil:
			case errors.Is(err, store.ErrConflict):
				conflict.Add(1)
			default:
				t.Errorf("Deny[%d]: %v", i, err)
			}
		}()
	}
	wg.Wait()

	if got := conflict.Load(); got != records {
		t.Errorf("Approve/Deny race: ErrConflict count = %d, want %d", got, records)
	}

	for i := range records {
		_, err := ds.Consume(ctx, concurrentDeviceID(i))
		switch {
		case err == nil:
			consumed.Add(1)
		case errors.Is(err, store.ErrConflict):
			// Denied; Consume rejects.
		default:
			t.Errorf("Consume[%d]: unexpected %v", i, err)
		}
	}
	if got := consumed.Load(); got == 0 || got > int64(records) {
		t.Errorf("Consume sweep: %d Approved consumes; want 1..%d", got, records)
	}
}

func concurrentDeviceID(i int) string { return "concurrent-dev-" + strconv.Itoa(i) }
func concurrentUserCode(i int) string { return "USER-" + strconv.Itoa(i) }
