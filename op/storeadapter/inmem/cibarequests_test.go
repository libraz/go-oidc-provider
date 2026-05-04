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

// makeCIBARequest is a small fixture builder for the CIBARequestStore
// tests. The defaults lean on the inmem store's default Clock so
// expiry checks fire predictably.
func makeCIBARequest(id string, status store.CIBARequestStatus, expiresAt time.Time) *store.CIBARequest {
	return &store.CIBARequest{
		ID:             id,
		ClientID:       "client-1",
		Scope:          []string{"openid"},
		Resource:       []string{"https://api.example.com"},
		ACRValues:      []string{"urn:mace:incommon:iap:silver"},
		BindingMessage: "auth #042",
		Interval:       5 * time.Second,
		IssuedAt:       time.Now(),
		ExpiresAt:      expiresAt,
		Status:         status,
	}
}

func TestCIBARequests_SaveFindRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	rec := makeCIBARequest("ciba-001-raw", store.CIBARequestStatusPending, time.Now().Add(10*time.Minute))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := cs.FindByAuthReqID(ctx, "ciba-001-raw")
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if got.ID != "ciba-001-raw" {
		t.Errorf("ID = %q, want raw value echoed back", got.ID)
	}
	if got.Status != store.CIBARequestStatusPending {
		t.Errorf("Status = %v, want Pending", got.Status)
	}
	if got.BindingMessage != "auth #042" {
		t.Errorf("BindingMessage = %q, want %q", got.BindingMessage, "auth #042")
	}
}

func TestCIBARequests_SaveDuplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	rec := makeCIBARequest("dup-id", store.CIBARequestStatusPending, time.Now().Add(time.Minute))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	if err := cs.Save(ctx, rec); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("Save duplicate: want ErrAlreadyExists, got %v", err)
	}
}

func TestCIBARequests_ApproveDenyConsume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	rec := makeCIBARequest("ap-id", store.CIBARequestStatusPending, time.Now().Add(time.Minute))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cs.Approve(ctx, "ap-id", "user-42"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := cs.Approve(ctx, "ap-id", "user-42"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("double Approve: want ErrConflict, got %v", err)
	}
	consumed, err := cs.Consume(ctx, "ap-id")
	if err != nil {
		t.Fatalf("Consume after Approve: %v", err)
	}
	if consumed.Subject != "user-42" {
		t.Errorf("Consume.Subject = %q, want user-42", consumed.Subject)
	}
	if consumed.Status != store.CIBARequestStatusConsumed {
		t.Errorf("Consume.Status = %v, want Consumed", consumed.Status)
	}
	if _, err := cs.Consume(ctx, "ap-id"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Errorf("double Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

func TestCIBARequests_ConsumePendingReturnsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	rec := makeCIBARequest("pending-id", store.CIBARequestStatusPending, time.Now().Add(time.Minute))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := cs.Consume(ctx, "pending-id"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("Consume of Pending record: want ErrConflict, got %v", err)
	}
}

func TestCIBARequests_DenyTransition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	rec := makeCIBARequest("deny-id", store.CIBARequestStatusPending, time.Now().Add(time.Minute))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cs.Deny(ctx, "deny-id", "user_denied"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, err := cs.FindByAuthReqID(ctx, "deny-id")
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if got.Status != store.CIBARequestStatusDenied {
		t.Errorf("Status = %v, want Denied", got.Status)
	}
	if got.DenyReason != "user_denied" {
		t.Errorf("DenyReason = %q, want user_denied", got.DenyReason)
	}
	if err := cs.Deny(ctx, "deny-id", "again"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("double Deny: want ErrConflict, got %v", err)
	}
}

func TestCIBARequests_PollViolationAccumulation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	rec := makeCIBARequest("poll-violate", store.CIBARequestStatusPending, time.Now().Add(time.Minute))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for i := 1; i <= 5; i++ {
		got, err := cs.IncrementPollViolation(ctx, "poll-violate")
		if err != nil {
			t.Fatalf("IncrementPollViolation #%d: %v", i, err)
		}
		if int(got) != i {
			t.Errorf("IncrementPollViolation #%d returned %d, want %d", i, got, i)
		}
	}
}

func TestCIBARequests_RecordPoll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	rec := makeCIBARequest("poll-id", store.CIBARequestStatusPending, time.Now().Add(time.Minute))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	when := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	if err := cs.RecordPoll(ctx, "poll-id", when); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	got, err := cs.FindByAuthReqID(ctx, "poll-id")
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if got.LastPolledAt == nil {
		t.Fatal("LastPolledAt is nil after RecordPoll")
	}
	if !got.LastPolledAt.Equal(when) {
		t.Errorf("LastPolledAt = %v, want %v", *got.LastPolledAt, when)
	}
}

func TestCIBARequests_Expired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()
	// ExpiresAt strictly before now → reads return ErrNotFound.
	rec := makeCIBARequest("exp-id", store.CIBARequestStatusPending, time.Now().Add(-time.Hour))
	if err := cs.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := cs.FindByAuthReqID(ctx, "exp-id"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired FindByAuthReqID: want ErrNotFound, got %v", err)
	}
}

// TestCIBARequests_Concurrent stresses the substore's state-machine
// transitions under -race. The shape mirrors how a CIBA OP looks at
// runtime: many independent /bc-authorize POSTs persist records in
// parallel, polls and approval transitions race each other, and the
// final Consume must succeed exactly once per record.
//
// The test fails under -race if any of the lock disciplines in
// cibarequests.go drifts (for example, a Save → Approve transition
// reading rec.Status without the mutex).
func TestCIBARequests_Concurrent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	cs := s.CIBARequests()

	const records = 64
	expires := time.Now().Add(time.Hour)
	for i := range records {
		rec := makeCIBARequest(concurrentAuthReqID(i), store.CIBARequestStatusPending, expires)
		if err := cs.Save(ctx, rec); err != nil {
			t.Fatalf("Save[%d]: %v", i, err)
		}
	}

	var (
		wg       sync.WaitGroup
		consumed atomic.Int64
		conflict atomic.Int64
	)
	for i := range records {
		// Reader goroutine: polls FindByAuthReqID concurrently with
		// the writer goroutines below. The result is discarded; the
		// goal is to surface mutex-discipline drift, not validate
		// the read itself.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				_, _ = cs.FindByAuthReqID(ctx, concurrentAuthReqID(i))
			}
		}()
		// Writer goroutine: increments the poll-violation counter
		// up to two strikes (the saturating arithmetic stays well
		// below the cap).
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cs.IncrementPollViolation(ctx, concurrentAuthReqID(i))
			_, _ = cs.IncrementPollViolation(ctx, concurrentAuthReqID(i))
		}()
		// Approver goroutine: races the Deny path. Exactly one
		// transition wins; the loser observes ErrConflict, which is
		// counted to confirm the CAS actually fires.
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cs.Approve(ctx, concurrentAuthReqID(i), "user-"+concurrentAuthReqID(i))
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
			err := cs.Deny(ctx, concurrentAuthReqID(i), "concurrent-deny")
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

	// Every record raced an Approve and a Deny; exactly one winner
	// and one ErrConflict per record means we should see records
	// conflict outcomes total.
	if got := conflict.Load(); got != records {
		t.Errorf("Approve/Deny race: ErrConflict count = %d, want %d", got, records)
	}

	// Sweep the records: Approved ones consume cleanly, Denied ones
	// stay rejected. The exact split depends on goroutine ordering;
	// we assert only the per-record invariants.
	for i := range records {
		id := concurrentAuthReqID(i)
		_, err := cs.Consume(ctx, id)
		switch {
		case err == nil:
			consumed.Add(1)
		case errors.Is(err, store.ErrConflict):
			// Record was Denied — Consume rejects.
		default:
			t.Errorf("Consume[%d]: unexpected %v", i, err)
		}
	}
	if got := consumed.Load(); got == 0 || got > int64(records) {
		t.Errorf("Consume sweep: %d Approved consumes; want 1..%d", got, records)
	}
}

func concurrentAuthReqID(i int) string {
	return "concurrent-ciba-" + strconv.Itoa(i)
}
