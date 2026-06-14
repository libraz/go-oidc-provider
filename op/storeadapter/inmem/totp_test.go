package inmem_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func newTOTPRecord(subject string) *store.TOTPRecord {
	return &store.TOTPRecord{
		Subject:          subject,
		SecretCiphertext: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		ConfirmedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestTOTPStore_PutGetRoundTrip(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ts := s.TOTPs()
	ctx := context.Background()

	rec := newTOTPRecord("user-alice")
	if err := ts.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ts.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Subject != rec.Subject {
		t.Errorf("Subject=%q want %q", got.Subject, rec.Subject)
	}
	if !bytes.Equal(got.SecretCiphertext, rec.SecretCiphertext) {
		t.Errorf("SecretCiphertext=%x want %x", got.SecretCiphertext, rec.SecretCiphertext)
	}
}

func TestTOTPStore_GetNotFound(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if _, err := s.TOTPs().Get(context.Background(), "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err=%v want ErrNotFound", err)
	}
}

func TestTOTPStore_PutOverwrites(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ts := s.TOTPs()
	ctx := context.Background()

	first := newTOTPRecord("user-alice")
	if err := ts.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}

	second := newTOTPRecord("user-alice")
	second.SecretCiphertext = []byte{0xff, 0xee, 0xdd}
	second.FailedCount = 5
	if err := ts.Put(ctx, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, err := ts.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.SecretCiphertext, second.SecretCiphertext) {
		t.Errorf("SecretCiphertext=%x want %x (overwrite did not stick)", got.SecretCiphertext, second.SecretCiphertext)
	}
	if got.FailedCount != 5 {
		t.Errorf("FailedCount=%d want 5", got.FailedCount)
	}
}

func TestTOTPStore_DeleteRemovesRecord(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ts := s.TOTPs()
	ctx := context.Background()

	rec := newTOTPRecord("user-alice")
	if err := ts.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := ts.Delete(ctx, "user-alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := ts.Get(ctx, "user-alice"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Delete: err=%v want ErrNotFound", err)
	}
}

func TestTOTPStore_DeleteMissingReturnsNotFound(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if err := s.TOTPs().Delete(context.Background(), "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err=%v want ErrNotFound", err)
	}
}

func TestTOTPStore_PutNilRejected(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if err := s.TOTPs().Put(context.Background(), nil); err == nil {
		t.Error("Put(nil) returned nil error")
	}
}

func TestTOTPStore_GetClonesRecord(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ts := s.TOTPs()
	ctx := context.Background()

	rec := newTOTPRecord("user-alice")
	if err := ts.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ts.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Mutating the returned record MUST NOT bleed into the store.
	got.SecretCiphertext[0] ^= 0xff
	got.FailedCount = 99

	again, err := ts.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if again.SecretCiphertext[0] == got.SecretCiphertext[0] {
		t.Errorf("SecretCiphertext shared backing array between Get calls")
	}
	if again.FailedCount != 0 {
		t.Errorf("FailedCount=%d want 0 (caller mutation leaked)", again.FailedCount)
	}
}

func TestTOTPStore_PutClonesRecord(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ts := s.TOTPs()
	ctx := context.Background()

	rec := newTOTPRecord("user-alice")
	if err := ts.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Mutate the original after Put — the store MUST hold an
	// independent copy.
	rec.SecretCiphertext[0] ^= 0xff

	got, err := ts.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SecretCiphertext[0] == rec.SecretCiphertext[0] {
		t.Errorf("post-Put mutation of caller record leaked into store")
	}
}

func TestTOTPStore_AcceptRaceSingleWinner(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ts := s.TOTPs()
	ctx := context.Background()
	rec := newTOTPRecord("user-alice")
	if err := ts.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	accepted := *rec
	accepted.LastAcceptedStep = 12345

	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ts.Accept(ctx, &accepted)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrAlreadyConsumed):
			default:
				t.Errorf("Accept: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("Accept wins=%d want 1", got)
	}
	got, err := ts.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastAcceptedStep != accepted.LastAcceptedStep {
		t.Fatalf("LastAcceptedStep=%d want %d", got.LastAcceptedStep, accepted.LastAcceptedStep)
	}
}
