package inmem_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func newEmailOTPRecord(subject string) *store.EmailOTPRecord {
	return &store.EmailOTPRecord{
		Subject:   subject,
		CodeSalt:  []byte{0x01, 0x02, 0x03},
		CodeHash:  []byte{0xaa, 0xbb, 0xcc},
		SentAt:    time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func TestEmailOTPStore_ConsumeRaceSingleWinner(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	es := s.EmailOTPs()
	ctx := context.Background()
	rec := newEmailOTPRecord("user-alice")
	if err := es.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	consumed := *rec
	consumed.ConsumedAt = time.Now().UTC()

	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := es.Consume(ctx, &consumed)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrAlreadyConsumed):
			default:
				t.Errorf("Consume: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("Consume wins=%d want 1", got)
	}
	got, err := es.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ConsumedAt.IsZero() {
		t.Fatal("ConsumedAt was not persisted")
	}
}
