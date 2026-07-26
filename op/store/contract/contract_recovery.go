package contract

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// RecoveryFactory builds a fresh standalone [store.RecoveryStore] for a
// single contract sub-test. Recovery batches are intentionally separate
// from [Backend] because they are supplied directly to the recovery-code
// step rather than through the aggregate [store.Store].
type RecoveryFactory func(t *testing.T) store.RecoveryStore

// RunRecoveryCodes exercises the single-use slot guarantees of
// [store.RecoveryStore], including the hash-match precondition that makes
// regenerating a batch revoke the codes it replaced. Adapter authors
// should call it from their black-box test suite.
func RunRecoveryCodes(t *testing.T, f RecoveryFactory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, store.RecoveryStore)
	}{
		{"Missing", recoveryMissing},
		{"PutGetRoundTrip", recoveryRoundTrip},
		{"PutReplacesBatchWholesale", recoveryPutReplaces},
		{"ConsumeMarksOneSlot", recoveryConsumeMarksSlot},
		{"ConsumeTwiceRejected", recoveryConsumeTwice},
		{"ConsumeSupersededHashRejected", recoveryConsumeSupersededHash},
		{"ConsumeMissingBatch", recoveryConsumeMissing},
		{"DeleteRemovesBatch", recoveryDelete},
		{"DeleteMissing", recoveryDeleteMissing},
		{"DefensiveCopies", recoveryDefensiveCopies},
		{"ConcurrentConsumeHasOneWinner", recoveryConcurrentConsume},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, f(t))
		})
	}
}

func recoveryMissing(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	if _, err := s.Get(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func recoveryRoundTrip(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	want := recoveryContractBatch()
	want.Codes[2].ConsumedAt = Reference.Add(-time.Hour)
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertRecoveryEqual(t, got, want)
}

func recoveryPutReplaces(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	first := recoveryContractBatch()
	first.Codes[0].ConsumedAt = Reference
	if err := s.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}

	// Regenerating mints a whole new batch; the previous slot list must
	// not survive underneath it.
	second := &store.RecoveryBatch{
		Subject:     first.Subject,
		GeneratedAt: Reference.Add(time.Hour),
		Codes: []store.RecoveryCode{
			{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$bmV3MA"},
			{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$bmV3MQ"},
		},
	}
	if err := s.Put(ctx, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, err := s.Get(ctx, first.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertRecoveryEqual(t, got, second)
}

func recoveryConsumeMarksSlot(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	seed := recoveryContractBatch()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	presented, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	presented.Codes[1].ConsumedAt = Reference
	if err := s.Consume(ctx, presented, 1); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after consume: %v", err)
	}
	if !got.Codes[1].ConsumedAt.Equal(Reference) {
		t.Fatalf("consumed slot ConsumedAt = %v, want %v", got.Codes[1].ConsumedAt, Reference)
	}
	for i, code := range got.Codes {
		if i == 1 {
			continue
		}
		if !code.ConsumedAt.IsZero() {
			t.Fatalf("slot %d ConsumedAt = %v, want zero", i, code.ConsumedAt)
		}
		if code.Hash != seed.Codes[i].Hash {
			t.Fatalf("slot %d Hash = %q, want %q", i, code.Hash, seed.Codes[i].Hash)
		}
	}
}

func recoveryConsumeTwice(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	seed := recoveryContractBatch()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	presented, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}
	presented.Codes[0].ConsumedAt = Reference
	if err := s.Consume(ctx, presented, 0); err != nil {
		t.Fatalf("Consume first: %v", err)
	}

	replay, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get before replay: %v", err)
	}
	replay.Codes[0].ConsumedAt = Reference.Add(time.Minute)
	if err := s.Consume(ctx, replay, 0); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume replay error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after replay: %v", err)
	}
	if !got.Codes[0].ConsumedAt.Equal(Reference) {
		t.Fatalf("ConsumedAt = %v, want the first redemption at %v", got.Codes[0].ConsumedAt, Reference)
	}
}

func recoveryConsumeSupersededHash(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	seed := recoveryContractBatch()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// The user reads a code, then regenerates the batch — the very act
	// that is supposed to revoke the codes they read.
	presented, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	regenerated := recoveryContractBatch()
	for i := range regenerated.Codes {
		regenerated.Codes[i].Hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$cmVnZW4" + string(rune('A'+i))
	}
	regenerated.GeneratedAt = Reference.Add(time.Hour)
	if err := s.Put(ctx, regenerated); err != nil {
		t.Fatalf("Put regenerated: %v", err)
	}

	presented.Codes[0].ConsumedAt = Reference
	if err := s.Consume(ctx, presented, 0); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume superseded hash error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after rejected consume: %v", err)
	}
	if !got.Codes[0].ConsumedAt.IsZero() {
		t.Fatal("a superseded code burned a slot of the regenerated batch")
	}
	if got.Codes[0].Hash != regenerated.Codes[0].Hash {
		t.Fatalf("Hash = %q, want the regenerated %q", got.Codes[0].Hash, regenerated.Codes[0].Hash)
	}
}

func recoveryConsumeMissing(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	batch := recoveryContractBatch()
	batch.Subject = "missing"
	if err := s.Consume(context.Background(), batch, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume(missing) error = %v, want ErrNotFound", err)
	}
}

func recoveryDelete(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	seed := recoveryContractBatch()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, seed.Subject); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, seed.Subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after delete error = %v, want ErrNotFound", err)
	}
}

func recoveryDeleteMissing(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	if err := s.Delete(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrNotFound", err)
	}
}

func recoveryDefensiveCopies(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	seed := recoveryContractBatch()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	seed.Codes[0].Hash = "mutated-after-put"

	first, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if first.Codes[0].Hash != recoveryContractBatch().Codes[0].Hash {
		t.Fatalf("input mutation leaked: Hash = %q", first.Codes[0].Hash)
	}

	first.Codes[0].Hash = "mutated-after-get"
	second, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if second.Codes[0].Hash != recoveryContractBatch().Codes[0].Hash {
		t.Fatalf("result mutation leaked: Hash = %q", second.Codes[0].Hash)
	}
}

func recoveryConcurrentConsume(t *testing.T, s store.RecoveryStore) {
	t.Helper()
	ctx := context.Background()
	seed := recoveryContractBatch()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	current, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		presented := cloneContractBatch(current)
		presented.Codes[0].ConsumedAt = Reference.Add(time.Duration(i) * time.Minute)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-release
			errs <- s.Consume(ctx, presented, 0)
		}()
	}
	<-ready
	<-ready
	close(release)
	wg.Wait()

	winners := 0
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			winners++
		case errors.Is(err, store.ErrAlreadyConsumed):
		default:
			t.Fatalf("Consume concurrent: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful concurrent redemptions = %d, want 1", winners)
	}
}

func recoveryContractBatch() *store.RecoveryBatch {
	return &store.RecoveryBatch{
		Subject:     "alice",
		GeneratedAt: Reference.Add(-24 * time.Hour),
		Codes: []store.RecoveryCode{
			{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$Y29kZTA"},
			{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$Y29kZTE"},
			{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$Y29kZTI"},
		},
	}
}

func cloneContractBatch(b *store.RecoveryBatch) *store.RecoveryBatch {
	out := *b
	out.Codes = append([]store.RecoveryCode(nil), b.Codes...)
	return &out
}

func assertRecoveryEqual(t *testing.T, got, want *store.RecoveryBatch) {
	t.Helper()
	if got.Subject != want.Subject {
		t.Fatalf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if !got.GeneratedAt.Equal(want.GeneratedAt) {
		t.Fatalf("GeneratedAt = %v, want %v", got.GeneratedAt, want.GeneratedAt)
	}
	if len(got.Codes) != len(want.Codes) {
		t.Fatalf("len(Codes) = %d, want %d", len(got.Codes), len(want.Codes))
	}
	for i := range want.Codes {
		if got.Codes[i].Hash != want.Codes[i].Hash {
			t.Fatalf("Codes[%d].Hash = %q, want %q", i, got.Codes[i].Hash, want.Codes[i].Hash)
		}
		if !got.Codes[i].ConsumedAt.Equal(want.Codes[i].ConsumedAt) {
			t.Fatalf("Codes[%d].ConsumedAt = %v, want %v", i, got.Codes[i].ConsumedAt, want.Codes[i].ConsumedAt)
		}
	}
}
