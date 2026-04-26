package composite_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestRace_BeginTxAndPerKindReads exercises the composite under
// `go test -race` with concurrent BeginTx callers, transactional writes on
// the anchor backend, and direct reads on the non-transactional backends.
// The intent is to surface any unsynchronised access introduced by the
// composite's routing layer; the underlying inmem stores are already
// race-clean.
func TestRace_BeginTxAndPerKindReads(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	clock := fakeClock{now: now}
	persistent := inmem.New(inmem.WithClock(clock))
	ephemeral := inmem.New(inmem.WithClock(clock))

	s, err := composite.New(
		composite.WithDefault(persistent),
		composite.With(composite.Interactions, ephemeral),
		composite.With(composite.ConsumedJTIs, ephemeral),
	)
	if err != nil {
		t.Fatalf("composite.New: %v", err)
	}

	const (
		txWorkers   = 8
		readWorkers = 8
		iterations  = 64
	)

	ctx := context.Background()
	var wg sync.WaitGroup

	// txWorkers open transactions on the composite (via the anchor) and
	// stage cross-substore writes. The anchor's BeginTx serialises them;
	// the composite layer must not introduce its own races.
	for w := range txWorkers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			runTxWorker(t, ctx, s, now, worker, iterations)
		}(w)
	}

	// readWorkers hammer the non-transactional Kinds (Interactions,
	// ConsumedJTIs, Clients) through the composite while transactions are
	// in flight. Routes for those Kinds resolve to a different backend, so
	// the reads must not block on the tx mutex.
	for w := range readWorkers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			runReadWorker(t, ctx, s, ephemeral, now, worker, iterations)
		}(w)
	}

	wg.Wait()
}

// runTxWorker drives a tight BeginTx/Commit loop with cross-substore writes
// inside each transaction. Errors reported via t.Errorf are surfaced after
// the WaitGroup drains.
func runTxWorker(t *testing.T, ctx context.Context, s *composite.Store, now time.Time, worker, iters int) {
	t.Helper()
	for i := range iters {
		tx, err := s.BeginTx(ctx)
		if err != nil {
			t.Errorf("BeginTx worker %d iter %d: %v", worker, i, err)
			return
		}
		grant := &store.Grant{
			ID:        uniqueID("g", worker, i),
			Subject:   "sub",
			ClientID:  "client",
			Scope:     []string{"openid"},
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.Grants().Save(ctx, grant); err != nil {
			t.Errorf("Grants.Save worker %d iter %d: %v", worker, i, err)
			_ = tx.Rollback()
			return
		}
		code := &store.AuthorizationCode{
			ID:        uniqueID("ac", worker, i),
			ClientID:  "client",
			Subject:   "sub",
			GrantID:   grant.ID,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now,
		}
		if err := tx.AuthorizationCodes().Save(ctx, code); err != nil {
			t.Errorf("AuthorizationCodes.Save worker %d iter %d: %v", worker, i, err)
			_ = tx.Rollback()
			return
		}
		if err := tx.Commit(); err != nil {
			t.Errorf("Commit worker %d iter %d: %v", worker, i, err)
			return
		}
	}
}

// runReadWorker drives non-transactional reads and writes across the
// ephemeral backend through the composite. Each iteration writes an
// interaction, marks a JTI, and reads the interaction back from the
// underlying ephemeral store to confirm routing.
func runReadWorker(t *testing.T, ctx context.Context, s *composite.Store, ephemeral *inmem.Store, now time.Time, worker, iters int) {
	t.Helper()
	for i := range iters {
		id := uniqueID("i", worker, i)
		rec := &store.Interaction{
			ID:        id,
			ClientID:  "client",
			Step:      "consent",
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.Interactions().Save(ctx, rec); err != nil {
			t.Errorf("Interactions.Save worker %d iter %d: %v", worker, i, err)
			return
		}
		if err := s.ConsumedJTIs().Mark(ctx, uniqueID("j", worker, i), now.Add(time.Hour)); err != nil {
			t.Errorf("ConsumedJTIs.Mark worker %d iter %d: %v", worker, i, err)
			return
		}
		if _, err := ephemeral.Interactions().Find(ctx, id); err != nil {
			t.Errorf("ephemeral.Interactions.Find worker %d iter %d: %v", worker, i, err)
			return
		}
	}
}

// uniqueID builds a deterministic record ID from the worker and iteration
// counters. crypto/rand is forbidden in this package and time.Now is
// off-limits, so we lean on the input space being collision-free by
// construction.
func uniqueID(prefix string, worker, iter int) string {
	return prefix + "-" + itoa(worker) + "-" + itoa(iter)
}

// itoa renders v as a decimal string. The helper keeps uniqueID allocation
// patterns simple without inviting fmt into the hot test loop.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
