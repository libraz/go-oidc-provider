package inmem_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fakeClock returns a fixed instant. It is the test-side analogue of
// timex.SystemClock that lets the harness drive expiry semantics
// deterministically.
type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

// newFactory returns a [contract.Factory] that builds a fresh inmem store
// pinned to the supplied reference time. The harness invokes the factory once
// per sub-test, so each sub-test gets an isolated backend.
func newFactory(now time.Time) contract.Factory {
	return func(t *testing.T) contract.Backend {
		t.Helper()
		s := inmem.New(inmem.WithClock(fakeClock{now: now}))
		return contract.Backend{Store: s, Now: now}
	}
}

func TestContract(t *testing.T) {
	t.Parallel()
	contract.Run(t, newFactory(contract.Reference))
}

func TestStore_ImplementsTransactional(t *testing.T) {
	t.Parallel()
	var s any = inmem.New()
	if _, ok := s.(store.Transactional); !ok {
		t.Fatal("inmem.Store must implement store.Transactional")
	}
	if _, ok := s.(store.ClientRegistry); !ok {
		t.Fatal("inmem.Store must implement store.ClientRegistry")
	}
}

func TestConsumeAuthCode_Race(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	const n = 64
	codeID := "race-code"
	if err := s.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID:        codeID,
		ClientID:  "c",
		Subject:   "s",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var wins, replays atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.AuthorizationCodes().Consume(ctx, codeID)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrAlreadyConsumed):
				replays.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if wins.Load() != 1 {
		t.Fatalf("expected exactly one Consume to win, got %d", wins.Load())
	}
	if replays.Load() != n-1 {
		t.Fatalf("expected %d replays, got %d", n-1, replays.Load())
	}
}

func TestBeginTx_SerialisesConcurrentTransactions(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	tx1, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("first BeginTx: %v", err)
	}

	// Start a second BeginTx in a goroutine. It must not return until
	// tx1 is committed.
	started := make(chan struct{})
	completed := make(chan store.Tx, 1)
	go func() {
		close(started)
		tx2, err := s.BeginTx(ctx)
		if err != nil {
			t.Errorf("second BeginTx: %v", err)
			return
		}
		completed <- tx2
	}()

	// Wait for the goroutine to start the second BeginTx call.
	<-started
	// Give the second BeginTx a chance to block.
	timer := time.NewTimer(50 * time.Millisecond)
	select {
	case <-completed:
		timer.Stop()
		t.Fatal("second BeginTx returned before first Commit")
	case <-timer.C:
	}

	// Commit the first tx; the second should now proceed.
	if err := tx1.Commit(); err != nil {
		t.Fatalf("tx1.Commit: %v", err)
	}

	select {
	case tx2 := <-completed:
		if err := tx2.Rollback(); err != nil {
			t.Fatalf("tx2.Rollback: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second BeginTx did not unblock after first Commit")
	}
}

func TestBeginTx_RollbackUnblocksWaiters(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	tx1, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}

	completed := make(chan struct{})
	go func() {
		tx2, err := s.BeginTx(ctx)
		if err != nil {
			t.Errorf("second BeginTx: %v", err)
			return
		}
		_ = tx2.Rollback()
		close(completed)
	}()

	// Cancel the first tx via Rollback.
	if err := tx1.Rollback(); err != nil {
		t.Fatalf("tx1.Rollback: %v", err)
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("second BeginTx did not unblock after first Rollback")
	}
}

func TestSave_DefensiveCopy(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	scope := []string{"openid", "email"}
	g := &store.Grant{
		ID:        "g",
		Subject:   "sub",
		ClientID:  "client",
		Scope:     scope,
		Claims:    map[string]any{"acr": "1"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Mutate the caller-side slice and map after Save.
	scope[0] = "tampered"
	g.Claims["injected"] = true

	got, err := s.Grants().Find(ctx, "g")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.Scope[0] != "openid" {
		t.Fatalf("Save did not defensively copy scope: %+v", got.Scope)
	}
	if _, leaked := got.Claims["injected"]; leaked {
		t.Fatalf("Save did not defensively copy claims: %+v", got.Claims)
	}
}

func TestFind_DefensiveCopy(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	g := &store.Grant{
		ID:        "g",
		Subject:   "sub",
		ClientID:  "client",
		Scope:     []string{"openid"},
		Claims:    map[string]any{"acr": "1"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Grants().Find(ctx, "g")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	got.Scope[0] = "tampered"
	got.Claims["injected"] = true

	again, err := s.Grants().Find(ctx, "g")
	if err != nil {
		t.Fatalf("Find again: %v", err)
	}
	if again.Scope[0] != "openid" {
		t.Fatal("Find did not return defensive copy of slice")
	}
	if _, leaked := again.Claims["injected"]; leaked {
		t.Fatal("Find did not return defensive copy of map")
	}
}

func TestBeginTx_CtxCancelled(t *testing.T) {
	t.Parallel()
	s := inmem.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.BeginTx(ctx); err == nil {
		t.Fatal("BeginTx with cancelled ctx must return an error")
	}
}

func TestTx_ClosedAfterCommit(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("second Commit must return an error")
	}
	// Substore handles obtained from a closed tx must error on use.
	err = tx.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{ID: "x", ExpiresAt: now.Add(time.Hour)})
	if err == nil {
		t.Fatal("Save on closed tx must return an error")
	}
}

func TestTx_RollbackDiscardsRefreshChain(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	parent := "root"
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "root", ClientID: "c", Subject: "s", GrantID: "g",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "child", ClientID: "c", Subject: "s", GrantID: "g",
		ParentID: &parent, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("tx Save: %v", err)
	}
	if err := tx.RefreshTokens().RevokeChain(ctx, "root"); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	// Rollback should drop both the new child and the revocation.
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	root, err := s.RefreshTokens().Find(ctx, "root")
	if err != nil {
		t.Fatalf("Find root after rollback: %v", err)
	}
	if root.ConsumedAt != nil {
		t.Fatalf("root revoked despite rollback: %+v", root)
	}
	if _, err := s.RefreshTokens().Find(ctx, "child"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find child after rollback: want ErrNotFound, got %v", err)
	}
}
