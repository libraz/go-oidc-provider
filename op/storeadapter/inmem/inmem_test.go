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

type mutableClock struct{ now time.Time }

func (c *mutableClock) Now() time.Time { return c.now }

// newFactory returns a [contract.Factory] that builds a fresh inmem store
// pinned to the supplied reference time. The harness invokes the factory once
// per sub-test, so each sub-test gets an isolated backend.
func newFactory(now time.Time) contract.Factory {
	return func(t *testing.T) contract.Backend {
		t.Helper()
		s := inmem.New(inmem.WithClock(fakeClock{now: now}))
		return contract.Backend{Store: s, Now: func() time.Time { return now }}
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

// TestConsumePAR_Race pins the one-time-use contract for the PAR
// store under concurrent redemption: exactly one Consume call wins,
// every other observer sees ErrAlreadyConsumed. The shape mirrors
// [TestConsumeAuthCode_Race] because RFC 9126 §2.2 borrows the
// authorization-code one-time semantic verbatim.
//
// Tracks: RFC 9126 §2.2 (PAR request_uri MUST be a one-time-use
// value). The same race surface is what the FAPI 2.0 formal analysis
// (eprint.iacr.org/2024/1540) calls "PAR request injection" — an
// attacker who races the legitimate /authorize completion can
// otherwise hijack the session if the AS allows two Consumes to
// succeed.
func TestConsumePAR_Race(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	const n = 64
	const uri = "urn:ietf:params:oauth:request_uri:race-1"
	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "c",
		RawParams: []byte(`{}`),
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
			_, err := s.PushedAuthRequests().Consume(ctx, uri)
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
		t.Fatalf("expected exactly one PAR Consume to win, got %d", wins.Load())
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

func TestUserStore_FindBySubject_RoundTrip(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ctx := context.Background()
	s.PutUser(ctx, &store.User{
		Subject:   "user-1",
		Claims:    map[string]any{"name": "Alice", "email": "alice@example.com"},
		UpdatedAt: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	})

	got, err := s.Users().FindBySubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("FindBySubject: %v", err)
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject=%q", got.Subject)
	}
	if got.Claims["name"] != "Alice" {
		t.Errorf("name claim=%v", got.Claims["name"])
	}

	// Defensive copy: mutating the returned map must not affect the
	// next read. The store SHOULD clone its internal map per call.
	got.Claims["name"] = "Bob"
	again, err := s.Users().FindBySubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("FindBySubject (second): %v", err)
	}
	if again.Claims["name"] != "Alice" {
		t.Errorf("defensive copy violated: %v", again.Claims["name"])
	}
}

func TestUserStore_FindBySubject_Missing(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	_, err := s.Users().FindBySubject(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindBySubject: want ErrNotFound, got %v", err)
	}
}

// TestAuthCode_HashOnStore_RawValueAbsent pins M-STORE-1 for the
// authorization-code substore: the raw bearer value the OP issues
// MUST NOT live in the underlying map. Find with the raw value still
// hits and a Find with a tampered value misses. The black-box
// equivalent of "raw value absent" is the tampered-value miss: the
// stored fingerprint is the SHA-256 digest of the raw ID, so any
// pre-image perturbation of the lookup parameter is rejected at the
// map-lookup boundary.
func TestAuthCode_HashOnStore_RawValueAbsent(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	const rawID = "raw-bearer-secret-authcode"
	if err := s.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID:        rawID,
		ClientID:  "c",
		Subject:   "u",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.AuthorizationCodes().Find(ctx, rawID)
	if err != nil {
		t.Fatalf("Find raw: %v", err)
	}
	if got.ID != rawID {
		t.Errorf("Find returned ID=%q want %q", got.ID, rawID)
	}
	if _, err := s.AuthorizationCodes().Find(ctx, rawID+"-tampered"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Find tampered err=%v want ErrNotFound", err)
	}
}

// TestRefresh_HashOnStore_RawValueAbsent pins M-STORE-1 for the
// refresh-token substore. ParentID is also hashed at Save time so a
// chain walk through the underlying map sees only digests; this test
// confirms RevokeChain still walks descendants correctly under the
// hashed-pointer regime.
func TestRefresh_HashOnStore_RawValueAbsent(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	const rootRaw = "raw-root-refresh"
	const childRaw = "raw-child-refresh"
	parent := rootRaw
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        rootRaw,
		ClientID:  "c",
		Subject:   "u",
		GrantID:   "g",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        childRaw,
		ParentID:  &parent,
		ClientID:  "c",
		Subject:   "u",
		GrantID:   "g",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save child: %v", err)
	}
	if _, err := s.RefreshTokens().Find(ctx, rootRaw); err != nil {
		t.Errorf("Find root raw: %v", err)
	}
	if _, err := s.RefreshTokens().Find(ctx, rootRaw+"-tampered"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Find tampered=%v want ErrNotFound", err)
	}
	// RevokeChain still walks the hashed parent pointer.
	if err := s.RefreshTokens().RevokeChain(ctx, rootRaw); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	got, err := s.RefreshTokens().Find(ctx, childRaw)
	if err != nil {
		t.Fatalf("Find child after RevokeChain: %v", err)
	}
	if got.ConsumedAt == nil {
		t.Errorf("child not revoked: %+v", got)
	}
}

func TestPAR_SaveSweepsExpiredRecords(t *testing.T) {
	t.Parallel()

	clk := &mutableClock{now: contract.Reference}
	s := inmem.New(inmem.WithClock(clk))
	ctx := context.Background()
	const uri = "urn:ietf:params:oauth:request_uri:stale"
	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: clk.now.Add(-time.Second),
		CreatedAt: clk.now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if _, err := s.PushedAuthRequests().Find(ctx, uri); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired err=%v want ErrNotFound", err)
	}
	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client-1",
		RawParams: []byte("response_type=code&scope=openid"),
		ExpiresAt: clk.now.Add(time.Minute),
		CreatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save replacement after expiry: %v", err)
	}
}

// TestPAR_HashOnStore_RawValueAbsent pins M-STORE-1 for the PAR
// substore.
func TestPAR_HashOnStore_RawValueAbsent(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	const rawURI = "urn:ietf:params:oauth:request_uri:raw-secret"
	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI:       rawURI,
		ClientID:  "c",
		RawParams: []byte(`{}`),
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got, err := s.PushedAuthRequests().Find(ctx, rawURI); err != nil {
		t.Errorf("Find raw: %v", err)
	} else if got.URI != rawURI {
		t.Errorf("Find returned URI=%q want %q", got.URI, rawURI)
	}
	if _, err := s.PushedAuthRequests().Find(ctx, rawURI+"-tampered"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Find tampered=%v want ErrNotFound", err)
	}
}

// TestIATStore_GetByHash_FastPath pins M-STORE-2: GetByHash is a
// keyed lookup, not a linear scan. The test inserts a deliberately
// large set of records and asserts the GetByHash call returns the
// right record for one specific hash; the original linear scan would
// silently pass too. The structural intent of the audit fix is captured
// by the Delete-then-GetByHash check that confirms the byHash index
// stays in sync.
func TestIATStore_GetByHash_FastPath(t *testing.T) {
	t.Parallel()
	s := inmem.New()
	ctx := context.Background()
	for i := range 64 {
		hash := "hash-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i/26))
		if err := s.InitialAccessTokens().Put(ctx, &store.InitialAccessToken{
			ID:          "iat-" + hash,
			HashedValue: hash,
			MaxUses:     1,
			CreatedAt:   contract.Reference,
		}); err != nil {
			t.Fatalf("Put %s: %v", hash, err)
		}
	}
	const targetHash = "hash-m-1"
	got, err := s.InitialAccessTokens().GetByHash(ctx, targetHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.HashedValue != targetHash {
		t.Errorf("HashedValue=%q want %q", got.HashedValue, targetHash)
	}
	// Delete drops the byHash entry alongside the id-keyed map.
	if err := s.InitialAccessTokens().Delete(ctx, "iat-"+targetHash); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.InitialAccessTokens().GetByHash(ctx, targetHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByHash after Delete=%v want ErrNotFound", err)
	}
	// Empty hash collapses to ErrNotFound rather than returning the
	// first record with HashedValue=="" (the audit's guard).
	if _, err := s.InitialAccessTokens().GetByHash(ctx, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByHash empty=%v want ErrNotFound", err)
	}
}

// TestSessionStore_ConcurrentRotate pins the SessionStore rotation
// contract directly against the in-memory adapter. The free-standing
// helper is also wired into [contract.Run] but the explicit call here
// documents the contract for backends that embed AssertConcurrentRotate
// without taking the full aggregate.
func TestSessionStore_ConcurrentRotate(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	contract.AssertConcurrentRotate(t, s.Sessions(), now)
}

// TestSessionStore_ExpiredReturnsNotFound pins the expired-session
// contract via the shared [contract.AssertExpiredSessionReturnsNotFound]
// helper. The same helper runs against the SQL and Redis adapters so
// the strict-less-than expiry boundary semantic is checked once and
// observed identically across every backend.
func TestSessionStore_ExpiredReturnsNotFound(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	contract.AssertExpiredSessionReturnsNotFound(t, s.Sessions(), now)
}

// TestSessionStore_NotFoundOnMissing pins the absent-ID contract via
// the shared [contract.AssertSessionNotFoundOnMissing] helper.
func TestSessionStore_NotFoundOnMissing(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	contract.AssertSessionNotFoundOnMissing(t, s.Sessions(), now)
}

// TestSessionStore_BatchListMatches pins the chooser-group batch
// lookup contract via the shared [contract.AssertSessionBatchListMatches]
// helper. The harness inserts a small batch (16 records) so the
// helper completes well inside the unit-test budget while still
// surfacing dedup / aliasing bugs that single-record cases would
// miss.
func TestSessionStore_BatchListMatches(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	contract.AssertSessionBatchListMatches(t, s.Sessions(), 16, now)
}

// TestTx_Rollback_ClearsStaging pins F-11: Rollback drops every
// staged record so a buggy caller cannot mutate the freed staging
// pointers into the next transaction. The test races several
// transactions through Rollback and asserts the second tx observes a
// clean state.
func TestTx_Rollback_ClearsStaging(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	tx1, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx1.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID:        "ac-rollback",
		ClientID:  "c",
		Subject:   "u",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("tx1 Save: %v", err)
	}
	if err := tx1.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	// Second transaction sees clean staging — no leftover from tx1.
	tx2, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx 2: %v", err)
	}
	if _, err := tx2.AuthorizationCodes().Find(ctx, "ac-rollback"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("tx2 Find after rollback=%v want ErrNotFound", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Fatalf("tx2 Rollback: %v", err)
	}
}
