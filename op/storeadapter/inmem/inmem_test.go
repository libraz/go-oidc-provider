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
		clock := &mutableClock{now: now}
		s := inmem.New(inmem.WithClock(clock))
		return contract.Backend{
			Store: s,
			Now:   clock.Now,
			Advance: func(delta time.Duration) {
				clock.now = clock.now.Add(delta)
			},
		}
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

// TestConsumeRefresh_Race pins the refresh-token rotation hardening:
// concurrent presentations of the same refresh token must have exactly
// one successful consumer, with every other racer observing replay.
//
// Tracks: CVE-2026-1035 (Keycloak; refresh token reuse bypass via a
// TOCTOU race in rotation enforcement).
func TestConsumeRefresh_Race(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	const n = 64
	const tokenID = "race-refresh"
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        tokenID,
		ClientID:  "c",
		Subject:   "s",
		GrantID:   "g",
		Scope:     []string{"openid", "offline_access"},
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
			_, err := s.RefreshTokens().Consume(ctx, tokenID)
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

// TestGrant_DefensiveCopy_AuthorizationDetails pins that the grant store
// deep-clones the RFC 9396 authorization_details slice (and its element
// maps) so a caller that mutates a Find result cannot reach back into the
// stored record. Without cloneObjectArray the returned slice aliases the
// stored maps and the second Find observes the mutation.
func TestGrant_DefensiveCopy_AuthorizationDetails(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	g := &store.Grant{
		ID:       "g-rar",
		Subject:  "sub",
		ClientID: "client",
		Scope:    []string{"openid"},
		AuthorizationDetails: []map[string]any{
			{"type": "payment_initiation", "amount": "100"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.Grants().Find(ctx, "g-rar")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	// Mutate both the slice (append a new element) and the inner map of
	// the element the caller received.
	got.AuthorizationDetails = append(got.AuthorizationDetails, map[string]any{"type": "injected"})
	got.AuthorizationDetails[0]["amount"] = "999"
	got.AuthorizationDetails[0]["injected"] = true

	again, err := s.Grants().Find(ctx, "g-rar")
	if err != nil {
		t.Fatalf("Find again: %v", err)
	}
	if len(again.AuthorizationDetails) != 1 {
		t.Fatalf("authorization_details length=%d want 1 (slice aliasing)", len(again.AuthorizationDetails))
	}
	if again.AuthorizationDetails[0]["amount"] != "100" {
		t.Errorf("amount=%v want 100 (element map aliasing)", again.AuthorizationDetails[0]["amount"])
	}
	if _, leaked := again.AuthorizationDetails[0]["injected"]; leaked {
		t.Error("element map mutation leaked into the stored grant")
	}
}

// TestJSONFields_DefensiveCopyNestedValues pins the ownership boundary for
// every JSON-shaped field. The in-memory adapter must match SQL's JSON
// round-trip: neither a Save input nor a Find result may retain a nested map
// or slice owned by the caller.
func TestJSONFields_DefensiveCopyNestedValues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))

	nested := map[string]any{"actor": map[string]any{"roles": []string{"reader"}}}
	g := &store.Grant{
		ID:                   "nested-grant",
		Subject:              "sub",
		ClientID:             "client",
		Claims:               nested,
		AuthorizationDetails: []map[string]any{{"locations": []any{map[string]any{"country": "JP"}}}},
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	// Mutate the caller-owned nested input after Save.
	nested["actor"].(map[string]any)["roles"].([]string)[0] = "admin"
	g.AuthorizationDetails[0]["locations"].([]any)[0].(map[string]any)["country"] = "US"

	got, err := s.Grants().Find(ctx, g.ID)
	if err != nil {
		t.Fatalf("Find grant: %v", err)
	}
	got.Claims["actor"].(map[string]any)["roles"].([]string)[0] = "operator"
	got.AuthorizationDetails[0]["locations"].([]any)[0].(map[string]any)["country"] = "DE"

	again, err := s.Grants().Find(ctx, g.ID)
	if err != nil {
		t.Fatalf("Find grant again: %v", err)
	}
	if role := again.Claims["actor"].(map[string]any)["roles"].([]string)[0]; role != "reader" {
		t.Errorf("nested claim role=%q, want reader", role)
	}
	if country := again.AuthorizationDetails[0]["locations"].([]any)[0].(map[string]any)["country"]; country != "JP" {
		t.Errorf("nested authorization detail country=%q, want JP", country)
	}

	s.PutUser(ctx, &store.User{Subject: "nested-user", Claims: nested, UpdatedAt: now})
	nested["actor"].(map[string]any)["roles"].([]string)[0] = "owner"
	user, err := s.Users().FindBySubject(ctx, "nested-user")
	if err != nil {
		t.Fatalf("Find user: %v", err)
	}
	if role := user.Claims["actor"].(map[string]any)["roles"].([]string)[0]; role != "admin" {
		t.Errorf("nested user role=%q, want admin", role)
	}

	extra := map[string]any{"act": map[string]any{"chain": []any{"original"}}}
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:               "nested-refresh",
		ClientID:         "client",
		Subject:          "sub",
		GrantID:          "nested-grant",
		AccessTokenExtra: extra,
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatalf("Save refresh token: %v", err)
	}
	extra["act"].(map[string]any)["chain"].([]any)[0] = "tampered"
	refresh, err := s.RefreshTokens().Find(ctx, "nested-refresh")
	if err != nil {
		t.Fatalf("Find refresh token: %v", err)
	}
	refresh.AccessTokenExtra["act"].(map[string]any)["chain"].([]any)[0] = "mutated"
	againRefresh, err := s.RefreshTokens().Find(ctx, "nested-refresh")
	if err != nil {
		t.Fatalf("Find refresh token again: %v", err)
	}
	if got := againRefresh.AccessTokenExtra["act"].(map[string]any)["chain"].([]any)[0]; got != "original" {
		t.Errorf("nested AccessTokenExtra=%q, want original", got)
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

func TestBeginTx_CancelledWaiterReleasesClusterLocks(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	first, err := s.BeginTx(t.Context())
	if err != nil {
		t.Fatalf("first BeginTx: %v", err)
	}
	waitCtx, cancel := context.WithCancel(t.Context())
	waiterStarted := make(chan struct{})
	waiterDone := make(chan error, 1)
	go func() {
		close(waiterStarted)
		tx, beginErr := s.BeginTx(waitCtx)
		if tx != nil {
			_ = tx.Rollback()
		}
		waiterDone <- beginErr
	}()
	<-waiterStarted
	cancel()
	if err := first.Rollback(); err != nil {
		t.Fatalf("first Rollback: %v", err)
	}
	if beginErr := <-waiterDone; !errors.Is(beginErr, context.Canceled) {
		t.Fatalf("cancelled waiter error=%v want context.Canceled", beginErr)
	}

	final, err := s.BeginTx(t.Context())
	if err != nil {
		t.Fatalf("BeginTx after cancelled waiter: %v", err)
	}
	if err := final.Rollback(); err != nil {
		t.Fatalf("final Rollback: %v", err)
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

func TestTx_AtomicClusterVisibility(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID: "tx-code", ClientID: "client", Subject: "subject",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save authorization code: %v", err)
	}
	if err := tx.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "tx-refresh", ClientID: "client", Subject: "subject",
		GrantID: "tx-grant", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save refresh token: %v", err)
	}
	if err := tx.Grants().Save(ctx, &store.Grant{
		ID: "tx-grant", ClientID: "client", Subject: "subject",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	if err := tx.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI: "tx-par", ClientID: "client",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save PAR: %v", err)
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "tx-jti", GrantID: "tx-grant", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register access token: %v", err)
	}
	if err := tx.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "tx-opaque", GrantID: "tx-grant", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save opaque access token: %v", err)
	}
	if err := tx.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "tx-revoked", RevokedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	type observation struct {
		name    string
		present bool
		err     error
	}
	readers := []struct {
		name string
		read func() (bool, error)
	}{
		{
			name: "authorization code",
			read: func() (bool, error) {
				rec, findErr := s.AuthorizationCodes().Find(ctx, "tx-code")
				return rec != nil, findErr
			},
		},
		{
			name: "refresh token",
			read: func() (bool, error) {
				rec, findErr := s.RefreshTokens().Find(ctx, "tx-refresh")
				return rec != nil, findErr
			},
		},
		{
			name: "grant",
			read: func() (bool, error) {
				rec, findErr := s.Grants().Find(ctx, "tx-grant")
				return rec != nil, findErr
			},
		},
		{
			name: "PAR",
			read: func() (bool, error) {
				rec, findErr := s.PushedAuthRequests().Find(ctx, "tx-par")
				return rec != nil, findErr
			},
		},
		{
			name: "access token",
			read: func() (bool, error) {
				rec, findErr := s.AccessTokens().Find(ctx, "tx-jti")
				return rec != nil, findErr
			},
		},
		{
			name: "opaque access token",
			read: func() (bool, error) {
				rec, findErr := s.OpaqueAccessTokens().Find(ctx, "tx-opaque")
				return rec != nil, findErr
			},
		},
		{
			name: "grant revocation",
			read: func() (bool, error) {
				return s.GrantRevocations().IsRevoked(ctx, "tx-revoked", "", now)
			},
		},
	}
	observed := make(chan observation, len(readers))
	var readersReady sync.WaitGroup
	readersReady.Add(len(readers))
	for _, reader := range readers {
		go func() {
			readersReady.Done()
			present, findErr := reader.read()
			observed <- observation{name: reader.name, present: present, err: findErr}
		}()
	}
	readersReady.Wait()
	timer := time.NewTimer(50 * time.Millisecond)
	select {
	case got := <-observed:
		timer.Stop()
		t.Fatalf("%s reader returned before Commit: %+v", got.name, got)
	case <-timer.C:
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	for range readers {
		got := <-observed
		if got.err != nil || !got.present {
			t.Errorf("%s missing after Commit: %+v", got.name, got)
		}
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{JTI: "after-close"}); err == nil {
		t.Fatal("access token write after commit must fail")
	}

	tx, err = s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx for rollback: %v", err)
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{JTI: "rollback-jti"}); err != nil {
		t.Fatalf("Register rollback access token: %v", err)
	}
	if err := tx.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{ID: "rollback-opaque"}); err != nil {
		t.Fatalf("Save rollback opaque token: %v", err)
	}
	if err := tx.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{GrantID: "rollback-grant", RevokedAt: now}); err != nil {
		t.Fatalf("Revoke rollback grant: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if err := tx.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{ID: "after-rollback"}); err == nil {
		t.Fatal("opaque access token write after Rollback must fail")
	}
	if _, err := tx.Grants().Find(ctx, "after-rollback"); err == nil {
		t.Fatal("grant read after Rollback must fail")
	}
	if rec, err := s.AccessTokens().Find(ctx, "rollback-jti"); err != nil || rec != nil {
		t.Fatalf("access token survived rollback: rec=%+v err=%v", rec, err)
	}
	if _, err := s.OpaqueAccessTokens().Find(ctx, "rollback-opaque"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("opaque token survived rollback: want ErrNotFound, got %v", err)
	}
	if revoked, err := s.GrantRevocations().IsRevoked(ctx, "rollback-grant", "", now); err != nil || revoked {
		t.Fatalf("tombstone survived rollback: revoked=%v err=%v", revoked, err)
	}
}

func TestTx_DirectWriteBlocksWithoutLostUpdate(t *testing.T) {
	t.Parallel()

	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := t.Context()
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI:       "transaction-jti",
		GrantID:   "transaction-grant",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("transaction Register: %v", err)
	}

	writerReady := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		close(writerReady)
		writerDone <- s.AccessTokens().Register(ctx, store.AccessTokenRecord{
			JTI:       "direct-jti",
			GrantID:   "direct-grant",
			ExpiresAt: now.Add(time.Hour),
		})
	}()
	<-writerReady
	timer := time.NewTimer(50 * time.Millisecond)
	select {
	case directErr := <-writerDone:
		timer.Stop()
		t.Fatalf("direct write returned before Commit: %v", directErr)
	case <-timer.C:
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if directErr := <-writerDone; directErr != nil {
		t.Fatalf("direct Register after Commit: %v", directErr)
	}
	for _, jti := range []string{"transaction-jti", "direct-jti"} {
		rec, findErr := s.AccessTokens().Find(ctx, jti)
		if findErr != nil || rec == nil {
			t.Errorf("Find(%q): rec=%+v err=%v", jti, rec, findErr)
		}
	}
}

func TestTx_RefreshRetryResponse_AtomicRotation(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "retry-parent", ClientID: "client", Subject: "subject", GrantID: "grant", Scope: []string{"openid"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save parent: %v", err)
	}

	parent := "retry-parent"
	successor := func(id string) *store.RefreshToken {
		return &store.RefreshToken{ID: id, ClientID: "client", Subject: "subject", GrantID: "grant", Scope: []string{"openid"}, ParentID: &parent, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.RefreshTokens().Consume(ctx, parent); err != nil {
		t.Fatalf("Consume in tx: %v", err)
	}
	retries, ok := tx.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Fatal("transactional refresh store does not implement RefreshRetryResponseStore")
	}
	if err := retries.SaveRotationWithRetry(ctx, successor("retry-rolled-back"), []byte("sealed-rollback")); err != nil {
		t.Fatalf("SaveRotationWithRetry in tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	gotParent, err := s.RefreshTokens().Find(ctx, parent)
	if err != nil || gotParent.ConsumedAt != nil {
		t.Fatalf("parent changed after rollback: rec=%+v err=%v", gotParent, err)
	}
	if _, err := s.RefreshTokens().Find(ctx, "retry-rolled-back"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("successor survived rollback: want ErrNotFound, got %v", err)
	}
	directRetries := s.RefreshTokens().(store.RefreshRetryResponseStore)
	if _, err := directRetries.LoadRetryResponse(ctx, parent); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retry response survived rollback: want ErrNotFound, got %v", err)
	}

	tx, err = s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx for commit: %v", err)
	}
	if _, err := tx.RefreshTokens().Consume(ctx, parent); err != nil {
		t.Fatalf("Consume for commit: %v", err)
	}
	retries = tx.RefreshTokens().(store.RefreshRetryResponseStore)
	sealed := []byte("sealed-commit")
	if err := retries.SaveRotationWithRetry(ctx, successor("retry-committed"), sealed); err != nil {
		t.Fatalf("SaveRotationWithRetry for commit: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got, err := directRetries.LoadRetryResponse(ctx, parent); err != nil || !bytes.Equal(got, sealed) {
		t.Fatalf("retry response after commit: got=%q err=%v", got, err)
	}
	if rec, err := s.RefreshTokens().Find(ctx, "retry-committed"); err != nil || rec == nil {
		t.Fatalf("successor missing after commit: rec=%+v err=%v", rec, err)
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
