package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// fixedClock pins the adapter to contract.Reference so the harness's
// expiry pre-conditions land at the same instant the records were
// stamped with.
type fixedClock struct{ now time.Time }

// Now reads through the pointer so a Now method value bound once —
// as the contract harness does — still observes later mutations. A
// value receiver would copy the struct at bind time and freeze the
// harness clock while the store's own clock kept moving.
func (c *fixedClock) Now() time.Time { return c.now }

// openSQLite returns a fresh in-process SQLite database. Each call
// produces an isolated database via the file::memory:?cache=shared
// trick scoped to a unique URI fragment so concurrent tests can run
// in parallel without colliding on the shared memory namespace.
func openSQLite(t *testing.T) *databasesql.DB {
	t.Helper()
	// Per-test database file under the testing.T's TempDir so the
	// driver's WAL files land in a directory the test framework
	// cleans up automatically.
	dir := t.TempDir()
	dsn := "file:" + dir + "/oidc.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newSQLiteFactory returns a contract.Factory that builds a fresh,
// migrated SQLite-backed store per sub-test.
func newSQLiteFactory(t *testing.T) contract.Factory {
	t.Helper()
	return func(t *testing.T) contract.Backend {
		t.Helper()
		clock := &fixedClock{now: contract.Reference}
		db := openSQLite(t)
		s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(clock))
		if err != nil {
			t.Fatalf("oidcsql.New: %v", err)
		}
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		return contract.Backend{
			Store: s,
			Now:   clock.Now,
			Advance: func(delta time.Duration) {
				clock.now = clock.now.Add(delta)
			},
			SeedUser: seedContractUser(s),
		}
	}
}

// TestSQLite_Contract drives every contract sub-test against the
// SQLite adapter. A failure here is the first signal that an
// adapter change has broken the documented store semantics.
func TestSQLite_Contract(t *testing.T) {
	t.Parallel()
	factory := newSQLiteFactory(t)
	contract.Run(t, factory)
	runMFAContracts(t, factory)
	runClientUpdateContracts(t, factory)
}

func TestSQLite_MigrateDetectsLegacyRefreshSchema(t *testing.T) {
	t.Parallel()

	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
CREATE TABLE oidc_refresh_tokens (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    parent_id TEXT,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '[]',
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
)`); err != nil {
		t.Fatalf("create legacy refresh table: %v", err)
	}
	err = s.Migrate(context.Background())
	if err == nil {
		t.Fatal("Migrate succeeded against legacy refresh schema; want missing-column error")
	}
	if !strings.Contains(err.Error(), "schema for oidc_refresh_tokens is missing required columns") ||
		!strings.Contains(err.Error(), "subject_public") ||
		!strings.Contains(err.Error(), "authorization_details") {
		t.Fatalf("Migrate error=%v, want missing refresh columns", err)
	}
}

func TestSQLite_RefreshReplayFromNonRootRevokesDescendants(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	ctx := context.Background()
	now := b.Now()
	clk := func() time.Time { return now }
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: b.Store.RefreshTokens(),
		Clock: clk,
		TTL:   24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exchanger, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store:    b.Store.RefreshTokens(),
		Clock:    clk,
		GraceTTL: -1,
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	issue := refresh.IssueInput{
		ClientID: "client-1",
		Subject:  "user-1",
		GrantID:  "grant-1",
		Scope:    []string{"openid"},
	}

	root, err := issuer.Issue(ctx, issue)
	if err != nil {
		t.Fatalf("Issue root: %v", err)
	}
	rootEx, err := exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Exchange root: %v", err)
	}
	issue.ParentID = &rootEx.ConsumedID
	mid, err := issuer.Issue(ctx, issue)
	if err != nil {
		t.Fatalf("Issue mid: %v", err)
	}
	midEx, err := exchanger.Exchange(ctx, refresh.ExchangeInput{Token: mid, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Exchange mid: %v", err)
	}
	issue.ParentID = &midEx.ConsumedID
	leaf, err := issuer.Issue(ctx, issue)
	if err != nil {
		t.Fatalf("Issue leaf: %v", err)
	}

	if _, err := exchanger.Exchange(ctx, refresh.ExchangeInput{Token: mid, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay mid err=%v want ErrTokenReplayed", err)
	}
	got, err := b.Store.RefreshTokens().Find(ctx, leaf)
	if err != nil {
		t.Fatalf("Find leaf: %v", err)
	}
	if got.ConsumedAt == nil || !got.Revoked {
		t.Fatalf("leaf not revoked after non-root replay: %+v", got)
	}
}

// TestSQLite_SessionStore_ConcurrentRotate pins the rotation
// post-condition declared on [store.SessionStore] directly against the
// SQL adapter. The free-standing helper is also exercised via
// [contract.Run] -> sessionCases; the explicit call documents the
// contract a sessions-only embedder is expected to honour.
func TestSQLite_SessionStore_ConcurrentRotate(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertConcurrentRotate(t, b.Store.Sessions(), b.Now())
}

// TestSQLite_SessionStore_ExpiredReturnsNotFound pins the
// expired-session contract against the SQL adapter via the shared
// [contract.AssertExpiredSessionReturnsNotFound] helper. The strict-
// less-than expiry boundary is checked at one source site
// (op/storeadapter/patterns.IsExpiredStrict) and observed identically
// across every backend.
func TestSQLite_SessionStore_ExpiredReturnsNotFound(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertExpiredSessionReturnsNotFound(t, b.Store.Sessions(), b.Now())
}

// TestSQLite_SessionStore_NotFoundOnMissing pins the absent-ID
// contract against the SQL adapter via the shared
// [contract.AssertSessionNotFoundOnMissing] helper.
func TestSQLite_SessionStore_NotFoundOnMissing(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertSessionNotFoundOnMissing(t, b.Store.Sessions(), b.Now())
}

// TestSQLite_SessionStore_BatchListMatches pins the chooser-group
// batch lookup contract against the SQL adapter via the shared
// [contract.AssertSessionBatchListMatches] helper.
func TestSQLite_SessionStore_BatchListMatches(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertSessionBatchListMatches(t, b.Store.Sessions(), 16, b.Now())
}

func TestSQLite_GCPreservesZeroExpiryAccessTokenRows(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	ctx := context.Background()
	now := b.Now()
	at := b.Store.AccessTokens()
	if err := at.Register(ctx, store.AccessTokenRecord{
		JTI:       "zero-at",
		GrantID:   "grant-zero",
		Subject:   "sub-zero",
		ClientID:  "client-zero",
		Scopes:    []string{"read"},
		IssuedAt:  now,
		ExpiresAt: time.Time{},
	}); err != nil {
		t.Fatalf("Register zero access token: %v", err)
	}
	if err := at.Register(ctx, store.AccessTokenRecord{
		JTI:       "expired-at",
		GrantID:   "grant-expired",
		Subject:   "sub-expired",
		ClientID:  "client-expired",
		Scopes:    []string{"read"},
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Register expired access token: %v", err)
	}

	n, err := at.GC(ctx, now)
	if err != nil {
		t.Fatalf("AccessTokens.GC: %v", err)
	}
	if n != 1 {
		t.Fatalf("AccessTokens.GC removed %d rows, want 1", n)
	}
	if got, err := at.Find(ctx, "zero-at"); err != nil || got == nil {
		t.Fatalf("zero-expiry access token missing after GC: got=%+v err=%v", got, err)
	}
	if got, err := at.Find(ctx, "expired-at"); err != nil || got != nil {
		t.Fatalf("expired access token survived GC: got=%+v err=%v", got, err)
	}
}

func TestSQLite_GCPreservesZeroExpiryOpaqueAccessTokenRows(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	ctx := context.Background()
	now := b.Now()
	opaque := b.Store.OpaqueAccessTokens()
	if err := opaque.Save(ctx, &store.OpaqueAccessToken{
		ID:        "zero-opaque-token",
		GrantID:   "grant-zero",
		Subject:   "sub-zero",
		ClientID:  "client-zero",
		Scope:     []string{"read"},
		Audience:  "https://api.example.com",
		IssuedAt:  now,
		ExpiresAt: time.Time{},
	}); err != nil {
		t.Fatalf("Save zero opaque token: %v", err)
	}
	if err := opaque.Save(ctx, &store.OpaqueAccessToken{
		ID:        "expired-opaque-token",
		GrantID:   "grant-expired",
		Subject:   "sub-expired",
		ClientID:  "client-expired",
		Scope:     []string{"read"},
		Audience:  "https://api.example.com",
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save expired opaque token: %v", err)
	}

	n, err := opaque.GC(ctx, now)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.GC: %v", err)
	}
	if n != 1 {
		t.Fatalf("OpaqueAccessTokens.GC removed %d rows, want 1", n)
	}
	if got, err := opaque.Find(ctx, "zero-opaque-token"); err != nil || got == nil {
		t.Fatalf("zero-expiry opaque token missing after GC: got=%+v err=%v", got, err)
	}
	if got, err := opaque.Find(ctx, "expired-opaque-token"); err == nil || got != nil {
		t.Fatalf("expired opaque token survived GC: got=%+v err=%v", got, err)
	}
}
