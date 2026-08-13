//go:build example

// store_test.go — self-verification for the hand-rolled scratchStore.
//
// It opens a fresh temp SQLite database, runs the migration, then drives
// a realistic sequence across every substore and asserts the sentinel
// errors the store.* contracts require. No browser or network is
// involved; the parent agent drives the browser round-trip separately.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

func newTestStore(t *testing.T) (*scratchStore, *databasesql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "scratch-test.db")
	// The pragmas match the ones main.go opens the database with. WAL is
	// not a tuning knob here: without it a transaction that reads a row
	// before writing it cannot take the write lock while any other
	// connection is still reading, and the contract's concurrent grant
	// amendment — several authorizations for one (subject, client)
	// landing together — has every attempt refused instead of one at a
	// time.
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := newScratchStore(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s, db
}

func TestStoreContract(t *testing.T) {
	t.Parallel()

	contract.Run(t, func(t *testing.T) contract.Backend {
		t.Helper()
		s, _ := newTestStore(t)
		s.now = func() time.Time { return contract.Reference }
		return contract.Backend{
			Store: s,
			Now:   s.now,
		}
	})
}

func TestAuthorizationCodes(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	ac := s.AuthorizationCodes()

	now := time.Now()
	code := &store.AuthorizationCode{
		ID:          "raw-code-secret",
		ClientID:    "demo-rp",
		Subject:     "principal-0001",
		GrantID:     "ledger-1",
		RedirectURI: "http://127.0.0.1:9090/callback",
		Scope:       []string{"openid", "profile"},
		ExpiresAt:   now.Add(time.Minute),
		CreatedAt:   now,
	}
	if err := ac.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := ac.Find(ctx, "raw-code-secret")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "raw-code-secret" {
		t.Fatalf("Find returned ID %q, want raw value restored", got.ID)
	}
	if len(got.Scope) != 2 {
		t.Fatalf("Find scope = %v", got.Scope)
	}

	if _, err := ac.Find(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find unknown = %v, want ErrNotFound", err)
	}

	consumed, err := ac.Consume(ctx, "raw-code-secret")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("Consume: ConsumedAt is nil")
	}

	if _, err := ac.Consume(ctx, "raw-code-secret"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume = %v, want ErrAlreadyConsumed", err)
	}
	if _, err := ac.Consume(ctx, "never-existed"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume unknown = %v, want ErrNotFound", err)
	}

	// The raw secret must never be persisted: a hand-query for the raw
	// value finds nothing because the column holds its digest.
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vault_grant_codes WHERE token_secret_digest = ?`,
		"raw-code-secret").Scan(&n); err != nil {
		t.Fatalf("digest probe: %v", err)
	}
	if n != 0 {
		t.Fatalf("raw secret found in digest column (%d rows) — hash-on-store violated", n)
	}
}

func TestGrants(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	g := s.Grants()

	now := time.Now()
	grant := &store.Grant{
		ID:        "ledger-1",
		Subject:   "principal-0001",
		ClientID:  "demo-rp",
		Scope:     []string{"openid", "email"},
		AuthTime:  now,
		ACR:       "urn:acr:pwd",
		AMR:       []string{"pwd"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := g.Save(ctx, grant); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := g.Find(ctx, "ledger-1"); err != nil {
		t.Fatalf("Find: %v", err)
	}
	got, err := g.FindBySubjectClient(ctx, "principal-0001", "demo-rp")
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	if got.ID != "ledger-1" {
		t.Fatalf("FindBySubjectClient ID = %q", got.ID)
	}
	has, err := g.HasAny(ctx)
	if err != nil || !has {
		t.Fatalf("HasAny = (%v, %v), want (true, nil)", has, err)
	}
	list, err := g.ListBySubject(ctx, "principal-0001")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListBySubject = (%d, %v)", len(list), err)
	}
	if err := g.Delete(ctx, "ledger-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := g.Find(ctx, "ledger-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Delete = %v, want ErrNotFound", err)
	}
	if err := g.Delete(ctx, "ledger-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("double Delete = %v, want ErrNotFound", err)
	}
}

func TestRefreshTokens(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	rt := s.RefreshTokens()

	now := time.Now()
	if err := rt.Save(ctx, &store.RefreshToken{
		ID: "rt-root", ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "ledger-1", Scope: []string{"openid"},
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := rt.Find(ctx, "rt-root"); err != nil {
		t.Fatalf("Find: %v", err)
	}
	if _, err := rt.Consume(ctx, "rt-root"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if _, err := rt.Consume(ctx, "rt-root"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume = %v, want ErrAlreadyConsumed", err)
	}
	if _, err := rt.Find(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find unknown = %v, want ErrNotFound", err)
	}

	// Rotation chain: child points at parent. RevokeChain must void both.
	parent := "rt-p"
	if err := rt.Save(ctx, &store.RefreshToken{
		ID: parent, ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "ledger-2", Scope: []string{"openid"},
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save parent: %v", err)
	}
	pid := parent
	if err := rt.Save(ctx, &store.RefreshToken{
		ID: "rt-c", ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "ledger-2", Scope: []string{"openid"}, ParentID: &pid,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save child: %v", err)
	}
	if err := rt.RevokeChain(ctx, parent); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	child, err := rt.Find(ctx, "rt-c")
	if err != nil {
		t.Fatalf("Find child after RevokeChain: %v", err)
	}
	if !child.Revoked {
		t.Fatal("child not voided by RevokeChain")
	}

	if err := rt.RevokeByGrant(ctx, "ledger-2"); err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
}

// refreshChainRoot mirrors the walk the OP runs once a replay is detected:
// the first hop presents the raw token the client sent and so goes through
// the bearer-credential Find, while every later hop presents the stored
// chain handle the previous record returned and so goes through
// store.RefreshChainResolver. A store whose parent pointers are digests can
// only be walked this way, which is why implementing the resolver is the
// condition for returning one.
func refreshChainRoot(ctx context.Context, tokens store.RefreshTokenStore, presented string, limit int) (string, error) {
	current := presented
	for i := range limit {
		var (
			rec *store.RefreshToken
			err error
		)
		if i == 0 {
			rec, err = tokens.Find(ctx, current)
		} else {
			resolver, ok := tokens.(store.RefreshChainResolver)
			if !ok {
				return "", errors.New("store does not implement store.RefreshChainResolver")
			}
			rec, err = resolver.FindByStoredHandle(ctx, current)
		}
		if err != nil {
			return "", err
		}
		if rec.ParentID == nil {
			return current, nil
		}
		current = *rec.ParentID
	}
	return "", errors.New("chain walk exceeded its depth limit")
}

// saveRefreshGeneration writes one generation of a rotation chain the way
// the token endpoint does: parent is the RAW id of the token that was just
// consumed, never the handle read back out of storage.
func saveRefreshGeneration(ctx context.Context, t *testing.T, rt store.RefreshTokenStore, id, parent string, now time.Time) {
	t.Helper()
	rec := &store.RefreshToken{
		ID: id, ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "ledger-chain", Scope: []string{"openid"},
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if parent != "" {
		rec.ParentID = &parent
	}
	if err := rt.Save(ctx, rec); err != nil {
		t.Fatalf("Save %s: %v", id, err)
	}
}

// TestRefreshChainReplayRevocation drives a chain several generations deep
// and revokes it from the middle, which is what a stolen-token replay looks
// like. It is the test that pins the raw/handle split end to end: hashing a
// parent pointer twice, or hashing a handle that is already a digest, leaves
// the pointers unable to link up and the cascade stops early.
func TestRefreshChainReplayRevocation(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	rt := s.RefreshTokens()
	now := time.Now()

	// Four generations: save, then consume, then save the successor with
	// the consumed raw id as its parent.
	chain := []string{"gen-0", "gen-1", "gen-2", "gen-3"}
	for i, id := range chain {
		parent := ""
		if i > 0 {
			parent = chain[i-1]
		}
		saveRefreshGeneration(ctx, t, rt, id, parent, now)
		if i < len(chain)-1 {
			if _, err := rt.Consume(ctx, id); err != nil {
				t.Fatalf("Consume %s: %v", id, err)
			}
		}
	}

	// Replay of a generation from the middle of the chain.
	if _, err := rt.Consume(ctx, "gen-1"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("replay Consume = %v, want ErrAlreadyConsumed", err)
	}

	root, err := refreshChainRoot(ctx, rt, "gen-1", len(chain)+1)
	if err != nil {
		t.Fatalf("chain walk from the replayed token: %v", err)
	}
	if root == "gen-0" {
		t.Fatal("chain walk reached the raw predecessor id — the parent pointer is not stored as a digest")
	}
	if err := rt.RevokeChain(ctx, root); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	for _, id := range chain {
		got, err := rt.Find(ctx, id)
		if err != nil {
			t.Fatalf("Find %s after RevokeChain: %v", id, err)
		}
		if !got.Revoked || got.ConsumedAt == nil {
			t.Fatalf("generation %s survived the cascade: revoked=%v consumed=%v", id, got.Revoked, got.ConsumedAt)
		}
	}

	// No generation's raw secret is recoverable from the table: a database
	// reader holds neither a redeemable token nor the material to derive one.
	for _, id := range chain {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM vault_renewal_slips
			 WHERE token_secret_digest = ? OR parent_secret_digest = ?`, id, id).Scan(&n); err != nil {
			t.Fatalf("raw-secret probe for %s: %v", id, err)
		}
		if n != 0 {
			t.Fatalf("raw id %q found in the slips table (%d rows) — hash-on-store violated", id, n)
		}
	}
}

// TestRefreshChainHandles pins the two directions of the credential /
// handle split on the refresh substore.
func TestRefreshChainHandles(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	rt := s.RefreshTokens()
	resolver, ok := rt.(store.RefreshChainResolver)
	if !ok {
		t.Fatal("RefreshTokens() does not implement store.RefreshChainResolver")
	}
	now := time.Now()
	saveRefreshGeneration(ctx, t, rt, "chain-root", "", now)
	saveRefreshGeneration(ctx, t, rt, "chain-mid", "chain-root", now)
	saveRefreshGeneration(ctx, t, rt, "chain-leaf", "chain-mid", now)

	leaf, err := rt.Find(ctx, "chain-leaf")
	if err != nil {
		t.Fatalf("Find leaf: %v", err)
	}
	if leaf.ParentID == nil {
		t.Fatal("Find leaf returned a nil ParentID")
	}
	midHandle := *leaf.ParentID
	if midHandle == "chain-mid" {
		t.Fatal("ParentID is the raw predecessor id, not a stored handle")
	}

	// The handle resolves, and the record it returns carries a ParentID
	// that is itself a handle, so the walk can keep climbing.
	mid, err := resolver.FindByStoredHandle(ctx, midHandle)
	if err != nil {
		t.Fatalf("FindByStoredHandle(mid): %v", err)
	}
	if mid.GrantID != "ledger-chain" {
		t.Fatalf("FindByStoredHandle(mid) returned the wrong record: %+v", mid)
	}
	if mid.ParentID == nil || *mid.ParentID == "chain-root" {
		t.Fatalf("mid.ParentID = %v, want a stored handle for the root", mid.ParentID)
	}
	root, err := resolver.FindByStoredHandle(ctx, *mid.ParentID)
	if err != nil {
		t.Fatalf("FindByStoredHandle(root): %v", err)
	}
	if root.ParentID != nil {
		t.Fatalf("root.ParentID = %v, want nil", root.ParentID)
	}
	if _, err := resolver.FindByStoredHandle(ctx, "not-a-handle"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByStoredHandle(unknown) = %v, want ErrNotFound", err)
	}

	// The security property: a handle read out of storage is inert on the
	// bearer-credential paths, so a digest lifted from a dump, replica, or
	// backup can never be redeemed as a refresh token.
	if _, err := rt.Find(ctx, midHandle); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find(handle) = %v, want ErrNotFound — the stored handle is redeemable", err)
	}
	if _, err := rt.Consume(ctx, midHandle); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume(handle) = %v, want ErrNotFound — the stored handle is redeemable", err)
	}

	// The reverse direction is deliberately not symmetric: a raw id also
	// resolves as a handle, because a chain whose replayed token has no
	// parent hands that raw id straight back as its own root, and both
	// RevokeChain and the resolver have to accept it there.
	if _, err := resolver.FindByStoredHandle(ctx, "chain-root"); err != nil {
		t.Fatalf("FindByStoredHandle(raw root id): %v", err)
	}
	if err := rt.RevokeChain(ctx, "chain-root"); err != nil {
		t.Fatalf("RevokeChain(raw root id): %v", err)
	}
	if err := rt.RevokeChain(ctx, "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeChain(unknown) = %v, want ErrNotFound", err)
	}
}

// TestRefreshRetryResponse covers the RFC 9700 delivery grace window: the
// sealed response rides along with the successor insert and is keyed by the
// predecessor's digest, so it is reachable by presenting the predecessor and
// by nothing else.
func TestRefreshRetryResponse(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	rt := s.RefreshTokens()
	retry, ok := rt.(store.RefreshRetryResponseStore)
	if !ok {
		t.Fatal("RefreshTokens() does not implement store.RefreshRetryResponseStore")
	}
	now := time.Now()
	saveRefreshGeneration(ctx, t, rt, "retry-parent", "", now)
	if _, err := rt.Consume(ctx, "retry-parent"); err != nil {
		t.Fatalf("Consume predecessor: %v", err)
	}

	parent := "retry-parent"
	sealed := []byte("opaque-sealed-token-response")
	if err := retry.SaveRotationWithRetry(ctx, &store.RefreshToken{
		ID: "retry-child", ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "ledger-chain", Scope: []string{"openid"}, ParentID: &parent,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}, sealed); err != nil {
		t.Fatalf("SaveRotationWithRetry: %v", err)
	}

	got, err := retry.LoadRetryResponse(ctx, "retry-parent")
	if err != nil {
		t.Fatalf("LoadRetryResponse: %v", err)
	}
	if string(got) != string(sealed) {
		t.Fatalf("LoadRetryResponse returned %q, want %q", got, sealed)
	}
	if _, err := retry.LoadRetryResponse(ctx, "retry-unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LoadRetryResponse(unknown) = %v, want ErrNotFound", err)
	}

	// The predecessor id is a bearer credential on this path too: the
	// handle stored as the successor's ParentID must not unlock the cache.
	child, err := rt.Find(ctx, "retry-child")
	if err != nil {
		t.Fatalf("Find successor: %v", err)
	}
	if child.ParentID == nil {
		t.Fatal("Find successor returned a nil ParentID")
	}
	if _, err := retry.LoadRetryResponse(ctx, *child.ParentID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LoadRetryResponse(handle) = %v, want ErrNotFound", err)
	}

	// A root token has no predecessor to key a response by.
	if err := retry.SaveRotationWithRetry(ctx, &store.RefreshToken{
		ID: "retry-orphan", ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "ledger-chain", Scope: []string{"openid"},
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}, sealed); err == nil {
		t.Fatal("SaveRotationWithRetry without a parent: want an error")
	}
}

func TestAccessTokens(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	reg := s.AccessTokens()

	now := time.Now()
	rec := store.AccessTokenRecord{
		JTI: "jti-1", GrantID: "ledger-1", Subject: "principal-0001",
		ClientID: "demo-rp", Scopes: []string{"openid"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := reg.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(ctx, rec); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Register = %v, want ErrAlreadyExists", err)
	}
	got, err := reg.Find(ctx, "jti-1")
	if err != nil || got == nil {
		t.Fatalf("Find = (%v, %v)", got, err)
	}
	absent, err := reg.Find(ctx, "nope")
	if err != nil || absent != nil {
		t.Fatalf("Find absent = (%v, %v), want (nil, nil)", absent, err)
	}
	if err := reg.RevokeByJTI(ctx, "jti-1"); err != nil {
		t.Fatalf("RevokeByJTI: %v", err)
	}
	got, _ = reg.Find(ctx, "jti-1")
	if got == nil || !got.Revoked {
		t.Fatal("RevokeByJTI did not flip Revoked")
	}
	if err := reg.RevokeByJTI(ctx, "jti-1"); err != nil {
		t.Fatalf("idempotent RevokeByJTI: %v", err)
	}
	n, err := reg.RevokeByGrant(ctx, "ledger-1")
	if err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	_ = n
}

func TestPAR(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	par := s.PushedAuthRequests()

	now := time.Now()
	uri := "urn:ietf:params:oauth:request_uri:abc123"
	if err := par.Save(ctx, &store.PushedAuthRequest{
		URI: uri, ClientID: "demo-rp", RawParams: []byte(`{"scope":"openid"}`),
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := par.Find(ctx, uri); err != nil {
		t.Fatalf("Find: %v", err)
	}
	if _, err := par.Consume(ctx, uri); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if _, err := par.Consume(ctx, uri); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume = %v, want ErrAlreadyConsumed", err)
	}
	// URI digest, not raw, in storage.
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vault_pushed_handles WHERE handle_digest = ?`, uri).Scan(&n); err != nil {
		t.Fatalf("digest probe: %v", err)
	}
	if n != 0 {
		t.Fatalf("raw URI found in digest column — hash-on-store violated")
	}
}

func TestInteractions(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	in := s.Interactions()

	now := time.Now()
	if err := in.Save(ctx, &store.Interaction{
		ID: "ix-1", ClientID: "demo-rp", Step: "consent",
		RawState: []byte("blob"), ExpiresAt: now.Add(time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := in.Find(ctx, "ix-1"); err != nil {
		t.Fatalf("Find: %v", err)
	}
	if err := in.Delete(ctx, "ix-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := in.Find(ctx, "ix-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Delete = %v, want ErrNotFound", err)
	}
}

func TestConsumedJTIs(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	j := s.ConsumedJTIs()

	now := time.Now()
	if err := j.Mark(ctx, "dpop-jti", now.Add(time.Minute)); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	if err := j.Mark(ctx, "dpop-jti", now.Add(time.Minute)); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Mark = %v, want ErrAlreadyConsumed", err)
	}
	has, err := j.Has(ctx, "dpop-jti")
	if err != nil || !has {
		t.Fatalf("Has = (%v, %v), want (true, nil)", has, err)
	}
	has, err = j.Has(ctx, "unknown")
	if err != nil || has {
		t.Fatalf("Has unknown = (%v, %v), want (false, nil)", has, err)
	}
}

func TestSessions(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	ss := s.Sessions()

	now := time.Now()
	if err := ss.Save(ctx, &store.Session{
		ID: "seat-1", Subject: "principal-0001", AuthTime: now,
		ChooserGroupID: "band-1", ExpiresAt: now.Add(time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := ss.Find(ctx, "seat-1"); err != nil {
		t.Fatalf("Find: %v", err)
	}
	if err := ss.Touch(ctx, "seat-1", now.Add(2*time.Hour), now); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	list, err := ss.ListByChooserGroup(ctx, "band-1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListByChooserGroup = (%d, %v)", len(list), err)
	}
	if err := ss.Delete(ctx, "seat-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := ss.Find(ctx, "seat-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Delete = %v, want ErrNotFound", err)
	}
	if err := ss.Touch(ctx, "seat-1", now, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch missing = %v, want ErrNotFound", err)
	}
}

func TestUsers(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	if err := seedUser(ctx, db); err != nil {
		t.Fatalf("seedUser: %v", err)
	}
	us, ok := s.Users().(store.UserPasswordStore)
	if !ok {
		t.Fatal("Users() does not implement store.UserPasswordStore")
	}
	byName, err := us.FindByUsername(ctx, demoUsername)
	if err != nil {
		t.Fatalf("FindByUsername: %v", err)
	}
	if byName.Subject != demoSubject {
		t.Fatalf("FindByUsername subject = %q", byName.Subject)
	}
	bySub, err := us.FindBySubject(ctx, demoSubject)
	if err != nil {
		t.Fatalf("FindBySubject: %v", err)
	}
	if bySub.Subject != demoSubject {
		t.Fatalf("FindBySubject subject = %q", bySub.Subject)
	}
	hash, err := us.ReadPasswordHash(ctx, demoSubject)
	if err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
	if !strings.HasPrefix(string(hash), "$argon2id$") {
		t.Fatalf("ReadPasswordHash returned %q, want a PHC argon2id string", string(hash))
	}
	if _, err := us.FindByUsername(ctx, "ghost@example.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByUsername unknown = %v, want ErrNotFound", err)
	}
	if _, err := us.ReadPasswordHash(ctx, "principal-ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReadPasswordHash unknown = %v, want ErrNotFound", err)
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	md := s.Metadata()

	if _, err := md.Get(ctx, store.SubjectModeKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get absent = %v, want ErrNotFound", err)
	}
	if err := md.Set(ctx, store.SubjectModeKey, store.SubjectModePublic); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, err := md.Get(ctx, store.SubjectModeKey)
	if err != nil || v != store.SubjectModePublic {
		t.Fatalf("Get = (%q, %v)", v, err)
	}
	// Set is idempotent / upsert.
	if err := md.Set(ctx, store.SubjectModeKey, store.SubjectModePublic); err != nil {
		t.Fatalf("re-Set: %v", err)
	}
}

func TestTransactionCommitAndRollback(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Commit path persists.
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID: "tx-commit", ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "g", RedirectURI: "http://x", Scope: []string{"openid"},
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}); err != nil {
		t.Fatalf("tx Save: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := s.AuthorizationCodes().Find(ctx, "tx-commit"); err != nil {
		t.Fatalf("committed code not visible: %v", err)
	}
	// Commit after Commit returns ErrTxRequired.
	if err := tx.Commit(); !errors.Is(err, store.ErrTxRequired) {
		t.Fatalf("double Commit = %v, want ErrTxRequired", err)
	}

	// Rollback path discards.
	tx2, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx2.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID: "tx-rollback", ClientID: "demo-rp", Subject: "principal-0001",
		GrantID: "g", RedirectURI: "http://x", Scope: []string{"openid"},
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}); err != nil {
		t.Fatalf("tx2 Save: %v", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := s.AuthorizationCodes().Find(ctx, "tx-rollback"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back code visible: %v", err)
	}
	// Rollback after Rollback is a no-op.
	if err := tx2.Rollback(); err != nil {
		t.Fatalf("double Rollback = %v, want nil", err)
	}
}
