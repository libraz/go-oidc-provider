package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file continues the [store.Transactional] contract with the three
// auxiliary substores of the atomic-routing cluster: the JWT access-token
// registry, the opaque access-token store, and the grant-revocation store.
// Their cases are registered in the group table in contract_tx.go, which
// holds the transaction lifecycle and the refresh-rotation cases; the split
// only keeps each file inside the package's size budget.
//
// What these three have in common is that they carry the *other* half of
// every revocation cascade. Retiring a refresh chain kills nothing the
// client already holds: the access tokens minted under the grant stay valid
// until one of these substores says otherwise. A cascade whose refresh half
// commits and whose access-token half does not is the failure the cluster
// exists to prevent, so each case pins the same three points — visible
// inside the transaction, durable after Commit, gone after Rollback.

// --- JWT access-token registry ------------------------------------------------

// txAccessTokenRegisterVisibleAndCommitted pins the registry's place in the
// cluster: the shadow row an issuance writes is readable through the
// transaction that wrote it and is still there after Commit. The row is what
// introspection, userinfo and revocation decide against, so a registration
// that the token endpoint believes it made and the verifier cannot find turns
// a freshly issued token into an unknown one.
func txAccessTokenRegisterVisibleAndCommitted(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireAccessTokens(t, b.Store)

	tx := beginTx(t, txr, ctx)
	registry := requireTxAccessTokens(t, tx)
	rec := newAccessTokenRecord(b.Now(), "tx-at-commit", "tx-at-grant")
	if err := registry.Register(ctx, rec); err != nil {
		t.Fatalf("tx Register: %v", err)
	}
	assertAccessTokenLive(t, registry, rec.JTI)
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertAccessTokenLive(t, outside, rec.JTI)
}

// txAccessTokenRollbackDiscardsRegistration pins the other direction: a
// rotation that fails after registering the shadow row must not leave the row
// behind. A stale registration is not merely clutter — the revocation
// endpoint would report a token that was never issued as live.
func txAccessTokenRollbackDiscardsRegistration(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireAccessTokens(t, b.Store)

	tx := beginTx(t, txr, ctx)
	registry := requireTxAccessTokens(t, tx)
	rec := newAccessTokenRecord(b.Now(), "tx-at-rollback", "tx-at-grant")
	if err := registry.Register(ctx, rec); err != nil {
		t.Fatalf("tx Register: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, ok := findAccessToken(t, outside, rec.JTI); ok {
		t.Fatal("a registration made inside a rolled-back transaction survived it")
	}
}

// txAccessTokenRevokeByGrantCascadesInTx drives the RFC 6749 §4.1.2 cascade
// through a transaction. The count is part of the contract, the retirement
// has to be visible to the transaction that performed it, and it has to
// survive Commit — while the record belonging to another grant stays live,
// which is what keeps a code-replay cascade from logging out every other
// session the user has.
func txAccessTokenRevokeByGrantCascadesInTx(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireAccessTokens(t, b.Store)
	seedAccessTokens(t, outside, ctx,
		newAccessTokenRecord(b.Now(), "tx-at-cascade-a", "tx-at-cascade"),
		newAccessTokenRecord(b.Now(), "tx-at-cascade-b", "tx-at-cascade"),
		newAccessTokenRecord(b.Now(), "tx-at-cascade-other", "tx-at-untouched"),
	)

	tx := beginTx(t, txr, ctx)
	registry := requireTxAccessTokens(t, tx)
	n, err := registry.RevokeByGrant(ctx, "tx-at-cascade")
	if err != nil {
		t.Fatalf("tx RevokeByGrant: %v", err)
	}
	if n != 2 {
		t.Fatalf("tx RevokeByGrant count = %d, want 2", n)
	}
	assertAccessTokenRetired(t, registry, "tx-at-cascade-a")
	assertAccessTokenRetired(t, registry, "tx-at-cascade-b")
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertAccessTokenRetired(t, outside, "tx-at-cascade-a")
	assertAccessTokenRetired(t, outside, "tx-at-cascade-b")
	assertAccessTokenLive(t, outside, "tx-at-cascade-other")
}

func seedAccessTokens(
	t *testing.T,
	registry store.AccessTokenRegistry,
	ctx context.Context,
	records ...store.AccessTokenRecord,
) {
	t.Helper()
	for _, rec := range records {
		if err := registry.Register(ctx, rec); err != nil {
			t.Fatalf("Register %s: %v", rec.JTI, err)
		}
	}
}

// assertAccessTokenLive asserts the record is present and not retired.
func assertAccessTokenLive(t *testing.T, registry store.AccessTokenRegistry, jti string) {
	t.Helper()
	got, ok := findAccessToken(t, registry, jti)
	if !ok {
		t.Fatalf("access token %s reads as absent", jti)
	}
	if got.Revoked {
		t.Fatalf("access token %s reads as revoked: %+v", jti, got)
	}
}

// assertAccessTokenRetired asserts the record is either gone or marked
// revoked; the registry contract permits both spellings.
func assertAccessTokenRetired(t *testing.T, registry store.AccessTokenRegistry, jti string) {
	t.Helper()
	if got, ok := findAccessToken(t, registry, jti); ok && !got.Revoked {
		t.Fatalf("access token %s survived the cascade: %+v", jti, got)
	}
}

// --- opaque access tokens -----------------------------------------------------

// txOpaqueAccessTokenSaveVisibleAndCommitted is
// [txAccessTokenRegisterVisibleAndCommitted] for the opaque-format substore,
// where the stored row is not a shadow of a self-contained token but the token
// itself: a save that a rollback-free transaction lost would leave the client
// holding a credential the OP cannot resolve at all.
func txOpaqueAccessTokenSaveVisibleAndCommitted(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireOpaqueAccessTokens(t, b.Store)

	tx := beginTx(t, txr, ctx)
	at := requireTxOpaqueAccessTokens(t, tx)
	tok := newOpaqueAT(b.Now(), "tx-oat-commit", "tx-oat-grant")
	if err := at.Save(ctx, tok); err != nil {
		t.Fatalf("tx Save: %v", err)
	}
	got, err := at.Find(ctx, tok.ID)
	if err != nil {
		t.Fatalf("tx Find after Save: %v", err)
	}
	if got.ID != tok.ID || got.Revoked {
		t.Fatalf("tx Find returned %+v, want the raw id and Revoked=false", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := outside.Find(ctx, tok.ID); err != nil {
		t.Fatalf("Find after Commit: %v", err)
	}
}

// txOpaqueAccessTokenRollbackDiscardsSave pins that a token minted inside a
// transaction that then failed is not resolvable afterwards.
func txOpaqueAccessTokenRollbackDiscardsSave(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireOpaqueAccessTokens(t, b.Store)

	tx := beginTx(t, txr, ctx)
	at := requireTxOpaqueAccessTokens(t, tx)
	tok := newOpaqueAT(b.Now(), "tx-oat-rollback", "tx-oat-grant")
	if err := at.Save(ctx, tok); err != nil {
		t.Fatalf("tx Save: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := outside.Find(ctx, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Rollback: want ErrNotFound, got %v", err)
	}
}

// txOpaqueAccessTokenRevokeByGrantCascadesInTx is
// [txAccessTokenRevokeByGrantCascadesInTx] for the opaque-format substore.
func txOpaqueAccessTokenRevokeByGrantCascadesInTx(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireOpaqueAccessTokens(t, b.Store)
	seedOpaqueAccessTokens(t, outside, ctx,
		newOpaqueAT(b.Now(), "tx-oat-cascade-a", "tx-oat-cascade"),
		newOpaqueAT(b.Now(), "tx-oat-cascade-b", "tx-oat-cascade"),
		newOpaqueAT(b.Now(), "tx-oat-cascade-other", "tx-oat-untouched"),
	)

	tx := beginTx(t, txr, ctx)
	at := requireTxOpaqueAccessTokens(t, tx)
	n, err := at.RevokeByGrant(ctx, "tx-oat-cascade")
	if err != nil {
		t.Fatalf("tx RevokeByGrant: %v", err)
	}
	if n != 2 {
		t.Fatalf("tx RevokeByGrant count = %d, want 2", n)
	}
	assertOpaqueAccessTokenRetired(t, at, "tx-oat-cascade-a")
	assertOpaqueAccessTokenRetired(t, at, "tx-oat-cascade-b")
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertOpaqueAccessTokenRetired(t, outside, "tx-oat-cascade-a")
	assertOpaqueAccessTokenRetired(t, outside, "tx-oat-cascade-b")
	survivor, err := outside.Find(ctx, "tx-oat-cascade-other")
	if err != nil {
		t.Fatalf("Find token of another grant: %v", err)
	}
	if survivor.Revoked {
		t.Fatal("the cascade revoked an opaque access token belonging to another grant")
	}
}

func seedOpaqueAccessTokens(
	t *testing.T,
	at store.OpaqueAccessTokenStore,
	ctx context.Context,
	tokens ...*store.OpaqueAccessToken,
) {
	t.Helper()
	for _, tok := range tokens {
		if err := at.Save(ctx, tok); err != nil {
			t.Fatalf("Save %s: %v", tok.ID, err)
		}
	}
}

// assertOpaqueAccessTokenRetired asserts the record is either gone or marked
// revoked; the substore contract permits backends to delete revoked rows.
func assertOpaqueAccessTokenRetired(t *testing.T, at store.OpaqueAccessTokenStore, id string) {
	t.Helper()
	got, err := at.Find(context.Background(), id)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatalf("Find %s: %v", id, err)
	}
	if !got.Revoked {
		t.Fatalf("opaque access token %s survived the cascade: %+v", id, got)
	}
}

// --- grant revocation ---------------------------------------------------------

// txGrantTombstoneVisibleAndCommitted pins the tombstone half of the cascade
// inside a transaction. The tombstone is what retires self-contained access
// tokens the OP cannot reach individually, so it is written in the same
// transaction as the rest of the cascade — and a verifier consulted after the
// commit must see it, or every JWT minted under the grant keeps verifying.
func txGrantTombstoneVisibleAndCommitted(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireGrantRevocations(t, b.Store)
	now := b.Now()

	tx := beginTx(t, txr, ctx)
	gr := requireTxGrantRevocations(t, tx)
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "tx-tombstone-commit",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "code_replay",
	}); err != nil {
		t.Fatalf("tx RevokeGrant: %v", err)
	}
	expectRevoked(t, gr, ctx, "tx-tombstone-commit", "", now.Add(-time.Second), true,
		"the revoking transaction does not see its own tombstone")
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	expectRevoked(t, outside, ctx, "tx-tombstone-commit", "", now.Add(-time.Second), true,
		"the tombstone did not survive Commit: every access token of the grant verifies again")
}

// txGrantTombstoneRollbackDiscardsTombstone pins the other direction. A
// tombstone is the coarsest instrument the OP has — it retires every token of
// a grant at once — so one that outlived the transaction that decided against
// it would log a user out on the strength of a request that failed.
func txGrantTombstoneRollbackDiscardsTombstone(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireGrantRevocations(t, b.Store)
	now := b.Now()

	tx := beginTx(t, txr, ctx)
	gr := requireTxGrantRevocations(t, tx)
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "tx-tombstone-rollback",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "code_replay",
	}); err != nil {
		t.Fatalf("tx RevokeGrant: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	expectRevoked(t, outside, ctx, "tx-tombstone-rollback", "", now.Add(-time.Second), false,
		"a tombstone written in a rolled-back transaction still revokes the grant")
}
