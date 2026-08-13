package contract

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file holds the contract sub-tests for the [store.Transactional]
// extension: what a backend must guarantee once the atomic-routing cluster
// is driven through a [store.Tx] handle instead of through the substore
// accessors of the aggregate.
//
// The distinction is not cosmetic. The OP runs refresh-token rotation and
// the RFC 9700 §2.2.2 replay cascade inside a transaction, so for those
// paths the transactional substores are the only implementation that ever
// executes in production. A backend whose Tx substores are a second,
// thinner implementation of the same interfaces can satisfy every
// sequential case elsewhere in the harness and still lose single-use, drop
// the cascade, or leave a rolled-back revocation applied — none of which
// the non-transactional groups can observe.
//
// Each case therefore pins one of three things: the semantics hold inside
// the transaction (read-your-own-writes), they survive Commit, or they
// vanish on Rollback.

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var transactionalCases = []subtest{
	{"BeginCommit", txBeginCommit},
	{"BeginRollback", txBeginRollback},
	{"RollbackAfterCommitNoOp", txRollbackAfterCommitNoOp},
	{"UseAfterCommitReportsTxRequired", txUseAfterCommitReportsTxRequired},
	{"CrossSubstore", txCrossSubstore},
	{"PARConsumeExpiredStillRedeems", txPARConsumeExpiredStillRedeems},
	{"RefreshConsumeReplayReturnsRecord", txRefreshConsumeReplayReturnsRecord},
	{"RefreshConsumeIsSingleShotAcrossTx", txRefreshConsumeIsSingleShotAcrossTx},
	{"RefreshRevokeChainVisibleInTx", txRefreshRevokeChainVisibleInTx},
	{"RefreshRevokeChainCommitRevokesDescendants", txRefreshRevokeChainCommitRevokesDescendants},
	{"RefreshRevokeChainRollbackLeavesChainLive", txRefreshRevokeChainRollbackLeavesChainLive},
	{"RefreshRevokeByGrantCommitRevokesGrant", txRefreshRevokeByGrantCommitRevokesGrant},
	{"RefreshRevokeByGrantRollbackLeavesGrantLive", txRefreshRevokeByGrantRollbackLeavesGrantLive},
	{"RefreshSaveOntoRevokedParent", txRefreshSaveOntoRevokedParent},
	{"RefreshSaveOntoParentRevokedByCommittedTx", txRefreshSaveOntoParentRevokedByCommittedTx},
	{"RefreshRetryResponseVisibleInTx", txRefreshRetryResponseVisibleInTx},
	{"RefreshRetryResponseSurvivesCommit", txRefreshRetryResponseSurvivesCommit},
	{"RefreshRetryResponseRollbackDiscardsBoth", txRefreshRetryResponseRollbackDiscardsBoth},
	{"RefreshRetryRotationOntoRevokedParent", txRefreshRetryRotationOntoRevokedParent},
	{"AccessTokenRegisterVisibleAndCommitted", txAccessTokenRegisterVisibleAndCommitted},
	{"AccessTokenRollbackDiscardsRegistration", txAccessTokenRollbackDiscardsRegistration},
	{"AccessTokenRevokeByGrantCascadesInTx", txAccessTokenRevokeByGrantCascadesInTx},
	{"OpaqueAccessTokenSaveVisibleAndCommitted", txOpaqueAccessTokenSaveVisibleAndCommitted},
	{"OpaqueAccessTokenRollbackDiscardsSave", txOpaqueAccessTokenRollbackDiscardsSave},
	{"OpaqueAccessTokenRevokeByGrantCascadesInTx", txOpaqueAccessTokenRevokeByGrantCascadesInTx},
	{"GrantTombstoneVisibleAndCommitted", txGrantTombstoneVisibleAndCommitted},
	{"GrantTombstoneRollbackDiscardsTombstone", txGrantTombstoneRollbackDiscardsTombstone},
}

// --- harness helpers ---------------------------------------------------------

// beginTx opens a transaction and registers a rollback so a case that fails
// part-way through still releases whatever the backend holds for it. Cases
// that go on to commit can use it too: [store.Tx.Rollback] is required to be
// a no-op after Commit.
func beginTx(t *testing.T, txr store.Transactional, ctx context.Context) store.Tx {
	t.Helper()
	tx, err := txr.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}

// seedRefreshTokens persists tokens through the non-transactional path so a
// case can arrange a chain before it opens the transaction under test.
// Seeding outside the transaction is deliberate: backends that hold the
// atomic cluster for the lifetime of a Tx cannot service the aggregate's own
// substore handles while one is open.
func seedRefreshTokens(t *testing.T, s store.Store, ctx context.Context, tokens ...*store.RefreshToken) {
	t.Helper()
	for _, rt := range tokens {
		if err := s.RefreshTokens().Save(ctx, rt); err != nil {
			t.Fatalf("Save %s: %v", rt.ID, err)
		}
	}
}

// requireRetryResponses returns the RFC 9700 grace-window extension of the
// aggregate's refresh substore, skipping when the backend does not implement
// it. A backend that cannot make the successor insert and the cache write one
// operation is required not to expose the interface.
func requireRetryResponses(t *testing.T, s store.Store) store.RefreshRetryResponseStore {
	t.Helper()
	retry, ok := s.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Skipf("backend %T does not implement store.RefreshRetryResponseStore", s.RefreshTokens())
	}
	return retry
}

// requireTxRetryResponses is [requireRetryResponses] for the substore handle
// bound to a transaction. The two are probed separately because a backend
// implements them separately: the extension exists precisely to make the
// successor insert and the cache write atomic, so a Tx that dropped it would
// leave the token endpoint no atomic path at all.
func requireTxRetryResponses(t *testing.T, tx store.Tx) store.RefreshRetryResponseStore {
	t.Helper()
	retry, ok := tx.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Skipf("backend %T does not implement store.RefreshRetryResponseStore", tx.RefreshTokens())
	}
	return retry
}

// requireTxAccessTokens fetches the transaction's JWT access-token registry,
// skipping when the backend opts out by returning nil — the same allowance
// [requireAccessTokens] makes for the aggregate.
func requireTxAccessTokens(t *testing.T, tx store.Tx) store.AccessTokenRegistry {
	t.Helper()
	registry := tx.AccessTokens()
	if registry == nil {
		t.Skipf("backend %T returns nil from Tx.AccessTokens()", tx)
	}
	return registry
}

// requireTxOpaqueAccessTokens fetches the transaction's opaque access-token
// substore, skipping when the backend returns nil.
func requireTxOpaqueAccessTokens(t *testing.T, tx store.Tx) store.OpaqueAccessTokenStore {
	t.Helper()
	at := tx.OpaqueAccessTokens()
	if at == nil {
		t.Skipf("backend %T returns nil from Tx.OpaqueAccessTokens()", tx)
	}
	return at
}

// requireTxGrantRevocations fetches the transaction's grant-revocation
// substore, skipping when the backend returns nil.
func requireTxGrantRevocations(t *testing.T, tx store.Tx) store.GrantRevocationStore {
	t.Helper()
	gr := tx.GrantRevocations()
	if gr == nil {
		t.Skipf("backend %T returns nil from Tx.GrantRevocations()", tx)
	}
	return gr
}

// --- transaction lifecycle ---------------------------------------------------

func txBeginCommit(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	tx := beginTx(t, txr, ctx)
	requireSubstoresNonNil(t, tx)
	code := newAuthCode(b.Now(), "tx-ac")
	if err := tx.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save in tx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	got, err := b.Store.AuthorizationCodes().Find(ctx, "tx-ac")
	if err != nil {
		t.Fatalf("Find after Commit: %v", err)
	}
	if got.ID != "tx-ac" {
		t.Fatalf("unexpected committed record: %+v", got)
	}
}

func requireSubstoresNonNil(t *testing.T, tx store.Tx) {
	t.Helper()
	if tx.AuthorizationCodes() == nil || tx.RefreshTokens() == nil ||
		tx.Grants() == nil || tx.PushedAuthRequests() == nil {
		t.Fatal("Tx returned nil substore handle")
	}
}

func txBeginRollback(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	tx, err := txr.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	code := newAuthCode(b.Now(), "tx-rb")
	if err := tx.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save in tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	_, err = b.Store.AuthorizationCodes().Find(ctx, "tx-rb")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Rollback: want ErrNotFound, got %v", err)
	}
}

func txRollbackAfterCommitNoOp(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	tx, err := txr.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback after Commit must be a no-op, got %v", err)
	}
}

// txUseAfterCommitReportsTxRequired pins what a settled handle owes the
// caller that keeps using it. [store.Tx.Commit] declares that every later
// call — read, write, or a second Commit — fails with an error satisfying
// errors.Is(err, [store.ErrTxRequired]), and the reads are the half a
// backend is most likely to leave open: the write path already has a
// staging buffer or a driver to refuse it, while a read can quietly fall
// through to the backing store.
//
// Both failure shapes it catches are worse than a plain missing check. A
// read that answers from the table with a nil error tells the handler it
// is still inside a transaction that no longer exists, and it acts on a
// record carrying none of the isolation it believes it has. A refusal
// that reports a backend-specific error instead of the sentinel is
// indistinguishable from a transport fault, so the retry loop above it
// re-drives a request whose defect is a leaked handle, forever.
//
// Every substore of the cluster is seeded through the aggregate first, so
// the settled reads have live data available to leak and a refusal cannot
// be mistaken for an empty store.
func txUseAfterCommitReportsTxRequired(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	seedSettledRecords(t, b, ctx)

	tx := beginTx(t, txr, ctx)
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	assertSettledReadsRefused(t, tx, ctx)

	orphan := newAuthCode(b.Now(), "tx-settled-orphan")
	assertTxRequired(t, "AuthorizationCodes().Save", false, tx.AuthorizationCodes().Save(ctx, orphan))
	assertTxRequired(t, "second Commit", false, tx.Commit())

	// The refused write must not have landed either: a backend that
	// reported the sentinel and staged the record anyway would publish it
	// on whatever transaction commits next.
	if _, err := b.Store.AuthorizationCodes().Find(ctx, orphan.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find the code a committed Tx refused to save: want ErrNotFound, got %v", err)
	}
}

// seedSettledRecords writes one record into each cluster substore
// [assertSettledReadsRefused] then looks for. Seeding runs through the
// aggregate and before BeginTx because backends that hold the cluster for
// the lifetime of a transaction cannot service the aggregate while one is
// open.
func seedSettledRecords(t *testing.T, b Backend, ctx context.Context) {
	t.Helper()
	if err := b.Store.AuthorizationCodes().Save(ctx, newAuthCode(b.Now(), "tx-settled-code")); err != nil {
		t.Fatalf("Save code: %v", err)
	}
	if err := b.Store.Grants().Save(ctx, newGrant(b.Now(), "tx-settled-grant", "sub", "client")); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	seedRefreshTokens(t, b.Store, ctx, newRefresh(b.Now(), "tx-settled-refresh", nil))
	if err := b.Store.PushedAuthRequests().Save(ctx, newPAR(b.Now(), "urn:par:tx-settled")); err != nil {
		t.Fatalf("Save PAR: %v", err)
	}
}

// assertSettledReadsRefused drives one lookup through each cluster
// substore of a settled handle. The four are checked together because a
// backend guards them one implementation at a time: a substore whose read
// path was written separately from the others is exactly where the gap
// survives.
func assertSettledReadsRefused(t *testing.T, tx store.Tx, ctx context.Context) {
	t.Helper()
	gotCode, err := tx.AuthorizationCodes().Find(ctx, "tx-settled-code")
	assertTxRequired(t, "AuthorizationCodes().Find", gotCode != nil, err)
	gotGrant, err := tx.Grants().Find(ctx, "tx-settled-grant")
	assertTxRequired(t, "Grants().Find", gotGrant != nil, err)
	gotRefresh, err := tx.RefreshTokens().Find(ctx, "tx-settled-refresh")
	assertTxRequired(t, "RefreshTokens().Find", gotRefresh != nil, err)
	gotPAR, err := tx.PushedAuthRequests().Find(ctx, "urn:par:tx-settled")
	assertTxRequired(t, "PushedAuthRequests().Find", gotPAR != nil, err)
	// The grace-window cache is an extension, so it is asserted only when
	// the backend exposes it — but the case itself never skips: the
	// mandatory four above are what a backend advertising
	// [store.Transactional] has to answer for.
	if retry, ok := tx.RefreshTokens().(store.RefreshRetryResponseStore); ok {
		sealed, err := retry.LoadRetryResponse(ctx, "tx-settled-refresh")
		assertTxRequired(t, "LoadRetryResponse", sealed != nil, err)
	}
}

// assertTxRequired asserts that one call made through a settled handle
// failed the way [store.Tx.Commit] requires. found reports whether the
// backend produced a record anyway, which is how a read that fell through
// to the backing store shows up.
func assertTxRequired(t *testing.T, op string, found bool, err error) {
	t.Helper()
	switch {
	case err == nil && found:
		t.Fatalf("%s through a committed Tx returned a record with a nil error: the call reached the "+
			"backing store, so a caller holding a closed handle cannot tell it left the transaction", op)
	case err == nil:
		t.Fatalf("%s through a committed Tx: want an error satisfying store.ErrTxRequired, got nil", op)
	case !errors.Is(err, store.ErrTxRequired):
		t.Fatalf("%s through a committed Tx: want an error satisfying store.ErrTxRequired, got %v — "+
			"a caller cannot tell a closed handle from a transport fault and retries it", op, err)
	case found:
		t.Fatalf("%s through a committed Tx returned a record alongside %v", op, err)
	}
}

func txCrossSubstore(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	tx := beginTx(t, txr, ctx)
	if err := saveCrossSubstore(ctx, tx, b.Now()); err != nil {
		t.Fatalf("save in tx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := b.Store.Grants().Find(ctx, "tx-g"); err != nil {
		t.Fatalf("Find grant: %v", err)
	}
	if _, err := b.Store.AuthorizationCodes().Find(ctx, "tx-c"); err != nil {
		t.Fatalf("Find code: %v", err)
	}
}

func saveCrossSubstore(ctx context.Context, tx store.Tx, now time.Time) error {
	grant := newGrant(now, "tx-g", "sub", "client")
	if err := tx.Grants().Save(ctx, grant); err != nil {
		return err
	}
	code := newAuthCode(now, "tx-c")
	code.GrantID = "tx-g"
	return tx.AuthorizationCodes().Save(ctx, code)
}

// txPARConsumeExpiredStillRedeems mirrors [parConsumeExpiredStillRedeems] on
// the transactional path: an embedder that consumes the request_uri inside a
// BeginTx transaction (so the consume is atomic with the authorization code's
// existence) MUST see the same single-use-only Consume contract — expiry is
// gated at presentation by Find, not at Consume. This pins the two Consume
// implementations against drift.
func txPARConsumeExpiredStillRedeems(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	par := newPAR(b.Now(), "urn:par:tx-exp-consume")
	par.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	tx := beginTx(t, txr, ctx)
	got, err := tx.PushedAuthRequests().Consume(ctx, "urn:par:tx-exp-consume")
	if err != nil {
		t.Fatalf("tx Consume expired-but-unconsumed: want success, got %v", err)
	}
	if got.ConsumedAt == nil {
		t.Fatal("tx Consume returned ConsumedAt=nil")
	}
	if _, err := tx.PushedAuthRequests().Consume(ctx, "urn:par:tx-exp-consume"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second tx Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

// --- refresh-token rotation and the replay cascade ---------------------------

// txRefreshConsumeReplayReturnsRecord mirrors the replay half of
// [refreshSaveFindConsume] on the transactional path. The transactional and
// non-transactional variants of one backend must agree that
// [store.ErrAlreadyConsumed] carries the consumed record: the replay handler
// recovers the chain root from it, and a nil record inside a transaction
// silently degrades the RFC 9700 §2.2.2 cascade to a best-effort lookup.
func txRefreshConsumeReplayReturnsRecord(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	rt := newRefresh(b.Now(), "tx-rt-replay", nil)
	seedRefreshTokens(t, b.Store, ctx, rt)
	tx := beginTx(t, txr, ctx)
	if _, err := tx.RefreshTokens().Consume(ctx, rt.ID); err != nil {
		t.Fatalf("first tx Consume: %v", err)
	}
	replayed, err := tx.RefreshTokens().Consume(ctx, rt.ID)
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second tx Consume: want ErrAlreadyConsumed, got %v", err)
	}
	if replayed == nil {
		t.Fatal("second tx Consume returned nil record with ErrAlreadyConsumed")
	}
	if replayed.ConsumedAt == nil {
		t.Fatal("second tx Consume returned ConsumedAt=nil")
	}
}

// txRefreshConsumeIsSingleShotAcrossTx pins single-use across the transaction
// boundary rather than within one transaction. Rotation commits the consume
// and the successor together, so the presentation that matters for replay
// detection is the one that arrives on a *later* transaction, after the first
// rotation is durable.
//
// A backend that stamped ConsumedAt only in its transaction-local view — or
// that re-read the record from a stale snapshot — would hand the second
// presenter a second successor, which is exactly the double-spend RFC 9700
// §2.2.2 exists to catch. The case also pins the two implementations against
// each other: the same token must read as consumed through the aggregate's
// own substore afterwards.
func txRefreshConsumeIsSingleShotAcrossTx(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	rt := newRefresh(b.Now(), "tx-rt-single-shot", nil)
	seedRefreshTokens(t, b.Store, ctx, rt)

	rotating := beginTx(t, txr, ctx)
	consumed, err := rotating.RefreshTokens().Consume(ctx, rt.ID)
	if err != nil {
		t.Fatalf("tx Consume: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("tx Consume returned ConsumedAt=nil")
	}
	if err := rotating.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	replaying := beginTx(t, txr, ctx)
	replayed, err := replaying.RefreshTokens().Consume(ctx, rt.ID)
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume in a later transaction: want ErrAlreadyConsumed, got %v", err)
	}
	if replayed == nil || replayed.ConsumedAt == nil {
		t.Fatal("replay Consume must return the consumed record so the cascade can recover the chain root")
	}
	if err := replaying.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if _, err := b.Store.RefreshTokens().Consume(ctx, rt.ID); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume outside a transaction after a committed tx Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

// txRefreshRevokeChainVisibleInTx pins the read-your-own-writes rule declared
// on [store.Tx]: a chain revoked inside a transaction must read back as
// revoked through that same transaction, flag included. A backend that defers
// the tombstone to Commit lets a handler that revokes and then re-reads treat
// a dead chain as merely rotated, which is exactly the distinction the grace
// window turns on.
func txRefreshRevokeChainVisibleInTx(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	root := newRefresh(b.Now(), "tx-chain-root", nil)
	child := newRefresh(b.Now(), "tx-chain-child", &root.ID)
	seedRefreshTokens(t, b.Store, ctx, root, child)
	tx := beginTx(t, txr, ctx)
	if err := tx.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}
	for _, id := range []string{root.ID, child.ID} {
		assertRevokedInTx(t, tx, id)
	}
}

// assertRevokedInTx asserts that a refresh token read through tx is either
// absent or carries both ConsumedAt and Revoked. Backends may delete or mark;
// what they may not do is report a cascade-retired record as an ordinary
// rotated one.
func assertRevokedInTx(t *testing.T, tx store.Tx, id string) {
	t.Helper()
	got, err := tx.RefreshTokens().Find(context.Background(), id)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatalf("tx Find %s: %v", id, err)
	}
	if got.ConsumedAt == nil {
		t.Fatalf("token %s: ConsumedAt=nil inside the revoking transaction", id)
	}
	if !got.Revoked {
		t.Fatalf("token %s: Revoked=false inside the revoking transaction", id)
	}
}

// txRefreshRevokeChainCommitRevokesDescendants pins the durable half of the
// cascade. [txRefreshRevokeChainVisibleInTx] only proves the revoking
// transaction can see its own work; what the replay response actually depends
// on is that every descendant is still retired once the transaction commits
// and the presenter comes back on a fresh connection.
//
// The unrelated chain is seeded for the other direction: a cascade that
// revoked by something coarser than the chain — the client, say, or the whole
// table — would pass a descendants-only assertion and log every other session
// of that user out.
func txRefreshRevokeChainCommitRevokesDescendants(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	root := newRefresh(b.Now(), "tx-commit-root", nil)
	mid := newRefresh(b.Now(), "tx-commit-mid", &root.ID)
	leaf := newRefresh(b.Now(), "tx-commit-leaf", &mid.ID)
	other := newRefresh(b.Now(), "tx-commit-other", nil)
	seedRefreshTokens(t, b.Store, ctx, root, mid, leaf, other)

	tx := beginTx(t, txr, ctx)
	if err := tx.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, id := range []string{root.ID, mid.ID, leaf.ID} {
		assertRevoked(t, b.Store, id)
	}
	assertRefreshLive(t, b.Store, other.ID)
}

// txRefreshRevokeChainRollbackLeavesChainLive pins the other side of the same
// operation: [store.Tx.Rollback] discards every change made through the
// transaction's substore handles, and a cascade is a change like any other.
//
// The rollback path is reached whenever the rotation the cascade was part of
// fails afterwards — a failed successor insert, a commit conflict, a request
// the client abandoned. A backend that revoked out-of-band, outside whatever
// the transaction can undo, would retire a chain the OP decided not to
// retire, and the user's client is logged out by a request that failed.
func txRefreshRevokeChainRollbackLeavesChainLive(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	root := newRefresh(b.Now(), "tx-rollback-root", nil)
	mid := newRefresh(b.Now(), "tx-rollback-mid", &root.ID)
	leaf := newRefresh(b.Now(), "tx-rollback-leaf", &mid.ID)
	seedRefreshTokens(t, b.Store, ctx, root, mid, leaf)

	tx := beginTx(t, txr, ctx)
	if err := tx.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}
	// Assert the cascade really ran before rolling it back, so a backend
	// whose RevokeChain is a no-op cannot pass this case by doing nothing.
	assertRevokedInTx(t, tx, leaf.ID)
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	for _, id := range []string{root.ID, mid.ID, leaf.ID} {
		assertRefreshLive(t, b.Store, id)
	}
}

// txRefreshRevokeByGrantCommitRevokesGrant is
// [txRefreshRevokeChainCommitRevokesDescendants] for the other cascade axis.
// RevokeByGrant is what the RFC 6749 §4.1.2 code-replay path calls, and it
// has to reach chains that share the grant without descending from one
// another — a backend that implemented it as "walk the chain from the first
// match" would leave every sibling root redeemable.
func txRefreshRevokeByGrantCommitRevokesGrant(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	targetA := newRefresh(b.Now(), "tx-grant-a", nil)
	targetA.GrantID = "tx-grant-target"
	targetB := newRefresh(b.Now(), "tx-grant-b", nil)
	targetB.GrantID = "tx-grant-target"
	other := newRefresh(b.Now(), "tx-grant-other", nil)
	other.GrantID = "tx-grant-untouched"
	seedRefreshTokens(t, b.Store, ctx, targetA, targetB, other)

	tx := beginTx(t, txr, ctx)
	if err := tx.RefreshTokens().RevokeByGrant(ctx, "tx-grant-target"); err != nil {
		t.Fatalf("tx RevokeByGrant: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertRevoked(t, b.Store, targetA.ID)
	assertRevoked(t, b.Store, targetB.ID)
	assertRefreshLive(t, b.Store, other.ID)
}

// txRefreshRevokeByGrantRollbackLeavesGrantLive is
// [txRefreshRevokeChainRollbackLeavesChainLive] for the grant axis.
func txRefreshRevokeByGrantRollbackLeavesGrantLive(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	targetA := newRefresh(b.Now(), "tx-grant-rollback-a", nil)
	targetA.GrantID = "tx-grant-rollback"
	targetB := newRefresh(b.Now(), "tx-grant-rollback-b", nil)
	targetB.GrantID = "tx-grant-rollback"
	seedRefreshTokens(t, b.Store, ctx, targetA, targetB)

	tx := beginTx(t, txr, ctx)
	if err := tx.RefreshTokens().RevokeByGrant(ctx, "tx-grant-rollback"); err != nil {
		t.Fatalf("tx RevokeByGrant: %v", err)
	}
	assertRevokedInTx(t, tx, targetA.ID)
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	assertRefreshLive(t, b.Store, targetA.ID)
	assertRefreshLive(t, b.Store, targetB.ID)
}

// txRefreshSaveOntoRevokedParent mirrors [refreshSaveOntoRevokedParent] on the
// transactional path so the two Save implementations of one backend cannot
// drift: a rotation onto a chain this transaction has already revoked must be
// refused with [store.ErrAlreadyConsumed].
func txRefreshSaveOntoRevokedParent(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	root := newRefresh(b.Now(), "tx-revoked-parent-root", nil)
	seedRefreshTokens(t, b.Store, ctx, root)
	tx := beginTx(t, txr, ctx)
	if err := tx.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}
	child := newRefresh(b.Now(), "tx-revoked-parent-child", &root.ID)
	if err := tx.RefreshTokens().Save(ctx, child); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("tx Save onto revoked parent: want ErrAlreadyConsumed, got %v", err)
	}
}

// txRefreshSaveOntoParentRevokedByCommittedTx is the durable form of
// [txRefreshSaveOntoRevokedParent]: the cascade committed in an earlier
// transaction, and the rotation arrives in a later one. This is the shape the
// race actually takes in production — the replay handler and the legitimate
// client's rotation are different requests — and it is the one a backend can
// fail while passing the same-transaction case, because there the check can
// be answered from the transaction's own staged writes.
//
// The post-condition after the caller aborts is the one [store.RefreshTokenStore.Save]
// names: a descendant of a revoked chain MUST NOT be redeemable afterwards.
func txRefreshSaveOntoParentRevokedByCommittedTx(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	root := newRefresh(b.Now(), "tx-committed-revoke-root", nil)
	seedRefreshTokens(t, b.Store, ctx, root)

	cascade := beginTx(t, txr, ctx)
	if err := cascade.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}
	if err := cascade.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	rotation := beginTx(t, txr, ctx)
	child := newRefresh(b.Now(), "tx-committed-revoke-child", &root.ID)
	if err := rotation.RefreshTokens().Save(ctx, child); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("tx Save onto a chain revoked by an earlier transaction: want ErrAlreadyConsumed, got %v", err)
	}
	// The contract lets a backend satisfy the post-condition by relying on
	// the caller aborting, which is what a token endpoint does with a
	// failed rotation.
	if err := rotation.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	assertRevoked(t, b.Store, child.ID)
}

// txRefreshRetryResponseVisibleInTx pins read-your-own-writes for the RFC 9700
// grace-window cache. The rotation stores the sealed response and the
// successor in one operation, and a handler that re-reads the cache inside the
// same transaction — to confirm what it is about to return, or to serve a
// retry that arrived on the same connection — must see what it just wrote.
//
// A backend that reads the cache straight from the committed table while
// writing it into the transaction reports "no retry response" for a rotation
// it is holding in its own buffer.
func txRefreshRetryResponseVisibleInTx(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	predecessor := newRefresh(b.Now(), "tx-retry-visible-parent", nil)
	seedRefreshTokens(t, b.Store, ctx, predecessor)
	if _, err := b.Store.RefreshTokens().Consume(ctx, predecessor.ID); err != nil {
		t.Fatalf("Consume predecessor: %v", err)
	}

	tx := beginTx(t, txr, ctx)
	retry := requireTxRetryResponses(t, tx)
	sealed := []byte("sealed-token-response")
	successor := newRefresh(b.Now(), "tx-retry-visible-child", &predecessor.ID)
	if err := retry.SaveRotationWithRetry(ctx, successor, sealed); err != nil {
		t.Fatalf("tx SaveRotationWithRetry: %v", err)
	}
	got, err := retry.LoadRetryResponse(ctx, predecessor.ID)
	if err != nil {
		t.Fatalf("LoadRetryResponse inside the rotating transaction: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Errorf("LoadRetryResponse in tx = %q, want %q", got, sealed)
	}
	// The successor is an ordinary refresh token; storing the retry copy
	// alongside it must not change that, inside the transaction either.
	if _, err := tx.RefreshTokens().Find(ctx, successor.ID); err != nil {
		t.Fatalf("tx Find successor after SaveRotationWithRetry: %v", err)
	}
}

// txRefreshRetryResponseSurvivesCommit pins the association the grace window
// actually reads on a retry: the sealed response is reachable by the
// *predecessor* the client re-presents, after the rotating transaction
// committed and the retry arrives as a separate request.
//
// A backend that kept the cache write transaction-local, or keyed it by the
// successor, answers a genuine retry with "no retry response" and sends a
// client holding a legitimate token down the replay-revocation path.
func txRefreshRetryResponseSurvivesCommit(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireRetryResponses(t, b.Store)
	predecessor := newRefresh(b.Now(), "tx-retry-commit-parent", nil)
	seedRefreshTokens(t, b.Store, ctx, predecessor)
	if _, err := b.Store.RefreshTokens().Consume(ctx, predecessor.ID); err != nil {
		t.Fatalf("Consume predecessor: %v", err)
	}

	tx := beginTx(t, txr, ctx)
	retry := requireTxRetryResponses(t, tx)
	sealed := []byte("sealed-token-response")
	successor := newRefresh(b.Now(), "tx-retry-commit-child", &predecessor.ID)
	if err := retry.SaveRotationWithRetry(ctx, successor, sealed); err != nil {
		t.Fatalf("tx SaveRotationWithRetry: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := outside.LoadRetryResponse(ctx, predecessor.ID)
	if err != nil {
		t.Fatalf("LoadRetryResponse after Commit: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Errorf("LoadRetryResponse after Commit = %q, want %q", got, sealed)
	}
	if _, err := b.Store.RefreshTokens().Find(ctx, successor.ID); err != nil {
		t.Fatalf("Find successor after Commit: %v", err)
	}
}

// txRefreshRetryResponseRollbackDiscardsBoth pins the atomicity the extension
// exists for, in the direction a partial implementation gets wrong. Neither
// half may survive a rollback: a surviving successor is a credential the
// client was never handed, and a surviving cache entry would answer a later
// presentation of the predecessor with a response describing tokens that were
// never issued.
func txRefreshRetryResponseRollbackDiscardsBoth(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	outside := requireRetryResponses(t, b.Store)
	predecessor := newRefresh(b.Now(), "tx-retry-rollback-parent", nil)
	seedRefreshTokens(t, b.Store, ctx, predecessor)
	if _, err := b.Store.RefreshTokens().Consume(ctx, predecessor.ID); err != nil {
		t.Fatalf("Consume predecessor: %v", err)
	}

	tx := beginTx(t, txr, ctx)
	retry := requireTxRetryResponses(t, tx)
	successor := newRefresh(b.Now(), "tx-retry-rollback-child", &predecessor.ID)
	if err := retry.SaveRotationWithRetry(ctx, successor, []byte("sealed-token-response")); err != nil {
		t.Fatalf("tx SaveRotationWithRetry: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if _, err := b.Store.RefreshTokens().Find(ctx, successor.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find successor after Rollback: want ErrNotFound, got %v", err)
	}
	if _, err := outside.LoadRetryResponse(ctx, predecessor.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LoadRetryResponse after Rollback: want ErrNotFound, got %v", err)
	}
}

// txRefreshRetryRotationOntoRevokedParent pins the replay half of the
// semantics [store.RefreshRetryResponseStore.SaveRotationWithRetry] declares
// it shares with Save. The retryable rotation is the path the token endpoint
// takes in the common case, so a backend that implemented the parent-still-
// live check only in Save would leave the cascade with a hole on the route
// almost every rotation uses.
func txRefreshRetryRotationOntoRevokedParent(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	root := newRefresh(b.Now(), "tx-retry-revoked-parent", nil)
	seedRefreshTokens(t, b.Store, ctx, root)
	if err := b.Store.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}

	tx := beginTx(t, txr, ctx)
	retry := requireTxRetryResponses(t, tx)
	successor := newRefresh(b.Now(), "tx-retry-revoked-child", &root.ID)
	err := retry.SaveRotationWithRetry(ctx, successor, []byte("sealed-token-response"))
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("tx SaveRotationWithRetry onto revoked parent: want ErrAlreadyConsumed, got %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	assertRevoked(t, b.Store, successor.ID)
}
