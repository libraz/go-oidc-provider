package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file groups the contract sub-tests for the substores that come after
// GrantStore: SessionStore, PushedAuthRequestStore, InteractionStore,
// ConsumedJTIStore, and the Transactional extension. They are split off from
// contract.go to keep the per-file size budget below 800 lines.

// --- SessionStore ------------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var sessionCases = []subtest{
	{"SaveFind", sessionSaveFind},
	{"Touch", sessionTouch},
	{"TouchMissing", sessionTouchMissing},
	{"Delete", sessionDelete},
	{"Expired", sessionExpired},
	{"ListByChooserGroup", sessionListByChooserGroup},
	{"ListByChooserGroupSkipsExpired", sessionListByChooserGroupSkipsExpired},
}

func sessionSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now, "s-1")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.Sessions().Find(ctx, "s-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "s-1" {
		t.Fatalf("unexpected session: %+v", got)
	}
}

func sessionTouch(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now, "s-touch")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	newExp := b.Now.Add(2 * time.Hour)
	newUpd := b.Now.Add(time.Minute)
	if err := b.Store.Sessions().Touch(ctx, "s-touch", newExp, newUpd); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := b.Store.Sessions().Find(ctx, "s-touch")
	if err != nil {
		t.Fatalf("Find after Touch: %v", err)
	}
	if !got.ExpiresAt.Equal(newExp) {
		t.Fatalf("Touch did not update ExpiresAt: got %v want %v", got.ExpiresAt, newExp)
	}
	if !got.UpdatedAt.Equal(newUpd) {
		t.Fatalf("Touch did not update UpdatedAt: got %v want %v", got.UpdatedAt, newUpd)
	}
}

func sessionTouchMissing(t *testing.T, f Factory) {
	b := f(t)
	err := b.Store.Sessions().Touch(context.Background(), "absent", b.Now, b.Now)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch missing: want ErrNotFound, got %v", err)
	}
}

func sessionDelete(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now, "s-del")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := b.Store.Sessions().Delete(ctx, "s-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	err := b.Store.Sessions().Delete(ctx, "s-del")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("repeat Delete: want ErrNotFound, got %v", err)
	}
}

func sessionExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now, "s-exp")
	s.ExpiresAt = b.Now.Add(-time.Hour)
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.Sessions().Find(ctx, "s-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
}

func sessionListByChooserGroup(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	a := newSession(b.Now, "s-a")
	a.ChooserGroupID = "cg-list"
	a.Subject = "user-a"
	bb := newSession(b.Now, "s-b")
	bb.ChooserGroupID = "cg-list"
	bb.Subject = "user-b"
	other := newSession(b.Now, "s-other")
	other.ChooserGroupID = "cg-other"
	for _, s := range []*store.Session{a, bb, other} {
		if err := b.Store.Sessions().Save(ctx, s); err != nil {
			t.Fatalf("Save %s: %v", s.ID, err)
		}
	}
	got, err := b.Store.Sessions().ListByChooserGroup(ctx, "cg-list")
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d want 2; got %+v", len(got), got)
	}
	for _, s := range got {
		if s.ChooserGroupID != "cg-list" {
			t.Errorf("returned session with ChooserGroupID=%q", s.ChooserGroupID)
		}
	}
}

func sessionListByChooserGroupSkipsExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	live := newSession(b.Now, "s-live")
	live.ChooserGroupID = "cg-mixed"
	dead := newSession(b.Now, "s-dead")
	dead.ChooserGroupID = "cg-mixed"
	dead.ExpiresAt = b.Now.Add(-time.Hour)
	for _, s := range []*store.Session{live, dead} {
		if err := b.Store.Sessions().Save(ctx, s); err != nil {
			t.Fatalf("Save %s: %v", s.ID, err)
		}
	}
	got, err := b.Store.Sessions().ListByChooserGroup(ctx, "cg-mixed")
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(got) != 1 || got[0].ID != "s-live" {
		t.Fatalf("got %+v want exactly s-live", got)
	}
}

// --- PushedAuthRequestStore --------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var parCases = []subtest{
	{"SaveFind", parSaveFind},
	{"ConsumeOnce", parConsumeOnce},
	{"Expired", parExpired},
}

func parSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	par := newPAR(b.Now, "urn:par:1")
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.PushedAuthRequests().Find(ctx, "urn:par:1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.URI != "urn:par:1" {
		t.Fatalf("unexpected par: %+v", got)
	}
}

func parConsumeOnce(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	par := newPAR(b.Now, "urn:par:2")
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	first, err := b.Store.PushedAuthRequests().Consume(ctx, "urn:par:2")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if first.ConsumedAt == nil {
		t.Fatal("Consume returned ConsumedAt=nil")
	}
	_, err = b.Store.PushedAuthRequests().Consume(ctx, "urn:par:2")
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

func parExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	par := newPAR(b.Now, "urn:par:exp")
	par.ExpiresAt = b.Now.Add(-time.Hour)
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.PushedAuthRequests().Find(ctx, "urn:par:exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
}

// --- InteractionStore --------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var interactionCases = []subtest{
	{"SaveFind", interactionSaveFind},
	{"Delete", interactionDelete},
	{"Expired", interactionExpired},
}

func interactionSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	i := newInteraction(b.Now, "i-1")
	if err := b.Store.Interactions().Save(ctx, i); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.Interactions().Find(ctx, "i-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "i-1" {
		t.Fatalf("unexpected interaction: %+v", got)
	}
}

func interactionDelete(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	i := newInteraction(b.Now, "i-del")
	if err := b.Store.Interactions().Save(ctx, i); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := b.Store.Interactions().Delete(ctx, "i-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	err := b.Store.Interactions().Delete(ctx, "i-del")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("repeat Delete: want ErrNotFound, got %v", err)
	}
}

func interactionExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	i := newInteraction(b.Now, "i-exp")
	i.ExpiresAt = b.Now.Add(-time.Hour)
	if err := b.Store.Interactions().Save(ctx, i); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.Interactions().Find(ctx, "i-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
}

// --- ConsumedJTIStore --------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var jtiCases = []subtest{
	{"MarkHas", jtiMarkHas},
	{"HasMissing", jtiHasMissing},
	{"Replay", jtiReplay},
}

func jtiMarkHas(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	expiresAt := b.Now.Add(time.Hour)
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-1", expiresAt); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	got, err := b.Store.ConsumedJTIs().Has(ctx, "jti-1")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !got {
		t.Fatal("Has returned false for marked jti")
	}
}

func jtiHasMissing(t *testing.T, f Factory) {
	b := f(t)
	got, err := b.Store.ConsumedJTIs().Has(context.Background(), "absent")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if got {
		t.Fatal("Has returned true for unknown jti")
	}
}

func jtiReplay(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	expiresAt := b.Now.Add(time.Hour)
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-replay", expiresAt); err != nil {
		t.Fatalf("first Mark: %v", err)
	}
	err := b.Store.ConsumedJTIs().Mark(ctx, "jti-replay", expiresAt)
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("replay Mark: want ErrAlreadyConsumed, got %v", err)
	}
}

// --- Transactional ----------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var transactionalCases = []subtest{
	{"BeginCommit", txBeginCommit},
	{"BeginRollback", txBeginRollback},
	{"RollbackAfterCommitNoOp", txRollbackAfterCommitNoOp},
	{"CrossSubstore", txCrossSubstore},
}

func txBeginCommit(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	tx, err := txr.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	requireSubstoresNonNil(t, tx)
	code := newAuthCode(b.Now, "tx-ac")
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
		tx.Grants() == nil || tx.Sessions() == nil ||
		tx.PushedAuthRequests() == nil {
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
	code := newAuthCode(b.Now, "tx-rb")
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

func txCrossSubstore(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	tx, err := txr.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if err := saveCrossSubstore(ctx, tx, b.Now); err != nil {
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
	if _, err := b.Store.Sessions().Find(ctx, "tx-s"); err != nil {
		t.Fatalf("Find session: %v", err)
	}
}

func saveCrossSubstore(ctx context.Context, tx store.Tx, now time.Time) error {
	grant := newGrant(now, "tx-g", "sub", "client")
	if err := tx.Grants().Save(ctx, grant); err != nil {
		return err
	}
	code := newAuthCode(now, "tx-c")
	code.GrantID = "tx-g"
	if err := tx.AuthorizationCodes().Save(ctx, code); err != nil {
		return err
	}
	sess := newSession(now, "tx-s")
	return tx.Sessions().Save(ctx, sess)
}
