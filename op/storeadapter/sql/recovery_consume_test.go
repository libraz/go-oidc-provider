package oidcsql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// A recovery code is single-use, and the only durable record of that is
// the stored slot's ConsumedAt. The redemption statement matches on
// "consumed_at = 0", so a Consume that writes the caller's value through
// unexamined writes zero back into the column whenever the caller left
// the slot unstamped — the row matches, nothing changes, and the code
// stays redeemable.
//
// What makes the shape worth an explicit cross-engine row is that the
// engines then disagree about it: MySQL's affected-row count reports
// changed rows and SQLite's and PostgreSQL's report matched rows, so
// the same call is a refusal on one engine and a success on the others.
// The success is the dangerous half — the caller is told the code is
// spent while the next holder of it can still redeem it — and no
// single-engine test can see the split at all.

// assertRecoveryConsumeStampsSlot drives the unstamped-slot redemption
// against whatever engine the provider is backed by and pins the
// post-condition the interface declares: a nil Consume means the stored
// slot carries a non-zero ConsumedAt and no later caller can redeem it.
//
// The assertions deliberately do not mark this a test helper: a failure
// here is the finding, and attributing it to the call site would report
// every engine's failure at the same line.
func assertRecoveryConsumeStampsSlot(t *testing.T, recovery store.RecoveryStore) {
	ctx := context.Background()
	const subject = "recovery-unstamped-subject"
	batch := &store.RecoveryBatch{
		Subject:     subject,
		GeneratedAt: contract.Reference,
		Codes: []store.RecoveryCode{
			{Hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdC1vbmU$aGFzaC1vbmU"},
			{Hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdC10d28$aGFzaC10d28"},
		},
	}
	if err := recovery.Put(ctx, batch); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Read the batch back the way a caller does, and redeem slot 0
	// exactly as it arrived — the library's own verifier stamps the slot
	// first, but the interface does not require a caller to, and this is
	// the path that decides whether the code survives the redemption.
	held, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !held.Codes[0].ConsumedAt.IsZero() {
		t.Fatalf("fixture slot arrived pre-stamped (%v); the unstamped path is not under test",
			held.Codes[0].ConsumedAt)
	}
	if err := recovery.Consume(ctx, held, 0); err != nil {
		t.Fatalf("Consume of an unstamped slot: %v", err)
	}

	stored, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if stored.Codes[0].ConsumedAt.IsZero() {
		t.Errorf("Consume returned nil but the stored slot is still unconsumed; " +
			"the code remains redeemable and the caller was told it was spent")
	}

	// The post-condition that matters to a user is not the column value
	// but that no one can redeem the code again. Re-present the same
	// slot the way a second holder would.
	replay, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get for replay: %v", err)
	}
	replay.Codes[0].ConsumedAt = time.Time{}
	if err := recovery.Consume(ctx, replay, 0); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Errorf("second Consume of the same slot = %v, want ErrAlreadyConsumed", err)
	}
}

// assertRecoveryConsumeKeepsCallerStamp pins the other half: a slot the
// caller did stamp keeps that exact instant. The library stamps from the
// OP's clock at the moment the code verified, and overwriting it with
// the adapter's own reading would move the timestamp an operator reads
// out of an account-management UI.
func assertRecoveryConsumeKeepsCallerStamp(t *testing.T, recovery store.RecoveryStore) {
	ctx := context.Background()
	const subject = "recovery-stamped-subject"
	stamp := contract.Reference.Add(90 * time.Minute)
	if err := recovery.Put(ctx, &store.RecoveryBatch{
		Subject:     subject,
		GeneratedAt: contract.Reference,
		Codes: []store.RecoveryCode{
			{Hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdC10aHI$aGFzaC10aHI"},
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	held, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	held.Codes[0].ConsumedAt = stamp
	if err := recovery.Consume(ctx, held, 0); err != nil {
		t.Fatalf("Consume of a stamped slot: %v", err)
	}
	stored, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if !stored.Codes[0].ConsumedAt.Equal(stamp) {
		t.Errorf("stored ConsumedAt = %v, want the caller's %v", stored.Codes[0].ConsumedAt, stamp)
	}
}

// runRecoveryConsumeStampContracts is the per-engine entry point. Each
// dialect's test calls it with its own factory so the rows run inside
// that engine's container.
func runRecoveryConsumeStampContracts(t *testing.T, f contract.Factory) {
	t.Helper()

	recovery := func(t *testing.T) store.RecoveryStore {
		t.Helper()
		s, ok := f(t).Store.(*oidcsql.Store)
		if !ok {
			t.Fatal("factory produced a store that is not the SQL adapter")
		}
		return s.RecoveryCodes()
	}

	t.Run("UnstampedSlotIsStamped", func(t *testing.T) {
		t.Parallel()
		assertRecoveryConsumeStampsSlot(t, recovery(t))
	})
	t.Run("CallerStampIsKept", func(t *testing.T) {
		t.Parallel()
		assertRecoveryConsumeKeepsCallerStamp(t, recovery(t))
	})
}

// TestSQLite_RecoveryConsumeStamp runs the rows on the engine that
// needs no container, so a default `go test` still covers the
// post-condition. The MySQL and PostgreSQL rows carry the cross-engine
// half and live behind the testcontainers tag.
func TestSQLite_RecoveryConsumeStamp(t *testing.T) {
	t.Parallel()
	runRecoveryConsumeStampContracts(t, newSQLiteFactory(t))
}
