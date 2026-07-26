//go:build testcontainers

package oidcdynamo_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// TestTx_BufferedWritesLandOnCommit pins the buffer semantics the
// adapter's [store.Tx] is built on: nothing is visible outside the
// transaction until Commit, everything is visible after it, and a
// rolled-back transaction leaves no trace. The contract harness covers
// the cluster substores through the OP's own call patterns; this covers
// the buffer directly so a regression points at the buffer rather than
// at whichever endpoint noticed.
func TestTx_BufferedWritesLandOnCommit(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "txcommit_")
	ctx := t.Context()

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	rec := store.AccessTokenRecord{
		JTI:       "jti-committed",
		GrantID:   "grant-1",
		Subject:   "sub-1",
		ClientID:  "client-1",
		IssuedAt:  contract.Reference,
		ExpiresAt: contract.Reference.Add(time.Hour),
	}
	if err := tx.AccessTokens().Register(ctx, rec); err != nil {
		t.Fatalf("tx Register: %v", err)
	}

	// Outside the transaction the write must not be visible yet. An
	// unregistered jti is reported as (nil, nil), not as an error.
	outside, err := s.AccessTokens().Find(ctx, rec.JTI)
	if err != nil {
		t.Fatalf("Find outside tx: %v", err)
	}
	if outside != nil {
		t.Fatalf("uncommitted write is visible outside the tx: %+v", outside)
	}
	// Inside it, the caller reads its own write.
	inside, err := tx.AccessTokens().Find(ctx, rec.JTI)
	if err != nil {
		t.Fatalf("Find inside tx: %v", err)
	}
	if inside == nil {
		t.Fatal("tx does not read its own write")
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	got, err := s.AccessTokens().Find(ctx, rec.JTI)
	if err != nil {
		t.Fatalf("Find after Commit: %v", err)
	}
	if got.Subject != rec.Subject || got.GrantID != rec.GrantID {
		t.Fatalf("committed record = %+v, want subject/grant of %+v", got, rec)
	}
}

func TestTx_RollbackDiscardsWrites(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "txrollback_")
	ctx := t.Context()

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI:       "jti-rolled-back",
		GrantID:   "grant-1",
		Subject:   "sub-1",
		ExpiresAt: contract.Reference.Add(time.Hour),
	}); err != nil {
		t.Fatalf("tx Register: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	got, err := s.AccessTokens().Find(ctx, "jti-rolled-back")
	if err != nil {
		t.Fatalf("Find after Rollback: %v", err)
	}
	if got != nil {
		t.Fatalf("rolled-back write survived: %+v", got)
	}
}

// TestTx_CommitSpansSubstores is the shape the token endpoint actually
// produces: a grant, a consumed authorization code, and a registered
// access token all landing as one transaction.
func TestTx_CommitSpansSubstores(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "txspan_")
	ctx := t.Context()

	code := &store.AuthorizationCode{
		ID:        "code-span",
		ClientID:  "client-1",
		Subject:   "sub-1",
		GrantID:   "grant-span",
		ExpiresAt: contract.Reference.Add(time.Hour),
		CreatedAt: contract.Reference,
	}
	if err := s.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save code: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.AuthorizationCodes().Consume(ctx, "code-span"); err != nil {
		t.Fatalf("tx Consume: %v", err)
	}
	if err := tx.Grants().Save(ctx, &store.Grant{
		ID:       "grant-span",
		Subject:  "sub-1",
		ClientID: "client-1",
		Scope:    []string{"openid"},
	}); err != nil {
		t.Fatalf("tx Grants().Save: %v", err)
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI:       "jti-span",
		GrantID:   "grant-span",
		Subject:   "sub-1",
		ExpiresAt: contract.Reference.Add(time.Hour),
	}); err != nil {
		t.Fatalf("tx Register: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	registered, err := s.AccessTokens().Find(ctx, "jti-span")
	if err != nil {
		t.Fatalf("Find access token after Commit: %v", err)
	}
	if registered == nil {
		t.Fatal("access token missing after Commit")
	}
	if _, err := s.Grants().Find(ctx, "grant-span"); err != nil {
		t.Fatalf("grant missing after Commit: %v", err)
	}
	consumed, err := s.AuthorizationCodes().Find(ctx, "code-span")
	if err != nil {
		t.Fatalf("code missing after Commit: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("code was not stamped consumed by the committed transaction")
	}
}

func newIsolatedStore(t *testing.T, prefix string) *oidcdynamo.Store {
	t.Helper()
	s, err := oidcdynamo.New(newEmulatorClient(t),
		oidcdynamo.WithTablePrefix(prefix),
		oidcdynamo.WithClock(fixedClock{now: contract.Reference}),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	return s
}
