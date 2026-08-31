//go:build testcontainers

package oidcdynamo_test

import (
	"errors"
	"testing"
	"time"

	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

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

// TestTx_SettledHandleRefusesGrantEnumerations pins what a settled
// handle owes a caller that keeps using it, for the grant lookups the
// transaction's buffer never sees.
//
// The buffer refuses every keyed read once the transaction settles, so
// Find is covered by that guard and by the store contract. The index
// enumerations resolve their candidates through the table instead — a
// secondary index cannot see staged writes, so the query is not routed
// through the buffer.
//
// Each lookup is driven twice, and the second run is the one that
// matters. When the index does return a candidate, the per-candidate
// re-read is keyed and the buffer refuses it, so the sentinel surfaces
// even from an unguarded enumeration. When it returns none there is
// nothing to re-read, and the call answers "this subject has no grants"
// with a nil error — indistinguishable, to the caller, from a subject
// who really has none, on a handle that stopped being a transaction some
// time ago.
func TestTx_SettledHandleRefusesGrantEnumerations(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "txsettled_")
	const subject, clientID = "sub-settled", "client-settled"
	if err := s.Grants().Save(t.Context(), &store.Grant{
		ID:        "grant-settled",
		Subject:   subject,
		ClientID:  clientID,
		Scope:     []string{"openid"},
		CreatedAt: contract.Reference,
		UpdatedAt: contract.Reference,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}

	for _, settle := range []struct {
		name  string
		close func(store.Tx) error
	}{
		{"Commit", store.Tx.Commit},
		{"Rollback", store.Tx.Rollback},
	} {
		t.Run(settle.name, func(t *testing.T) {
			t.Parallel()
			tx, err := s.BeginTx(t.Context())
			if err != nil {
				t.Fatalf("BeginTx: %v", err)
			}
			if err := settle.close(tx); err != nil {
				t.Fatalf("%s: %v", settle.name, err)
			}

			t.Run("IndexHasCandidates", func(t *testing.T) {
				assertGrantLookupsRefused(t, tx.Grants(), subject, clientID)
			})
			t.Run("IndexIsEmpty", func(t *testing.T) {
				assertGrantLookupsRefused(t, tx.Grants(), "sub-without-grants", "client-without-grants")
			})
		})
	}
}

// assertGrantLookupsRefused drives every grant lookup that does not go
// through the transaction's buffer and asserts each one reports the
// closed-handle sentinel rather than an answer.
func assertGrantLookupsRefused(t *testing.T, grants store.GrantStore, subject, clientID string) {
	t.Helper()
	ctx := t.Context()

	assertClosed := func(op string, found bool, err error) {
		t.Helper()
		switch {
		case err == nil:
			t.Errorf("%s through a settled Tx: want an error satisfying store.ErrTxRequired, got nil", op)
		case !errors.Is(err, store.ErrTxRequired):
			t.Errorf("%s through a settled Tx: want an error satisfying store.ErrTxRequired, got %v", op, err)
		case found:
			t.Errorf("%s through a settled Tx returned a result alongside %v", op, err)
		}
	}

	one, err := grants.FindBySubjectClient(ctx, subject, clientID)
	assertClosed("Grants().FindBySubjectClient", one != nil, err)
	list, err := grants.ListBySubject(ctx, subject)
	assertClosed("Grants().ListBySubject", len(list) > 0, err)
	any, err := grants.HasAny(ctx)
	assertClosed("Grants().HasAny", any, err)

	clients, ok := grants.(store.GrantClientLister)
	if !ok {
		t.Fatalf("%T does not implement store.GrantClientLister", grants)
	}
	clientPage, err := clients.ListClientIDsBySubject(ctx, subject, "", 10)
	assertClosed("Grants().ListClientIDsBySubject", len(clientPage.ClientIDs) > 0, err)

	subjects, ok := grants.(store.GrantSubjectLister)
	if !ok {
		t.Fatalf("%T does not implement store.GrantSubjectLister", grants)
	}
	subjectPage, err := subjects.ListSubjectsByClient(ctx, clientID, "", 10)
	assertClosed("Grants().ListSubjectsByClient", len(subjectPage.Subjects) > 0, err)
}

func newIsolatedStore(t *testing.T, prefix string) *oidcdynamo.Store {
	t.Helper()
	s, _ := newWrappedStore(t, prefix, nil)
	return s
}

// newWrappedStore builds an isolated store whose requests pass through
// wrap before reaching the emulator, so a test can count the calls the
// adapter makes or fail one of them. It returns the raw client too: a
// test that has to observe or seed the stored items themselves needs a
// path that is not the adapter under test. A nil wrap leaves the client
// untouched.
func newWrappedStore(
	t *testing.T,
	prefix string,
	wrap func(oidcdynamo.API) oidcdynamo.API,
) (*oidcdynamo.Store, *awsdynamodb.Client) {
	t.Helper()
	client := newEmulatorClient(t)
	var api oidcdynamo.API = client
	if wrap != nil {
		api = wrap(client)
	}
	s, err := oidcdynamo.New(api,
		oidcdynamo.WithTablePrefix(prefix),
		oidcdynamo.WithClock(&fixedClock{now: contract.Reference}),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)
	return s, client
}
