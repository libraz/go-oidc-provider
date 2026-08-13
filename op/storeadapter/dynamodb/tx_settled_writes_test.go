//go:build testcontainers

package oidcdynamo_test

import (
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// The bulk revocations enumerate their targets through the parent store
// — a secondary index cannot see staged writes — and only then act on
// each candidate through the transaction's buffer. The buffer's own
// closed-handle guard therefore runs per candidate, which means a
// settled handle reports the sentinel only when the enumeration found
// something. Against an index that matches nothing the same call
// returns silent success, and a caller that has leaked a handle is told
// "revoked nothing, all good" instead of "you are no longer in a
// transaction".
//
// That is why every case below is driven twice: once where the index
// has candidates and once where it is empty. Seeding a match and
// querying for it is the version of this test that passes without the
// guard, because each per-candidate re-read hits the buffer and
// surfaces the sentinel on its own.

// settledRevocationKeys names the identifiers one run of the matrix
// drives the revocations with. The seeded set makes every enumeration
// find candidates; the absent set makes every one of them come back
// empty.
type settledRevocationKeys struct {
	name     string
	chainID  string
	grantID  string
	clientID string
}

// TestTx_SettledHandleRefusesRevocationWrites pins the [store.Tx] rule
// on the write side: once a transaction has settled, every call through
// its handles fails with an error satisfying
// errors.Is(err, [store.ErrTxRequired]) — whatever the backing index
// happens to hold.
func TestTx_SettledHandleRefusesRevocationWrites(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "txsettledwrites_")
	seedSettledRevocationFixtures(t, s)

	seeded := settledRevocationKeys{
		name:     "IndexHasCandidates",
		chainID:  "settled-chain-root",
		grantID:  "settled-grant",
		clientID: "settled-client",
	}
	absent := settledRevocationKeys{
		name:     "IndexIsEmpty",
		chainID:  "settled-chain-absent",
		grantID:  "grant-with-no-records",
		clientID: "client-with-no-records",
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
			for _, keys := range []settledRevocationKeys{seeded, absent} {
				t.Run(keys.name, func(t *testing.T) {
					tx, err := s.BeginTx(t.Context())
					if err != nil {
						t.Fatalf("BeginTx: %v", err)
					}
					if err := settle.close(tx); err != nil {
						t.Fatalf("%s: %v", settle.name, err)
					}
					assertRevocationWritesRefused(t, tx, keys)
				})
			}
		})
	}
}

// seedSettledRevocationFixtures writes one record into each substore the
// matrix drives, so the seeded half of the matrix enumerates a
// non-empty index. Everything is written outside a transaction: the
// records only exist to give the enumerations something to find.
func seedSettledRevocationFixtures(t *testing.T, s *oidcdynamo.Store) {
	t.Helper()
	ctx := t.Context()
	now := contract.Reference

	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        "settled-chain-root",
		ClientID:  "settled-client",
		Subject:   "settled-subject",
		GrantID:   "settled-grant",
		Scope:     []string{"openid"},
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI:       "settled-jti",
		GrantID:   "settled-grant",
		Subject:   "settled-subject",
		ClientID:  "settled-client",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed access token: %v", err)
	}
	if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID:        "settled-opaque",
		GrantID:   "settled-grant",
		Subject:   "settled-subject",
		ClientID:  "settled-client",
		Scope:     []string{"openid"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed opaque access token: %v", err)
	}
	if err := s.Grants().Save(ctx, &store.Grant{
		ID:        "settled-grant-record",
		Subject:   "settled-subject",
		ClientID:  "settled-client",
		Scope:     []string{"openid"},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// assertRevocationWritesRefused drives every revocation that enumerates
// its targets outside the transaction's buffer and asserts each reports
// the closed-handle sentinel rather than a count or a silent nil.
func assertRevocationWritesRefused(t *testing.T, tx store.Tx, keys settledRevocationKeys) {
	t.Helper()
	ctx := t.Context()

	assertClosed := func(op string, err error) {
		t.Helper()
		switch {
		case err == nil:
			t.Errorf(
				"%s through a settled Tx: want an error satisfying store.ErrTxRequired, got nil "+
					"— a leaked handle reads as a completed revocation",
				op,
			)
		case !errors.Is(err, store.ErrTxRequired):
			t.Errorf("%s through a settled Tx: want an error satisfying store.ErrTxRequired, got %v", op, err)
		}
	}
	assertClosedCount := func(op string, n int, err error) {
		t.Helper()
		assertClosed(op, err)
		if n != 0 {
			t.Errorf("%s through a settled Tx reported %d retired records alongside %v", op, n, err)
		}
	}

	refreshes := tx.RefreshTokens()
	assertClosed("RefreshTokens().RevokeChain", refreshes.RevokeChain(ctx, keys.chainID))
	assertClosed("RefreshTokens().RevokeByGrant", refreshes.RevokeByGrant(ctx, keys.grantID))
	assertClosed(
		"RefreshTokens().RevokeByClient",
		revokeByClient(t, refreshes).RevokeByClient(ctx, keys.clientID),
	)

	registry := tx.AccessTokens()
	n, err := registry.RevokeByGrant(ctx, keys.grantID)
	assertClosedCount("AccessTokens().RevokeByGrant", n, err)
	assertClosed(
		"AccessTokens().RevokeByClient",
		revokeByClient(t, registry).RevokeByClient(ctx, keys.clientID),
	)

	opaque := tx.OpaqueAccessTokens()
	n, err = opaque.RevokeByGrant(ctx, keys.grantID)
	assertClosedCount("OpaqueAccessTokens().RevokeByGrant", n, err)
	assertClosed(
		"OpaqueAccessTokens().RevokeByClient",
		revokeByClient(t, opaque).RevokeByClient(ctx, keys.clientID),
	)

	assertClosed(
		"Grants().RevokeByClient",
		revokeByClient(t, tx.Grants()).RevokeByClient(ctx, keys.clientID),
	)
}

func revokeByClient(t *testing.T, substore any) store.RevokeByClient {
	t.Helper()
	revoke, ok := substore.(store.RevokeByClient)
	if !ok {
		t.Fatalf("%T does not implement store.RevokeByClient", substore)
	}
	return revoke
}
