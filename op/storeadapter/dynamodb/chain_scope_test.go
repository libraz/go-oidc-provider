//go:build testcontainers

package oidcdynamo_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// TestTx_RevokeByChainLandsOnCommitOnly pins the transactional view of
// chain-scoped revocation: the flips are buffered, a rollback leaves the
// chain live, and a commit retires exactly that grant's chain.
func TestTx_RevokeByChainLandsOnCommitOnly(t *testing.T) {
	t.Parallel()
	s := newIsolatedStore(t, "txchain_")
	ctx := t.Context()
	for _, r := range []struct{ id, chain string }{
		{"oat-a1", "chain-a"}, {"oat-a2", "chain-a"}, {"oat-b", "chain-b"}, {"oat-none", ""},
	} {
		if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
			ID: r.id, GrantID: "grant-1", ClientID: "client-1", Subject: "sub-1", ChainID: r.chain,
			IssuedAt: contract.Reference, ExpiresAt: contract.Reference.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save %s: %v", r.id, err)
		}
	}
	revokeChain := func(commit bool) int {
		t.Helper()
		tx, err := s.BeginTx(ctx)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		chains, ok := tx.OpaqueAccessTokens().(store.OpaqueAccessTokenChainRevoker)
		if !ok {
			t.Fatal("tx opaque access-token view does not revoke by chain")
		}
		n, err := chains.RevokeByChain(ctx, "grant-1", "chain-a")
		if err != nil {
			t.Fatalf("tx RevokeByChain: %v", err)
		}
		if commit {
			err = tx.Commit()
		} else {
			err = tx.Rollback()
		}
		if err != nil {
			t.Fatalf("settle (commit=%v): %v", commit, err)
		}
		return n
	}
	assertRevoked := func(want map[string]bool) {
		t.Helper()
		for id, revoked := range want {
			got, err := s.OpaqueAccessTokens().Find(ctx, id)
			if err != nil {
				t.Fatalf("Find %s: %v", id, err)
			}
			if got.Revoked != revoked {
				t.Fatalf("%s Revoked=%v want %v", id, got.Revoked, revoked)
			}
		}
	}

	if n := revokeChain(false); n != 2 {
		t.Fatalf("rolled-back RevokeByChain count = %d, want 2", n)
	}
	assertRevoked(map[string]bool{"oat-a1": false, "oat-a2": false, "oat-b": false, "oat-none": false})
	if n := revokeChain(true); n != 2 {
		t.Fatalf("committed RevokeByChain count = %d, want 2", n)
	}
	assertRevoked(map[string]bool{"oat-a1": true, "oat-a2": true, "oat-b": false, "oat-none": false})
}

// TestTx_AccessTokensOnlyTombstoneKeepsTheIssuanceCutoff pins the staged
// tombstone write: an access-token-only revocation committed over a
// whole-grant row widens only its own cutoff, so issuance is still
// refused up to the whole-grant instant and no later, through the
// transaction's view and the store's alike.
func TestTx_AccessTokensOnlyTombstoneKeepsTheIssuanceCutoff(t *testing.T) {
	t.Parallel()
	s := newIsolatedStore(t, "txscope_")
	ctx := t.Context()
	wholeAt, accessAt := contract.Reference.Add(-time.Hour), contract.Reference
	expires := contract.Reference.Add(time.Hour)
	if err := s.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "grant-scope", RevokedAt: wholeAt, ExpiresAt: expires, Reason: "logout",
	}); err != nil {
		t.Fatalf("RevokeGrant whole: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "grant-scope", RevokedAt: accessAt, ExpiresAt: expires, Reason: "revoke", AccessTokensOnly: true,
	}); err != nil {
		t.Fatalf("tx RevokeGrant access-only: %v", err)
	}
	between := wholeAt.Add(time.Minute)
	check := func(view store.GrantRevocationStore, label string) {
		t.Helper()
		checker, ok := view.(store.IssuanceRevocationChecker)
		if !ok {
			t.Fatalf("%s: grant revocations do not check issuance", label)
		}
		for _, c := range []struct {
			at                time.Time
			revoked, issuance bool
		}{
			{wholeAt, true, true},
			{between, true, false},
			{accessAt, true, false},
			{accessAt.Add(time.Nanosecond), false, false},
		} {
			revoked, err := view.IsRevoked(ctx, "grant-scope", "", c.at)
			if err != nil || revoked != c.revoked {
				t.Fatalf("%s IsRevoked(%v) = %v, %v; want %v", label, c.at, revoked, err, c.revoked)
			}
			refused, err := checker.IsIssuanceRevoked(ctx, "grant-scope", c.at)
			if err != nil || refused != c.issuance {
				t.Fatalf("%s IsIssuanceRevoked(%v) = %v, %v; want %v", label, c.at, refused, err, c.issuance)
			}
		}
	}
	check(tx.GrantRevocations(), "tx")
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	check(s.GrantRevocations(), "store")
}

// TestGrantTombstone_StoredZeroCutoffStillRevokesEverything pins the
// meaning of a row already in a table with revoked_at stored as 0: it
// revokes every token and refuses issuance whatever the instant, and no
// later revocation — access-token-only, whole-grant, or whole-grant
// staged in a transaction — narrows it to a finite cutoff.
func TestGrantTombstone_StoredZeroCutoffStillRevokesEverything(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, _ := newHookedStore(t, client, "zerocut_")
	ctx := t.Context()
	if _, err := client.PutItem(ctx, &awsdynamodb.PutItemInput{
		TableName: aws.String(tableNamed(t, s, "zerocut_", "grant_revocations")),
		Item: map[string]types.AttributeValue{
			"pk":         &types.AttributeValueMemberS{Value: "grant#grant-zero"},
			"revoked_at": &types.AttributeValueMemberN{Value: "0"},
		},
	}); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	revocations := s.GrantRevocations()
	checker, ok := revocations.(store.IssuanceRevocationChecker)
	if !ok {
		t.Fatal("grant revocations do not check issuance")
	}
	assertAllRevoked := func(label string) {
		t.Helper()
		for _, at := range []time.Time{contract.Reference.Add(-time.Hour), contract.Reference.Add(time.Hour)} {
			if revoked, err := revocations.IsRevoked(ctx, "grant-zero", "", at); err != nil || !revoked {
				t.Fatalf("%s IsRevoked(%v) = %v, %v; want true", label, at, revoked, err)
			}
			if refused, err := checker.IsIssuanceRevoked(ctx, "grant-zero", at); err != nil || !refused {
				t.Fatalf("%s IsIssuanceRevoked(%v) = %v, %v; want true", label, at, refused, err)
			}
		}
	}
	assertAllRevoked("stored")
	if err := revocations.RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "grant-zero", RevokedAt: contract.Reference, AccessTokensOnly: true,
	}); err != nil {
		t.Fatalf("RevokeGrant access-only: %v", err)
	}
	assertAllRevoked("after access-only revocation")
	whole := store.GrantTombstone{GrantID: "grant-zero", RevokedAt: contract.Reference, Reason: "logout"}
	if err := revocations.RevokeGrant(ctx, whole); err != nil {
		t.Fatalf("RevokeGrant whole: %v", err)
	}
	assertAllRevoked("after whole-grant revocation")
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.GrantRevocations().RevokeGrant(ctx, whole); err != nil {
		t.Fatalf("tx RevokeGrant whole: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertAllRevoked("after staged whole-grant revocation")
}
