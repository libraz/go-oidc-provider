package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// opaqueOnly hides the chain-revocation capability of the wrapped substore.
type opaqueOnly struct{ store.OpaqueAccessTokenStore }

// A chain scope retires only its own chain, and widens to the grant when
// the chain is unknown or the store cannot revoke by chain.
func TestOpaqueAccessTokensOfChain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		hide        bool
		chainID     string
		wantSibling bool // whether the other chain's token is revoked
	}{
		{name: "chain", chainID: "chain-a"},
		{name: "unknown chain", chainID: "", wantSibling: true},
		{name: "store without chain revocation", hide: true, chainID: "chain-a", wantSibling: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			oat := inmem.New().OpaqueAccessTokens()
			for id, chain := range map[string]string{"at-a": "chain-a", "at-b": "chain-b"} {
				if err := oat.Save(ctx, &store.OpaqueAccessToken{
					ID: id, GrantID: "grant-1", ClientID: "client-1", ChainID: chain,
					IssuedAt: now, ExpiresAt: now.Add(time.Hour),
				}); err != nil {
					t.Fatalf("Save %s: %v", id, err)
				}
			}
			r := revocation.Revoker{OpaqueAccessTokens: oat}
			if c.hide {
				r.OpaqueAccessTokens = opaqueOnly{oat}
			}
			if out := r.Run(ctx, revocation.OpaqueAccessTokensOfChain("grant-1", c.chainID)); !out.Complete() {
				t.Fatalf("Run: %v", out.Err())
			}
			for id, want := range map[string]bool{"at-a": true, "at-b": c.wantSibling} {
				got, err := oat.Find(ctx, id)
				if err != nil {
					t.Fatalf("Find %s: %v", id, err)
				}
				if got.Revoked != want {
					t.Errorf("%s Revoked=%v want %v", id, got.Revoked, want)
				}
			}
		})
	}
}

// Only a teardown that closes the grant writes a tombstone that refuses
// issuance; the RFC 7009 cascade of one refresh token does not.
func TestGrantScopesAndIssuance(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		scope      revocation.Scope
		wantClosed bool
	}{
		"access tokens of grant":          {revocation.AccessTokensOfGrant("grant-1"), false},
		"compromised grant access tokens": {revocation.CompromisedGrantAccessTokens("grant-1"), true},
		"whole grant":                     {revocation.WholeGrant("grant-1"), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			revs := inmem.New().GrantRevocations()
			out := revocation.Revoker{
				GrantRevocations:   revs,
				Strategy:           store.RevocationStrategyGrantTombstone,
				Now:                now,
				TombstoneRetention: time.Hour,
			}.Run(ctx, c.scope)
			if !out.Complete() {
				t.Fatalf("Run: %v", out.Err())
			}
			issuedAt := now.Add(-time.Minute)
			if revoked, err := revs.IsRevoked(ctx, "grant-1", "", issuedAt); err != nil || !revoked {
				t.Fatalf("IsRevoked=%v err=%v: every grant scope must revoke the grant's access tokens", revoked, err)
			}
			closed, err := revs.(store.IssuanceRevocationChecker).IsIssuanceRevoked(ctx, "grant-1", issuedAt)
			if err != nil || closed != c.wantClosed {
				t.Fatalf("IsIssuanceRevoked=%v err=%v want %v", closed, err, c.wantClosed)
			}
		})
	}
}

// NewRevoker stamps the tombstone with the supplied instant, the retention
// derived from the access-token TTL plus the clock-skew allowance, and the
// supplied reason.
func TestNewRevoker_StampsTombstone(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.FixedZone("x", 9*3600))
	revs := &fakeGrantRevocations{}
	out := revocation.NewRevoker(nil, nil, nil, revs, store.RevocationStrategyGrantTombstone,
		30*time.Minute, now, "logout").Run(context.Background(), revocation.WholeGrant("grant-1"))
	if !out.Complete() {
		t.Fatalf("outcome incomplete: %v", out.Err())
	}
	if len(revs.tombstones) != 1 {
		t.Fatalf("tombstones=%d want 1", len(revs.tombstones))
	}
	got := revs.tombstones[0]
	if !got.RevokedAt.Equal(now) || got.RevokedAt.Location() != time.UTC {
		t.Errorf("RevokedAt=%v want %v in UTC", got.RevokedAt, now.UTC())
	}
	if want := now.Add(30*time.Minute + revocation.ClockSkewAllowance); !got.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt=%v want %v", got.ExpiresAt, want)
	}
	if got.Reason != "logout" {
		t.Errorf("Reason=%q want logout", got.Reason)
	}
}

// A teardown that closes the grant writes exactly one issuance-closing
// tombstone under every strategy, with the same RevokedAt, retention and
// reason, so GC reclaims it on one schedule; a scope that leaves issuance
// open writes none outside the grant-tombstone strategy.
func TestIssuanceClosureIsStrategyIndependent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for name, strategy := range map[string]store.AccessTokenRevocationStrategy{
		"grant_tombstone": store.RevocationStrategyGrantTombstone,
		"jti_registry":    store.RevocationStrategyJTIRegistry,
		"none":            store.RevocationStrategyNone,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for scopeName, c := range map[string]struct {
				scope revocation.Scope
				want  int
			}{
				"whole grant":                     {revocation.WholeGrant("grant-1"), 1},
				"compromised grant access tokens": {revocation.CompromisedGrantAccessTokens("grant-1"), 1},
				"access tokens of grant":          {revocation.AccessTokensOfGrant("grant-1"), 0},
			} {
				revs := &fakeGrantRevocations{}
				out := revocation.NewRevoker(nil, nil, inmem.New().AccessTokens(), revs, strategy,
					30*time.Minute, now, "code_replay").Run(context.Background(), c.scope)
				if !out.Complete() {
					t.Fatalf("%s: outcome incomplete: %v", scopeName, out.Err())
				}
				want := c.want
				if strategy == store.RevocationStrategyGrantTombstone && scopeName == "access tokens of grant" {
					want = 1 // the access-token-only tombstone the JWT rung writes
				}
				if len(revs.tombstones) != want {
					t.Fatalf("%s: tombstones=%d want %d", scopeName, len(revs.tombstones), want)
				}
				if want == 0 || scopeName == "access tokens of grant" {
					continue
				}
				got := revs.tombstones[0]
				if got.AccessTokensOnly {
					t.Errorf("%s: closure tombstone is access-token-only", scopeName)
				}
				if !got.RevokedAt.Equal(now) || got.Reason != "code_replay" {
					t.Errorf("%s: RevokedAt=%v Reason=%q", scopeName, got.RevokedAt, got.Reason)
				}
				if wantExp := now.Add(revocation.TombstoneRetention(30 * time.Minute)); !got.ExpiresAt.Equal(wantExp) {
					t.Errorf("%s: ExpiresAt=%v want %v", scopeName, got.ExpiresAt, wantExp)
				}
			}
		})
	}
}
