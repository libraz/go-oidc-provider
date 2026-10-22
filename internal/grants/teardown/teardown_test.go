package teardown_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/teardown"
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
			r := teardown.Revoker{OpaqueAccessTokens: oat}
			if c.hide {
				r.OpaqueAccessTokens = opaqueOnly{oat}
			}
			if out := r.Run(ctx, teardown.OpaqueAccessTokensOfChain("grant-1", c.chainID)); !out.Complete() {
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
		scope      teardown.Scope
		wantClosed bool
	}{
		"access tokens of grant":          {teardown.AccessTokensOfGrant("grant-1"), false},
		"compromised grant access tokens": {teardown.CompromisedGrantAccessTokens("grant-1"), true},
		"whole grant":                     {teardown.WholeGrant("grant-1"), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			revs := inmem.New().GrantRevocations()
			out := teardown.Revoker{
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
