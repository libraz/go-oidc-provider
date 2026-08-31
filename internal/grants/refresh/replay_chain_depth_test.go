package refresh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// chainDepthBeyondWalkLimit is a rotation depth deeper than the parent-walk
// limit the exchanger applies when resolving a chain root. The limit is
// unexported, so the fixture names a depth known to exceed it rather than
// importing it. The tests below assert the walk really did give up
// (chain_root_lookup_failed), so raising the limit past this depth turns them
// red instead of silently retiring their coverage.
const chainDepthBeyondWalkLimit = 1100

// longChainFixture is one live grant carrying a rotation history longer than
// the chain-root walk can traverse. This is not an exotic state: a chain grows
// one node per refresh, every rotation slides the refresh-token expiry forward,
// and the store reclaims a grant's history only once the grant stops being
// refreshed — so a client refreshing every few minutes reaches this depth
// within days of ordinary, legitimate use.
//
// stolen is a consumed intermediate token an attacker replays; tip is the
// successor that is still redeemable at the moment of the replay, and it is
// the token the cascade exists to kill.
type longChainFixture struct {
	exchanger *refresh.Exchanger
	tokens    store.RefreshTokenStore
	events    *recordingEmitter
	stolen    string
	tip       string
}

func newLongChainFixture(tb testing.TB, depth int) longChainFixture {
	tb.Helper()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	clk := func() time.Time { return cur }
	tokens := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
	events := &recordingEmitter{}

	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{Store: tokens, Clock: clk, TTL: 24 * time.Hour})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	exchanger, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: tokens,
		Clock: clk,
		Audit: events,
	})
	if err != nil {
		tb.Fatalf("NewExchanger: %v", err)
	}

	ctx := context.Background()
	current, err := issuer.Issue(ctx, goodIssue())
	if err != nil {
		tb.Fatalf("Issue root: %v", err)
	}
	// Rotate the chain the way the token endpoint does: consume the live
	// token, then mint its successor with the consumed id as ParentID. Going
	// through Exchange rather than writing rows directly is what makes the
	// resulting pointer graph the one a real rotation history has.
	var previous string
	for i := range depth {
		out, exErr := exchanger.Exchange(ctx, refresh.ExchangeInput{Token: current, ClientID: "client-1"})
		if exErr != nil {
			tb.Fatalf("Exchange generation %d: %v", i, exErr)
		}
		parent := out.ConsumedID
		next, isErr := issuer.Issue(ctx, refresh.IssueInput{
			ClientID: out.ClientID,
			Subject:  out.Subject,
			GrantID:  out.GrantID,
			Scope:    out.Scope,
			ParentID: &parent,
		})
		if isErr != nil {
			tb.Fatalf("Issue generation %d: %v", i+1, isErr)
		}
		previous, current = current, next
	}
	// Past the grace window so re-presenting the consumed token is a replay
	// rather than an idempotent retry of the rotation that consumed it.
	cur = cur.Add(refresh.GraceTTLDefault + time.Second)

	return longChainFixture{
		exchanger: exchanger,
		tokens:    tokens,
		events:    events,
		stolen:    previous,
		tip:       current,
	}
}

// TestExchange_ReplayOnAChainTooLongToWalkStillKillsTheSuccessor is the
// invariant the chain-root walk must not be allowed to trade away: after a
// confirmed replay, no successor of the replayed chain may remain redeemable.
//
// A chain longer than the walk limit resolves no root, and returning
// invalid_grant for the replayed request alone would leave the thief's live
// successor spendable indefinitely — refresh it once and the chain rolls on,
// past the point where the OP has already concluded it was compromised. The
// walk limit is a guard against a corrupted pointer graph; a long rotation
// history is not corruption, so hitting it must escalate to the grant-scoped
// cascade rather than abandon the revocation.
func TestExchange_ReplayOnAChainTooLongToWalkStillKillsTheSuccessor(t *testing.T) {
	t.Parallel()

	f := newLongChainFixture(t, chainDepthBeyondWalkLimit)
	ctx := context.Background()

	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    f.stolen,
		ClientID: "client-1",
	}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	// Guards the premise: if the walk had resolved a root this test would be
	// exercising the ordinary chain cascade, not the depth-limit fallback.
	if !hasChainRevokeFailure(f.events.snapshot(), "chain_root_lookup_failed") {
		t.Fatalf("chain root walk resolved a root at depth %d; the fallback under test never ran",
			chainDepthBeyondWalkLimit)
	}

	rec, err := f.tokens.Find(ctx, f.tip)
	if err != nil {
		t.Fatalf("Find chain tip: %v", err)
	}
	if !rec.Revoked {
		t.Error("the live successor survived the replay cascade unrevoked")
	}

	// The decisive assertion: whoever holds the successor must not be able to
	// spend it. A revoked flag the exchange path ignored would be no
	// remediation at all, and neither is an invalid_grant on the replayed
	// request alone.
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    f.tip,
		ClientID: "client-1",
	}); err == nil {
		t.Error("the successor token was still redeemable after the replay cascade")
	} else if !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Errorf("successor exchange err=%v want ErrTokenReplayed", err)
	}

	// The access-token half of the cascade belongs to the caller, and it
	// runs off the grant the exchanger resolved. A fallback that retired the
	// history but reported no grant would leave every access token under it
	// redeemable, so the depth path has to surface the grant too.
	if got := f.exchanger.RevokeReplayedChain(ctx, f.stolen); got != "grant-1" {
		t.Errorf("resolved grant=%q want %q", got, "grant-1")
	}
}

// TestExchange_ReplayOnAChainTooLongToWalkRetiresTheWholeHistory pins the
// breadth of the fallback. The grant-scoped cascade is deliberately coarser
// than the chain: it retires every record issued under the same consent, which
// over-revokes and never under-revokes. Asserting it here keeps a future
// narrowing of the fallback from reintroducing a live node the walk could not
// reach.
func TestExchange_ReplayOnAChainTooLongToWalkRetiresTheWholeHistory(t *testing.T) {
	t.Parallel()

	f := newLongChainFixture(t, chainDepthBeyondWalkLimit)
	ctx := context.Background()

	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    f.stolen,
		ClientID: "client-1",
	}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	for _, id := range []string{f.stolen, f.tip} {
		rec, err := f.tokens.Find(ctx, id)
		if err != nil {
			t.Fatalf("Find %q: %v", id, err)
		}
		if !rec.Revoked {
			t.Errorf("record %q left unrevoked after the cascade", id)
		}
		if rec.ConsumedAt == nil {
			t.Errorf("record %q left unconsumed after the cascade", id)
		}
	}
}
