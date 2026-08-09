package refresh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// deferredFixture is the two-node rotation chain the deferral tests replay
// against: root was exchanged once, child is the live successor, and the clock
// already sits past the RFC 9700 §2.2.2 grace window.
type deferredFixture struct {
	exchanger *refresh.Exchanger
	tokens    store.RefreshTokenStore
	events    *recordingEmitter
	root      string
	child     string
}

func newDeferredFixture(tb testing.TB) deferredFixture {
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
		Store:              tokens,
		Clock:              clk,
		Audit:              events,
		DeferReplayCascade: true,
	})
	if err != nil {
		tb.Fatalf("NewExchanger: %v", err)
	}
	ctx := context.Background()
	root, err := issuer.Issue(ctx, goodIssue())
	if err != nil {
		tb.Fatalf("Issue root: %v", err)
	}
	out, err := exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		tb.Fatalf("Exchange root: %v", err)
	}
	parent := out.ConsumedID
	child, err := issuer.Issue(ctx, refresh.IssueInput{
		ClientID: out.ClientID,
		Subject:  out.Subject,
		GrantID:  out.GrantID,
		Scope:    out.Scope,
		ParentID: &parent,
	})
	if err != nil {
		tb.Fatalf("Issue child: %v", err)
	}
	// Past the grace window so the replay below takes the strict path rather
	// than the idempotent-retry path.
	cur = cur.Add(refresh.GraceTTLDefault + time.Second)
	return deferredFixture{exchanger: exchanger, tokens: tokens, events: events, root: root, child: child}
}

// chainTipRevoked reports whether the live successor has been retired.
func (f deferredFixture) chainTipRevoked(tb testing.TB) bool {
	tb.Helper()
	rec, err := f.tokens.Find(context.Background(), f.child)
	if err != nil {
		tb.Fatalf("Find chain tip: %v", err)
	}
	return rec.Revoked
}

// TestExchange_DeferredCascadeWaitsForTheCaller pins the contract
// DeferReplayCascade hands over: Exchange still reports the replay as
// ErrTokenReplayed, but the chain stays intact until the caller runs
// RevokeReplayedChain. That separation is what lets a caller who wraps
// Exchange in a transaction place the cascade after the transaction settles
// instead of inside it, where a bounded transaction would cap it and a
// rollback would discard it.
func TestExchange_DeferredCascadeWaitsForTheCaller(t *testing.T) {
	t.Parallel()

	f := newDeferredFixture(t)
	ctx := context.Background()

	_, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: f.root, ClientID: "client-1"})
	if !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}
	if f.chainTipRevoked(t) {
		t.Fatal("Exchange retired the chain inline despite DeferReplayCascade")
	}

	f.exchanger.RevokeReplayedChain(ctx, f.root)

	if !f.chainTipRevoked(t) {
		t.Error("RevokeReplayedChain left the live chain tip redeemable")
	}
}

// TestExchange_DeferredCascadeStillEmitsReplayDetected pins the half of the
// finding that must NOT move with the cascade: the replay audit event fires
// inside Exchange in either mode, so a caller that never gets to run the
// cascade cannot swallow the detection.
func TestExchange_DeferredCascadeStillEmitsReplayDetected(t *testing.T) {
	t.Parallel()

	f := newDeferredFixture(t)
	ctx := context.Background()

	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: f.root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	var found bool
	events := f.events.snapshot()
	for _, ev := range events {
		if ev.Name == "refresh.replay_detected" && ev.Level == audit.LevelWarn {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected refresh.replay_detected warn event, got %+v", events)
	}
}

// TestRevokeReplayedChain_EmptyTokenIsNoOp pins the guard: a caller that
// arms nothing and runs the cascade anyway must not walk a chain from an
// empty handle.
func TestRevokeReplayedChain_EmptyTokenIsNoOp(t *testing.T) {
	t.Parallel()

	f := newDeferredFixture(t)
	f.exchanger.RevokeReplayedChain(context.Background(), "")
	if f.chainTipRevoked(t) {
		t.Error("RevokeReplayedChain(\"\") retired a chain")
	}
	if events := f.events.snapshot(); len(events) != 0 {
		t.Errorf("RevokeReplayedChain(\"\") emitted %+v", events)
	}
}
