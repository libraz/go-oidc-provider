package refresh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// newNonRotatingFixture is [newFixture] with
// [refresh.ExchangerConfig.RotationDisabled] set.
func newNonRotatingFixture(tb testing.TB, t0 time.Time) fixture {
	tb.Helper()
	cur := t0
	clk := timex.ClockFunc(func() time.Time { return cur })
	st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: time.Hour})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store:              st,
		Clock:              clk,
		DeferReplayCascade: true,
		RotationDisabled:   true,
	})
	if err != nil {
		tb.Fatalf("NewExchanger: %v", err)
	}
	return fixture{issuer: iss, exchanger: exc, store: st, cur: &cur}
}

// TestExchange_RotationDisabled_TokenStaysRedeemable pins the
// non-rotating exchange: the presented token is not consumed, so it
// redeems again after the grace window a rotating exchanger would apply,
// and only its own expiry ends it.
func TestExchange_RotationDisabled_TokenStaysRedeemable(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newNonRotatingFixture(t, t0)
	ctx := context.Background()
	tok, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	for i, at := range []time.Duration{0, refresh.GraceTTLDefault + time.Second, 30 * time.Minute} {
		*f.cur = t0.Add(at)
		out, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: tok, ClientID: "client-1"})
		if err != nil {
			t.Fatalf("exchange %d at +%v: %v", i, at, err)
		}
		if out.ConsumedID != tok || out.InGrace {
			t.Errorf("exchange %d: ConsumedID=%q InGrace=%v, want the presented token outside grace", i, out.ConsumedID, out.InGrace)
		}
	}
	rec, err := f.store.Find(ctx, tok)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Errorf("record consumed at %v; a non-rotating exchange must leave it unconsumed", rec.ConsumedAt)
	}

	*f.cur = t0.Add(time.Hour + time.Second)
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: tok, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenMissing) {
		t.Errorf("expired token: err=%v, want ErrTokenMissing", err)
	}
}

// TestExchange_RotationDisabled_KeepsBindingChecks confirms the read
// path applies the client and scope rules the consuming path does.
func TestExchange_RotationDisabled_KeepsBindingChecks(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newNonRotatingFixture(t, t0)
	ctx := context.Background()
	tok, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: tok, ClientID: "client-2"}); !errors.Is(err, refresh.ErrClientMismatch) {
		t.Errorf("foreign client: err=%v, want ErrClientMismatch", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token: tok, ClientID: "client-1", RequestedScope: []string{"openid", "admin"},
	}); !errors.Is(err, refresh.ErrScopeWidening) {
		t.Errorf("widened scope: err=%v, want ErrScopeWidening", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: "unknown", ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenMissing) {
		t.Errorf("unknown token: err=%v, want ErrTokenMissing", err)
	}
	// None of the refusals spent the token.
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: tok, ClientID: "client-1"}); err != nil {
		t.Errorf("token refused after rejected attempts: %v", err)
	}
}

// TestExchange_RotationDisabled_RevokedChainIsRefused covers the
// revocation half: once the chain is retired the token reads as a
// replay, and the caller's cascade has a grant to act on.
func TestExchange_RotationDisabled_RevokedChainIsRefused(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newNonRotatingFixture(t, t0)
	ctx := context.Background()
	tok, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := f.store.RevokeChain(ctx, tok); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	_, err = f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: tok, ClientID: "client-1"})
	if !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("revoked token: err=%v, want ErrTokenReplayed", err)
	}
	if got := f.exchanger.RevokeReplayedChain(ctx, tok); got.GrantID != "grant-1" {
		t.Errorf("RevokeReplayedChain grant=%q, want grant-1", got.GrantID)
	}
}
