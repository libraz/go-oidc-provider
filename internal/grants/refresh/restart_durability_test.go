package refresh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
)

// TestExchange_RotationVerdictSurvivesAProcessThatNeverSawTheRotation
// pins that whether a refresh token has already been spent is answered
// from the store, and from nothing the process is holding.
//
// Rotation is a promise with a long tail: a token handed out today may
// be replayed months later, across restarts, deploys and rescheduled
// pods, and across a fleet where the node that answers the replay is
// almost never the node that performed the rotation. Any part of the
// verdict that lives in process memory — a startup timestamp, a
// warm-up watermark, a cache of what this instance has seen — is
// therefore a part that resets. When it resets, tokens do not merely
// become unverifiable; they become valid again, which is the failure
// direction that matters.
//
// The test models the restart by building a second Exchanger over the
// same store. That is the whole of what a restart is from this code's
// point of view: new instance, no memory of the first, same durable
// state underneath. A verdict that depended on anything the first
// instance accumulated would come out differently here.
//
// Tracks: CVE-2026-9802 (Keycloak) — stale-token detection compared the
// token against the cluster startup time, which a server restart reset,
// so refresh tokens already rotated away were accepted again by anyone
// who had captured one.
func TestExchange_RotationVerdictSurvivesAProcessThatNeverSawTheRotation(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	original, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    original,
		ClientID: "client-1",
	}); err != nil {
		t.Fatalf("rotate the original token: %v", err)
	}

	// Move past the grace window, so the replay below is unambiguously
	// a replay rather than a legitimate retry of the rotation.
	*f.cur = f.cur.Add(24 * time.Hour)

	// The restart. Nothing carries over but the store.
	restarted, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: f.store,
		Clock: func() time.Time { return *f.cur },
	})
	if err != nil {
		t.Fatalf("NewExchanger after restart: %v", err)
	}

	_, err = restarted.Exchange(ctx, refresh.ExchangeInput{
		Token:    original,
		ClientID: "client-1",
	})
	if err == nil {
		t.Fatal("a refresh token rotated away before the restart was accepted by the restarted instance; " +
			"the staleness verdict is reading process-lifetime state rather than the store")
	}
	if !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay after restart: err=%v, want ErrTokenReplayed", err)
	}

	// The control: a token the restarted instance never saw issued is
	// still exchangeable through it, so the refusal above is about the
	// token's history and not about the instance being inert.
	fresh, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue after restart: %v", err)
	}
	if _, err := restarted.Exchange(ctx, refresh.ExchangeInput{
		Token:    fresh,
		ClientID: "client-1",
	}); err != nil {
		t.Fatalf("the restarted instance refused an unspent token: %v", err)
	}
}
