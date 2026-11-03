package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// commitRaceStore decorates the reference Store so one refresh transaction
// loses a concurrent presentation of the same token at Commit, the way a
// backend that checks consumed_at only in its conditional commit does.
type commitRaceStore struct {
	store.Store
	backing *inmem.Store
	// loseTo, when set, is the token a concurrent winner consumes just before
	// the next Commit, which then reports store.ErrConflict.
	loseTo  *atomic.Pointer[string]
	advance func()
}

func (s commitRaceStore) BeginTx(ctx context.Context) (store.Tx, error) {
	inner, err := s.Store.(store.Transactional).BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return commitRaceTx{Tx: inner, s: s}, nil
}

type commitRaceTx struct {
	store.Tx
	s commitRaceStore
}

func (t commitRaceTx) Commit() error {
	token := t.s.loseTo.Swap(nil)
	if token == nil {
		return t.Tx.Commit()
	}
	// The loser's staged writes are discarded; the winner's consumption lands.
	_ = t.Rollback()
	if _, err := t.s.backing.RefreshTokens().Consume(context.Background(), *token); err != nil {
		return err
	}
	t.s.advance()
	return store.ErrConflict
}

// TestRefresh_CommitConflictEndsAsReplay pins that a refresh presentation
// losing a concurrent race at Commit ends as a serialising backend would end
// it: invalid_grant with the RFC 9700 §2.2.2 cascade retiring the chain, never
// a server_error that skips the cascade. The losing attempt rotated nothing,
// so it must not record a token.refreshed event either.
func TestRefresh_CommitConflictEndsAsReplay(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	issuedAt := cur
	clock := movableClock{cur: &cur}
	backing := inmem.New(inmem.WithClock(clock))
	loseTo := &atomic.Pointer[string]{}
	decorated := commitRaceStore{
		Store:   backing,
		backing: backing,
		loseTo:  loseTo,
		// Past the grace window, so the re-run classifies the winner's
		// consumption as a replay rather than a lost-response retry.
		advance: func() { cur = cur.Add(2 * time.Minute) },
	}
	capture := newAuditCapture()
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithStore(decorated), op.WithUserStore(backing.Users()), op.WithAuditLogger(capture.logger())),
	)
	prov.Store = backing
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: cur},
	}
	client, secret := f.confidentialClientFixture(t)
	const grantID = "grant-commit-race"

	tip := seedReplayChain(t, f, client.ID, secret, "rt-commit-race", grantID)
	rotations := countAuditEvents(t, capture, "token.refreshed")
	if rotations != 2 {
		t.Fatalf("token.refreshed recorded %d times for two committed rotations, want 2", rotations)
	}

	loseTo.Store(&tip)
	assertRefreshRefused(t, f, client.ID, secret, tip, "presentation that lost the commit race")
	if loseTo.Load() != nil {
		t.Fatal("the commit race was never injected")
	}
	assertChainNodeRevoked(t, f, tip, "chain tip")
	assertGrantTombstoned(t, f, grantID, issuedAt)
	if got := countAuditEvents(t, capture, "token.refreshed"); got != rotations {
		t.Fatalf("token.refreshed recorded %d times, want %d: the attempt that lost the commit logged a rotation", got, rotations)
	}
}

// countAuditEvents counts the audit records named name.
func countAuditEvents(t *testing.T, c *auditCapture, name string) int {
	t.Helper()
	n := 0
	dec := json.NewDecoder(strings.NewReader(c.buf.String()))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode audit line: %v", err)
		}
		if rec["audit"] == "true" && rec["event"] == name {
			n++
		}
	}
	return n
}
