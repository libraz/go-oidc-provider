package inmem

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

type parTestClock struct{ now time.Time }

func (c *parTestClock) Now() time.Time { return c.now }

func TestPARSaveAmortizesFullSweep(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ps := s.pars
	ctx := context.Background()

	if err := ps.Save(ctx, &store.PushedAuthRequest{
		URI:       "urn:ietf:params:oauth:request_uri:expired-1",
		ClientID:  "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: clk.now.Add(-parRetention - time.Second),
		CreatedAt: clk.now.Add(-parRetention - time.Minute),
	}); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if len(ps.m) != 1 {
		t.Fatalf("after first save len=%d want 1 (expired record retained until amortized sweep)", len(ps.m))
	}

	for i := uint32(1); i < parFullGCSaveInterval; i++ {
		if err := ps.Save(ctx, &store.PushedAuthRequest{
			URI:       "urn:ietf:params:oauth:request_uri:fresh-" + strconv.Itoa(int(i)),
			ClientID:  "client-1",
			RawParams: []byte("response_type=code"),
			ExpiresAt: clk.now.Add(time.Minute),
			CreatedAt: clk.now,
		}); err != nil {
			t.Fatalf("Save fresh #%d: %v", i, err)
		}
	}
	if _, exists := ps.m[hashKey("urn:ietf:params:oauth:request_uri:expired-1")]; exists {
		t.Fatal("PAR past its retention window survived the amortized full sweep")
	}
	if ps.savesSinceGC != 0 {
		t.Fatalf("savesSinceGC=%d want 0 after sweep", ps.savesSinceGC)
	}
}

// TestPARSaveReclaimsKeyPastRetention covers the other side of the
// key-scoped eviction: once a record is past [parRetention] the store
// has finished with it, so a push claiming that key is no longer
// refused as a duplicate of a row nobody can redeem.
func TestPARSaveReclaimsKeyPastRetention(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ps := s.pars
	ctx := context.Background()

	const uri = "urn:ietf:params:oauth:request_uri:reclaimed"
	if err := ps.Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: clk.now.Add(time.Minute),
		CreatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	clk.now = clk.now.Add(time.Minute + parRetention + time.Second)
	if err := ps.Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client-1",
		RawParams: []byte("response_type=code&scope=openid"),
		ExpiresAt: clk.now.Add(time.Minute),
		CreatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save past retention: %v", err)
	}
	if _, err := ps.Find(ctx, uri); err != nil {
		t.Fatalf("Find after reclaiming the key: %v", err)
	}
}

// TestPARTxSaveRefusesToDisplaceRedeemableRecord holds the
// transactional insert to the same reclamation predicate as the direct
// one: a staged record replaces the committed row under its key at
// commit, so it may only claim a key whose record is past retention.
func TestPARTxSaveRefusesToDisplaceRedeemableRecord(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	const uri = "urn:ietf:params:oauth:request_uri:tx-collision"
	if err := s.pars.Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: clk.now.Add(time.Minute),
		CreatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	clk.now = clk.now.Add(5 * time.Minute)

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			t.Errorf("Rollback: %v", err)
		}
	}()
	err = tx.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client-1",
		RawParams: []byte("response_type=code&scope=openid"),
		ExpiresAt: clk.now.Add(time.Minute),
		CreatedAt: clk.now,
	})
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("tx Save onto a redeemable record: want ErrAlreadyExists, got %v", err)
	}
}

// TestPARSweepKeepsUnconsumedRecordRedeemable pins the reclamation
// invariant that the sweep cannot observably change Consume: a pushed
// request that the user has not finished authenticating for stays
// redeemable exactly once, however long its own lifetime has been over
// and however many unrelated pushes arrived meanwhile. Reclaiming on
// expiry alone turns a completed interactive login into access_denied
// at code emission, intermittently and only under push load.
func TestPARSweepKeepsUnconsumedRecordRedeemable(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ps := s.pars
	ctx := context.Background()

	const uri = "urn:ietf:params:oauth:request_uri:slow-login"
	if err := ps.Save(ctx, &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: clk.now.Add(time.Minute),
		CreatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The user spends longer on password, second factor and consent
	// than the request_uri lifetime.
	clk.now = clk.now.Add(5 * time.Minute)

	// Other clients keep pushing while that login is in progress,
	// crossing the sweep threshold several times over.
	for i := range 4 * int(parFullGCSaveInterval) {
		if err := ps.Save(ctx, &store.PushedAuthRequest{
			URI:       "urn:ietf:params:oauth:request_uri:other-" + strconv.Itoa(i),
			ClientID:  "client-2",
			RawParams: []byte("response_type=code"),
			ExpiresAt: clk.now.Add(time.Minute),
			CreatedAt: clk.now,
		}); err != nil {
			t.Fatalf("Save unrelated push #%d: %v", i, err)
		}
	}

	got, err := ps.Consume(ctx, uri)
	if err != nil {
		t.Fatalf("Consume after unrelated pushes: %v (the login completed; the sweep must not deny it)", err)
	}
	if got.ConsumedAt == nil {
		t.Fatal("Consume returned ConsumedAt=nil")
	}
	// Retention must not weaken single use: the replay still fails.
	if _, err := ps.Consume(ctx, uri); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}
