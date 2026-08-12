package contract

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file holds the concurrency contract sub-tests. Every case here
// drives one operation from several goroutines at once and pins what the
// substore looks like afterwards.
//
// The sequential cases elsewhere in the harness already pin single-use
// and idempotency as a caller sees them one call at a time. What they
// cannot catch is a backend that implements those rules as "read the
// record, decide, write it back": every such implementation passes the
// sequential case and then, under the parallel traffic the rule exists
// for, hands two callers the same single-use record or lets the writer
// that read first overwrite the one that read last.
//
// The traffic modelled is not hypothetical. A stolen authorization code
// is redeemed against the legitimate client's redemption; a device polls
// while its user_code is being guessed; a logout cascade runs against a
// replay cascade on the same grant.

// concurrentRacers is the number of goroutines each case drives an
// operation from. It is large enough that a lost update is near-certain
// on a backend that has one, and small enough to stay well inside any
// connection pool the harness runs against.
const concurrentRacers = 8

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var concurrencyCases = []subtest{
	{"AuthorizationCodeConsumeHasOneWinner", concurrentAuthCodeConsume},
	{"RefreshConsumeHasOneWinner", concurrentRefreshConsume},
	{"PushedAuthRequestConsumeHasOneWinner", concurrentPARConsume},
	{"DeviceCodeConsumeHasOneWinner", concurrentDeviceCodeConsume},
	{"CIBAConsumeHasOneWinner", concurrentCIBAConsume},
	{"RefreshRotationHasOneWinner", concurrentRefreshRotation},
	{"RevokeGrantKeepsTheWidestWindow", concurrentRevokeGrant},
}

// race runs attempt from [concurrentRacers] goroutines and returns their
// errors in launch order.
func race(attempt func(i int) error) []error {
	errs := make([]error, concurrentRacers)
	var wg sync.WaitGroup
	wg.Add(concurrentRacers)
	for i := range concurrentRacers {
		go func() {
			defer wg.Done()
			errs[i] = attempt(i)
		}()
	}
	wg.Wait()
	return errs
}

// assertOneWinner reports the index of the single attempt that
// succeeded, failing the test when the count is anything but one.
//
// Two winners means the record was handed out twice. Zero means the
// backend turned every caller away, which is just as wrong: the
// operation is one a legitimate client must be able to complete.
func assertOneWinner(t *testing.T, op string, errs []error) int {
	t.Helper()
	won, winner := 0, -1
	for i, err := range errs {
		if err == nil {
			won++
			winner = i
		}
	}
	if won != 1 {
		t.Fatalf("%s: %d of %d concurrent attempts succeeded, want exactly 1 (errors: %v)",
			op, won, len(errs), errs)
	}
	return winner
}

func concurrentAuthCodeConsume(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	codes := b.Store.AuthorizationCodes()
	if err := codes.Save(ctx, newAuthCode(b.Now(), "ac-race")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	errs := race(func(int) error {
		_, err := codes.Consume(ctx, "ac-race")
		return err
	})
	assertOneWinner(t, "AuthorizationCodes().Consume", errs)

	// The losers converge on the same answer a sequential replay gets, so
	// the token endpoint's replay cascade fires for them.
	if _, err := codes.Consume(ctx, "ac-race"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume after the race: want ErrAlreadyConsumed, got %v", err)
	}
}

func concurrentRefreshConsume(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	refreshes := b.Store.RefreshTokens()
	if err := refreshes.Save(ctx, newRefresh(b.Now(), "rt-race", nil)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	errs := race(func(int) error {
		_, err := refreshes.Consume(ctx, "rt-race")
		return err
	})
	assertOneWinner(t, "RefreshTokens().Consume", errs)

	if _, err := refreshes.Consume(ctx, "rt-race"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume after the race: want ErrAlreadyConsumed, got %v", err)
	}
}

func concurrentPARConsume(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	pars := b.Store.PushedAuthRequests()
	if err := pars.Save(ctx, newPAR(b.Now(), "urn:par:race")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	errs := race(func(int) error {
		_, err := pars.Consume(ctx, "urn:par:race")
		return err
	})
	assertOneWinner(t, "PushedAuthRequests().Consume", errs)

	if _, err := pars.Consume(ctx, "urn:par:race"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume after the race: want ErrAlreadyConsumed, got %v", err)
	}
}

func concurrentDeviceCodeConsume(t *testing.T, f Factory) {
	b := f(t)
	dc := requireDeviceCodes(t, b.Store)
	ctx := context.Background()
	if err := dc.Save(ctx, newDeviceCode(b.Now(), "dc-race", "AAAA-0401")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := dc.Approve(ctx, "dc-race", "sub-1", b.Now()); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// A device that polls faster than its interval has several polls in
	// flight the moment the user approves; only one may collect tokens.
	errs := race(func(int) error {
		_, err := dc.Consume(ctx, "dc-race")
		return err
	})
	assertOneWinner(t, "DeviceCodes().Consume", errs)

	if _, err := dc.Consume(ctx, "dc-race"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume after the race: want ErrAlreadyConsumed, got %v", err)
	}
}

func concurrentCIBAConsume(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Save(ctx, newCIBARequest(b.Now(), "ar-race")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cr.Approve(ctx, "ar-race", "sub", "urn:mace:incommon:iap:bronze", b.Now()); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	errs := race(func(int) error {
		_, err := cr.Consume(ctx, "ar-race")
		return err
	})
	assertOneWinner(t, "CIBARequests().Consume", errs)

	if _, err := cr.Consume(ctx, "ar-race"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume after the race: want ErrAlreadyConsumed, got %v", err)
	}
}

// concurrentRefreshRotation drives the RFC 9700 grace window under the
// traffic it was written for: a client whose token response was lost
// retries, and the retries arrive together.
//
// Exactly one rotation may install the successor, and the cached
// response the predecessor carries afterwards MUST be the one that
// rotation sealed. A backend that let a losing attempt write its own
// copy would answer the client's retry with a response describing tokens
// that were never issued.
func concurrentRefreshRotation(t *testing.T, f Factory) {
	b := f(t)
	refreshes := b.Store.RefreshTokens()
	retry, ok := refreshes.(store.RefreshRetryResponseStore)
	if !ok {
		t.Skipf("backend %T does not implement store.RefreshRetryResponseStore", refreshes)
	}
	ctx := context.Background()

	predecessor := newRefresh(b.Now(), "rt-rotate-race-parent", nil)
	if err := refreshes.Save(ctx, predecessor); err != nil {
		t.Fatalf("Save predecessor: %v", err)
	}
	if _, err := refreshes.Consume(ctx, predecessor.ID); err != nil {
		t.Fatalf("Consume predecessor: %v", err)
	}

	sealed := func(i int) []byte { return []byte("sealed-response-" + strconv.Itoa(i)) }
	errs := race(func(i int) error {
		successor := newRefresh(b.Now(), "rt-rotate-race-child", &predecessor.ID)
		return retry.SaveRotationWithRetry(ctx, successor, sealed(i))
	})
	winner := assertOneWinner(t, "RefreshTokens().SaveRotationWithRetry", errs)

	if _, err := refreshes.Find(ctx, "rt-rotate-race-child"); err != nil {
		t.Fatalf("Find successor after the race: %v", err)
	}
	got, err := retry.LoadRetryResponse(ctx, predecessor.ID)
	if err != nil {
		t.Fatalf("LoadRetryResponse: %v", err)
	}
	if !bytes.Equal(got, sealed(winner)) {
		t.Errorf("LoadRetryResponse = %q, want %q — the cached response is not the one the successful rotation sealed",
			got, sealed(winner))
	}
}

// concurrentRevokeGrant pins the tombstone's two horizons under parallel
// cascades. A logout, a replay detection, and an operator revocation can
// all target one grant at the same instant, each computing its own
// RevokedAt and its own retention.
//
// Both horizons MUST converge on the widest value supplied. A backend
// that reads the row and writes back what it decided lets the cascade
// that read first land last: RevokedAt then rewinds, and every access
// token minted between the two instants — the ones the later cascade
// existed to kill — starts verifying again.
func concurrentRevokeGrant(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()

	errs := race(func(i int) error {
		return gr.RevokeGrant(ctx, store.GrantTombstone{
			GrantID:   "grant-race",
			RevokedAt: now.Add(time.Duration(i) * time.Second),
			ExpiresAt: now.Add(time.Duration(i+1) * time.Hour),
			Reason:    "code_replay",
		})
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent RevokeGrant %d: %v", i, err)
		}
	}

	newest := now.Add(time.Duration(concurrentRacers-1) * time.Second)
	expectRevoked(t, gr, ctx, "grant-race", "", newest, true,
		"RevokedAt did not advance to the latest cascade: tokens minted before it verify again")
	expectRevoked(t, gr, ctx, "grant-race", "", newest.Add(time.Nanosecond), false,
		"RevokedAt advanced past every cascade: tokens minted after the last one were revoked")

	// A cutoff past every retention but the widest MUST leave the row: it
	// proves ExpiresAt converged on the longest-lived token's horizon
	// rather than on whichever cascade wrote last.
	widest := now.Add(time.Duration(concurrentRacers) * time.Hour)
	n, err := gr.GC(ctx, widest.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 0 {
		t.Fatalf("GC dropped %d rows: the tombstone kept a retention shorter than %s", n, widest)
	}
}
