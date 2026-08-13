package contract

import (
	"bytes"
	"context"
	"errors"
	"slices"
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
	{"IATIncrementUsesHasOneWinner", concurrentIATSingleUse},
	{"IATIncrementUsesStopsAtTheCeiling", concurrentIATMultiUse},
	{"GrantAmendKeepsEveryWriterScope", concurrentGrantAmend},
}

// race runs attempt from [concurrentRacers] goroutines and returns their
// errors in launch order.
//
// The goroutines are held at a barrier until every one of them is
// running, so they enter the operation together. Launching them and
// letting them start where they may staggers the callers by however
// long the runtime took to schedule each one, which on a backend whose
// lost-update window is a single round trip is long enough for the
// window to have closed before the second caller arrives — and the
// contract case then reports a non-atomic backend as correct.
func race(attempt func(i int) error) []error {
	errs := make([]error, concurrentRacers)
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(concurrentRacers)
	done.Add(concurrentRacers)
	for i := range concurrentRacers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			errs[i] = attempt(i)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	return errs
}

// assertWinners reports the indices of the attempts that succeeded,
// failing the test when the count is anything but want.
//
// More winners than want means the record was handed out beyond its
// ceiling. Fewer is just as wrong: the operation is one a legitimate
// client must be able to complete, and a backend that turned an extra
// caller away rejected a registration the operator paid for.
func assertWinners(t *testing.T, op string, errs []error, want int) []int {
	t.Helper()
	won := make([]int, 0, want)
	for i, err := range errs {
		if err == nil {
			won = append(won, i)
		}
	}
	if len(won) != want {
		t.Fatalf("%s: %d of %d concurrent attempts succeeded, want exactly %d (errors: %v)",
			op, len(won), len(errs), want, errs)
	}
	return won
}

// assertOneWinner reports the index of the single attempt that
// succeeded, failing the test when the count is anything but one.
//
// Two winners means the record was handed out twice. Zero means the
// backend turned every caller away, which is just as wrong: the
// operation is one a legitimate client must be able to complete.
func assertOneWinner(t *testing.T, op string, errs []error) int {
	t.Helper()
	return assertWinners(t, op, errs, 1)[0]
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

// concurrentIATSingleUse drives the ceiling
// [store.InitialAccessTokenStore.IncrementUses] declares atomic under the
// traffic that makes the declaration matter: one Initial Access Token
// handed to an automated onboarding job that registers several clients at
// once, or leaked and replayed in parallel.
//
// A backend that reads the counter, decides, and writes it back passes
// every sequential registration case in the harness and then admits N
// clients on a single-use credential, because each racer reads the same
// pre-increment value. The ceiling is what the operator was promised when
// they minted the token, so it is asserted three ways: the number of
// callers told "yes", the answer every other caller got, and the counter
// the token carries afterwards.
func concurrentIATSingleUse(t *testing.T, f Factory) {
	concurrentIATIncrementUses(t, f, 0, 1)
}

// concurrentIATMultiUse is [concurrentIATSingleUse] for the multi-use
// tokens an operator mints for tenant onboarding. It exists because the
// single-use variant alone is passed by a backend that hard-codes a
// ceiling of one and ignores MaxUses entirely: such a backend would
// reject the second and third registration of an invitation that was
// paid for, and the single-use case cannot see it.
func concurrentIATMultiUse(t *testing.T, f Factory) {
	concurrentIATIncrementUses(t, f, 3, 3)
}

func concurrentIATIncrementUses(t *testing.T, f Factory, maxUses, ceiling int) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	ctx := context.Background()
	tok := newIAT(b.Now(), "iat-race", "hash-race")
	tok.MaxUses = maxUses
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}

	errs := race(func(int) error {
		_, err := s.IncrementUses(ctx, tok.ID)
		return err
	})
	assertWinners(t, "InitialAccessTokens().IncrementUses", errs, ceiling)
	for i, err := range errs {
		if err != nil && !errors.Is(err, store.ErrConflict) {
			t.Fatalf("IncrementUses %d past the ceiling: want ErrConflict, got %v — "+
				"the caller cannot tell a replay race from an absent or broken token", i, err)
		}
	}

	// The counter has to agree with the verdicts. A backend that answered
	// the right number of callers but let the lost updates overwrite each
	// other leaves a token that reads as unspent, and the next
	// registration is admitted on a credential already at its ceiling.
	got, err := s.GetByHash(ctx, tok.HashedValue)
	if err != nil {
		t.Fatalf("GetByHash after the race: %v", err)
	}
	if got.Uses != ceiling {
		t.Fatalf("Uses = %d after %d concurrent increments, want the ceiling %d",
			got.Uses, concurrentRacers, ceiling)
	}
	if _, err := s.IncrementUses(ctx, tok.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("IncrementUses after the race: want ErrConflict, got %v", err)
	}
}

// grantAmendAttempts bounds the retries [amendGrantScope] makes. It is
// far more generous than the bound the OP itself applies to a contended
// grant, because the traffic differs: the OP retries a user racing
// themselves across two tabs, while this case deliberately drives every
// racer at one record, and an optimistic backend hands out one commit per
// round.
const grantAmendAttempts = 4 * concurrentRacers

// concurrentGrantAmend drives the read-amend-write cycle
// [store.GrantStore.Save] declares backends must make safe, under the
// traffic the declaration names: several authorizations for the same
// (subject, client) completing at once, each adding a scope to what the
// record already holds.
//
// The union is the whole point. A grant is amended, not replaced, so a
// backend that neither locks the row nor rejects a stale basis lets the
// writer that read first land last: the scope the other authorization
// recorded disappears while both users are told their consent was
// stored, and the client that was granted it gets an access_denied on a
// scope the user approved.
//
// The cycle runs inside a transaction because that is the only shape in
// which either permitted defence exists — a row lock has to span the read
// and the write, and a rejected write has to have a basis to compare
// against — and it is the shape the OP itself uses on every path that
// amends a grant. Backends that do not implement [store.Transactional]
// never see that cycle and are skipped.
func concurrentGrantAmend(t *testing.T, f Factory) {
	b := f(t)
	txr := requireTransactional(t, b.Store)
	ctx := context.Background()
	base := newGrant(b.Now(), "grant-amend-race", "sub-amend", "client-amend")
	base.Scope = []string{"openid"}
	if err := b.Store.Grants().Save(ctx, base); err != nil {
		t.Fatalf("Save: %v", err)
	}

	errs := race(func(i int) error {
		return amendGrantScope(ctx, txr, base.ID, amendedScope(i))
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent amend %d: %v — every amendment is one a re-read reproduces, "+
				"so a caller that keeps re-reading has to be able to land it", i, err)
		}
	}

	got, err := b.Store.Grants().Find(ctx, base.ID)
	if err != nil {
		t.Fatalf("Find after the race: %v", err)
	}
	for i := range concurrentRacers {
		if !slices.Contains(got.Scope, amendedScope(i)) {
			t.Fatalf("scope %q is missing from %v: an amendment that reported success was overwritten "+
				"by one that read the record before it",
				amendedScope(i), got.Scope)
		}
	}
	if !slices.Contains(got.Scope, "openid") {
		t.Fatalf("the scope the grant started with is missing from %v", got.Scope)
	}
}

func amendedScope(i int) string { return "scope-" + strconv.Itoa(i) }

// amendGrantScope runs one read-amend-write cycle against a grant,
// re-driving the whole cycle when the backend reports the basis it read
// is no longer current. Retrying is what the contract asks of a caller:
// [store.GrantStore.Save] lets a backend answer [store.ErrConflict]
// instead of locking, and nothing about a losing attempt was invalid —
// the amendment it carried is one a re-read reproduces exactly.
func amendGrantScope(ctx context.Context, txr store.Transactional, id, scope string) error {
	var err error
	for attempt := 1; attempt <= grantAmendAttempts; attempt++ {
		if err = amendGrantScopeOnce(ctx, txr, id, scope); err == nil || !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

func amendGrantScopeOnce(ctx context.Context, txr store.Transactional, id, scope string) error {
	tx, err := txr.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	g, err := tx.Grants().Find(ctx, id)
	if err != nil {
		return err
	}
	g.Scope = append(slices.Clone(g.Scope), scope)
	if err := tx.Grants().Save(ctx, g); err != nil {
		return err
	}
	return tx.Commit()
}
