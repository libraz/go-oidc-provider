package contract

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file holds the redemption-state matrix: every substore that
// declares an id-keyed Consume, driven through every combination of the
// two conditions that decide its answer.
//
// The two conditions are the record's own: whether it has already been
// redeemed, and whether its lifetime has run out. They are independent,
// so there are four states, and the interesting one is the pair — an
// expired record that was also redeemed. A backend reaches it whenever a
// client presents a token it has been holding offline, or one restored
// from a backup, and the two checks are evaluated in whichever order the
// implementation happens to have written them.
//
// The order is not a detail. [store.RefreshTokenStore.Consume] makes it
// normative — expiry takes precedence — because the two answers lead to
// different places: ErrNotFound is an ordinary invalid_grant, while
// ErrAlreadyConsumed is replay evidence that runs the RFC 9700 §2.2.2
// cascade and takes the client's whole chain down with it. A backend
// that checks redeemed-ness first turns an expired token into a
// self-inflicted outage for the account that presented it.
//
// The grid is generated rather than listed. Every combination of the two
// conditions is driven against every substore whose interface declares
// the redemption, so a state nobody thought to write a case for is not a
// state the suite silently skips.

// consumeState is one cell of the redemption grid.
type consumeState struct {
	// consumed reports that the record was already redeemed before the
	// call under test.
	consumed bool

	// expired reports that the record's ExpiresAt is behind the
	// backend's clock at the time of the call.
	expired bool
}

func (s consumeState) name() string {
	switch {
	case s.consumed && s.expired:
		return "ExpiredAndConsumed"
	case s.consumed:
		return "Consumed"
	case s.expired:
		return "Expired"
	default:
		return "Live"
	}
}

// consumeStates enumerates the grid. The loop is the point: the cases
// come from the combination of the conditions rather than from a list
// somebody kept in sync with it.
func consumeStates() []consumeState {
	out := make([]consumeState, 0, 4)
	for _, consumed := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			out = append(out, consumeState{consumed: consumed, expired: expired})
		}
	}
	return out
}

// recordRule says what the interface requires of the record a Consume
// hands back alongside its answer.
type recordRule uint8

const (
	// recordRequired: the answer is worthless without the record. A
	// successful redemption returns what was redeemed, and
	// [store.RefreshTokenStore.Consume] extends the same MUST to its
	// replay answer so the caller can recover the chain root.
	recordRequired recordRule = iota

	// recordForbidden: handing the record back is itself the defect.
	// [store.PushedAuthRequestStore.Consume] forbids it on replay
	// because the record carries the whole pushed authorization request.
	recordForbidden

	// recordOptional: the interface leaves it to the backend.
	recordOptional
)

// consumeOutcome is what one cell of the grid must answer.
type consumeOutcome struct {
	// err is the sentinel the call must satisfy; nil means the
	// redemption succeeds.
	err error

	// record is what the answer owes the caller.
	record recordRule
}

// consumable is one row of the matrix: a substore that declares an
// id-keyed Consume, with the states it can be driven into and the answer
// its interface declares for each.
type consumable struct {
	// accessor is the [store.Store] method that returns the substore.
	// [consumeCoverage] matches it against the accessors whose interface
	// declares the redemption, which is what keeps the matrix complete.
	accessor string

	// arrange puts a record into st and returns the id to present. It
	// skips the sub-test when the backend cannot be driven into the
	// state — reaching "expired and consumed" needs a redemption
	// followed by a clock that moves, and not every backend exposes one.
	arrange func(t *testing.T, b Backend, ctx context.Context, st consumeState) string

	// consume redeems id and reports whether a record came back.
	consume func(ctx context.Context, s store.Store, id string) (bool, error)

	// want maps a state onto the answer the interface declares.
	want func(st consumeState) consumeOutcome

	// require skips the row when the backend does not provide the
	// substore at all.
	require func(t *testing.T, s store.Store)
}

// consumeCases is the generated grid: one sub-test per (substore,
// state), plus the coverage guard that checks the rows against the
// interfaces.
//
//nolint:gochecknoglobals // sub-test table generated from the interface declarations.
var consumeCases = buildConsumeCases()

func buildConsumeCases() []subtest {
	states := consumeStates()
	cases := make([]subtest, 0, 1+len(consumables)*len(states))
	cases = append(cases, subtest{"Coverage", consumeCoverage})
	for _, sub := range consumables {
		for _, st := range states {
			cases = append(cases, subtest{
				name: sub.accessor + "/" + st.name(),
				fn: func(t *testing.T, f Factory) {
					runConsumeCase(t, f, sub, st)
				},
			})
		}
	}
	return cases
}

func runConsumeCase(t *testing.T, f Factory, sub consumable, st consumeState) {
	b := f(t)
	sub.require(t, b.Store)
	ctx := context.Background()
	id := sub.arrange(t, b, ctx, st)
	want := sub.want(st)

	found, err := sub.consume(ctx, b.Store, id)
	switch {
	case want.err == nil && err != nil:
		t.Fatalf("%s().Consume on a %s record: want success, got %v", sub.accessor, st.name(), err)
	case want.err != nil && !errors.Is(err, want.err):
		t.Fatalf("%s().Consume on a %s record: want %v, got %v — the answer decides whether the "+
			"endpoint reports an ordinary invalid_grant or runs a revocation cascade",
			sub.accessor, st.name(), want.err, err)
	}
	switch want.record {
	case recordRequired:
		if !found {
			t.Fatalf("%s().Consume on a %s record answered %v without the record: the caller cannot "+
				"recover what it needs from the answer alone", sub.accessor, st.name(), err)
		}
	case recordForbidden:
		if found {
			t.Fatalf("%s().Consume on a %s record answered %v and handed the record back: a failed "+
				"redemption must not deliver the record it refused", sub.accessor, st.name(), err)
		}
	case recordOptional:
	}
}

// consumeCoverage checks the matrix against the substores whose
// interface declares an id-keyed Consume.
//
// Listing the rows by hand is what lets a substore join the redemption
// contract without joining the grid: the interface declares the
// single-use rule, no case drives it, and the backend that gets the
// precedence backwards is discovered by an account whose whole refresh
// chain was revoked for presenting an expired token.
func consumeCoverage(t *testing.T, _ Factory) {
	covered := make(map[string]string, len(consumables))
	for _, sub := range consumables {
		covered[sub.accessor] = "consumables"
	}
	assertCovers(t, "id-keyed Consume substores", idKeyedConsumeAccessors(), covered)
}

// consumeIDFor derives a per-cell record id so the four states of one
// substore cannot collide if a backend is ever reused across them.
func consumeIDFor(prefix string, st consumeState) string {
	return fmt.Sprintf("%s-%s", prefix, st.name())
}

// pastExpiry is the ExpiresAt an arranged record carries when the cell
// wants it already lapsed.
func pastExpiry(b Backend) time.Time { return b.Now().Add(-time.Hour) }

//nolint:gochecknoglobals // matrix rows; declared once so [Run] can iterate.
var consumables = []consumable{
	{
		accessor: "AuthorizationCodes",
		require:  func(*testing.T, store.Store) {},
		arrange: func(t *testing.T, b Backend, ctx context.Context, st consumeState) string {
			t.Helper()
			id := consumeIDFor("ac-matrix", st)
			code := newAuthCode(b.Now(), id)
			if st.expired {
				code.ExpiresAt = pastExpiry(b)
			}
			if st.consumed {
				stamped := pastExpiry(b)
				code.ConsumedAt = &stamped
			}
			if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
				t.Fatalf("Save %s: %v", id, err)
			}
			return id
		},
		consume: func(ctx context.Context, s store.Store, id string) (bool, error) {
			got, err := s.AuthorizationCodes().Consume(ctx, id)
			return got != nil, err
		},
		want: func(st consumeState) consumeOutcome {
			switch {
			case st.expired:
				// Expiry outranks redemption: an expired code that was
				// also redeemed is an ordinary invalid_grant, not the
				// replay evidence that revokes the user's grant.
				return consumeOutcome{err: store.ErrNotFound, record: recordOptional}
			case st.consumed:
				return consumeOutcome{err: store.ErrAlreadyConsumed, record: recordOptional}
			default:
				return consumeOutcome{record: recordRequired}
			}
		},
	},
	{
		accessor: "RefreshTokens",
		require:  func(*testing.T, store.Store) {},
		arrange: func(t *testing.T, b Backend, ctx context.Context, st consumeState) string {
			t.Helper()
			id := consumeIDFor("rt-matrix", st)
			rt := newRefresh(b.Now(), id, nil)
			if st.expired {
				rt.ExpiresAt = pastExpiry(b)
			}
			if st.consumed {
				stamped := pastExpiry(b)
				rt.ConsumedAt = &stamped
			}
			if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
				t.Fatalf("Save %s: %v", id, err)
			}
			return id
		},
		consume: func(ctx context.Context, s store.Store, id string) (bool, error) {
			got, err := s.RefreshTokens().Consume(ctx, id)
			return got != nil, err
		},
		want: func(st consumeState) consumeOutcome {
			switch {
			case st.expired:
				return consumeOutcome{err: store.ErrNotFound, record: recordOptional}
			case st.consumed:
				// The replay answer carries the record: the cascade
				// recovers the chain root from it, and a nil record
				// degrades a targeted revocation into a guess.
				return consumeOutcome{err: store.ErrAlreadyConsumed, record: recordRequired}
			default:
				return consumeOutcome{record: recordRequired}
			}
		},
	},
	{
		accessor: "PushedAuthRequests",
		require:  func(*testing.T, store.Store) {},
		arrange: func(t *testing.T, b Backend, ctx context.Context, st consumeState) string {
			t.Helper()
			id := consumeIDFor("urn:par:matrix", st)
			par := newPAR(b.Now(), id)
			if st.expired {
				par.ExpiresAt = pastExpiry(b)
			}
			if st.consumed {
				stamped := pastExpiry(b)
				par.ConsumedAt = &stamped
			}
			if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
				t.Fatalf("Save %s: %v", id, err)
			}
			return id
		},
		consume: func(ctx context.Context, s store.Store, id string) (bool, error) {
			got, err := s.PushedAuthRequests().Consume(ctx, id)
			return got != nil, err
		},
		want: func(st consumeState) consumeOutcome {
			// The request_uri is the one redemption expiry does not
			// gate: an interactive login that outlives the lifetime
			// reaches Consume only after Find already admitted the
			// request, so re-applying the gate here would fail the flow
			// at code emission for no security benefit.
			if st.consumed {
				return consumeOutcome{err: store.ErrAlreadyConsumed, record: recordForbidden}
			}
			return consumeOutcome{record: recordRequired}
		},
	},
	{
		accessor: "DeviceCodes",
		require: func(t *testing.T, s store.Store) {
			t.Helper()
			requireDeviceCodes(t, s)
		},
		arrange: func(t *testing.T, b Backend, ctx context.Context, st consumeState) string {
			t.Helper()
			return arrangeDeviceCode(t, b, ctx, st)
		},
		consume: func(ctx context.Context, s store.Store, id string) (bool, error) {
			got, err := s.DeviceCodes().Consume(ctx, id)
			return got != nil, err
		},
		want: func(st consumeState) consumeOutcome {
			switch {
			case st.expired:
				return consumeOutcome{err: store.ErrNotFound, record: recordOptional}
			case st.consumed:
				return consumeOutcome{err: store.ErrAlreadyConsumed, record: recordOptional}
			default:
				return consumeOutcome{record: recordRequired}
			}
		},
	},
	{
		accessor: "CIBARequests",
		require: func(t *testing.T, s store.Store) {
			t.Helper()
			requireCIBA(t, s)
		},
		arrange: func(t *testing.T, b Backend, ctx context.Context, st consumeState) string {
			t.Helper()
			return arrangeCIBARequest(t, b, ctx, st)
		},
		consume: func(ctx context.Context, s store.Store, id string) (bool, error) {
			got, err := s.CIBARequests().Consume(ctx, id)
			return got != nil, err
		},
		want: func(st consumeState) consumeOutcome {
			switch {
			case st.expired:
				return consumeOutcome{err: store.ErrNotFound, record: recordOptional}
			case st.consumed:
				return consumeOutcome{err: store.ErrAlreadyConsumed, record: recordOptional}
			default:
				return consumeOutcome{record: recordRequired}
			}
		},
	},
}

// arrangeDeviceCode drives a device-authorization record into st.
//
// Unlike the token substores the record cannot be seeded into its
// redeemed state directly: [store.DeviceCodeStore.Save] persists a
// freshly created record, and every later state is reached through the
// transitions the interface declares. The expired-and-redeemed cell
// therefore needs a clock that moves, and skips on a backend that does
// not expose one rather than pretending the state was reached.
func arrangeDeviceCode(t *testing.T, b Backend, ctx context.Context, st consumeState) string {
	t.Helper()
	dc := requireDeviceCodes(t, b.Store)
	id := consumeIDFor("dc-matrix", st)
	rec := newDeviceCode(b.Now(), id, deviceUserCodeFor(st))
	if st.expired && !st.consumed {
		rec.ExpiresAt = pastExpiry(b)
	}
	if err := dc.Save(ctx, rec); err != nil {
		t.Fatalf("Save %s: %v", id, err)
	}
	if st.expired && !st.consumed {
		return id
	}
	if err := dc.Approve(ctx, id, "sub-1", b.Now()); err != nil {
		t.Fatalf("Approve %s: %v", id, err)
	}
	if !st.consumed {
		return id
	}
	if _, err := dc.Consume(ctx, id); err != nil {
		t.Fatalf("arrange Consume %s: %v", id, err)
	}
	if st.expired {
		advancePastExpiry(t, b)
	}
	return id
}

// arrangeCIBARequest is [arrangeDeviceCode] for the backchannel
// authentication record, which has the same closed state machine.
func arrangeCIBARequest(t *testing.T, b Backend, ctx context.Context, st consumeState) string {
	t.Helper()
	cr := requireCIBA(t, b.Store)
	id := consumeIDFor("ar-matrix", st)
	rec := newCIBARequest(b.Now(), id)
	if st.expired && !st.consumed {
		rec.ExpiresAt = pastExpiry(b)
	}
	if err := cr.Save(ctx, rec); err != nil {
		t.Fatalf("Save %s: %v", id, err)
	}
	if st.expired && !st.consumed {
		return id
	}
	if err := cr.Approve(ctx, id, "sub", "urn:mace:incommon:iap:silver", b.Now()); err != nil {
		t.Fatalf("Approve %s: %v", id, err)
	}
	if !st.consumed {
		return id
	}
	if _, err := cr.Consume(ctx, id); err != nil {
		t.Fatalf("arrange Consume %s: %v", id, err)
	}
	if st.expired {
		advancePastExpiry(t, b)
	}
	return id
}

// advancePastExpiry moves the backend clock beyond the lifetime the
// record builders hand out, skipping when the backend has no injectable
// clock.
func advancePastExpiry(t *testing.T, b Backend) {
	t.Helper()
	if b.Advance == nil {
		t.Skip("backend supplies no Advance hook: the expired-and-redeemed cell needs a clock that moves")
	}
	b.Advance(25 * time.Hour)
}

// deviceUserCodeFor keeps the four cells of the device-code row on
// distinct user codes, which the substore indexes uniquely.
func deviceUserCodeFor(st consumeState) string {
	switch {
	case st.consumed && st.expired:
		return "CNSM-0003"
	case st.consumed:
		return "CNSM-0002"
	case st.expired:
		return "CNSM-0001"
	default:
		return "CNSM-0000"
	}
}
