package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// DELETE /register/{client_id} has to leave the deployment with nothing
// live that is bound to the deleted client. The library reaches that
// state by probing every client-keyed substore for
// [store.RevokeByClient], so the guarantee is only as complete as the
// backend's implementation of it — and a type assertion that fails is
// silent by construction.
//
// That silence is what this group removes. A backend may decline the
// extension outright and leave the cascade to the embedder's
// OnClientDeleted hook, but it may not decline it substore by substore:
// a partial implementation reads as a working cascade at the call site
// and leaves live records behind in whichever substores were missed. So
// the group skips only when the backend implements the extension
// nowhere, and fails as soon as it implements the extension somewhere
// and not everywhere.
//
// That whole-backend rule is also why no adapter support matrix is
// maintained anywhere: the group derives each backend's participation
// from the backend itself, so there is no second description of it to
// fall out of date.

const (
	// cascadeTargetClient owns the records the cascade must retire.
	cascadeTargetClient = "cascade-target-client"

	// cascadeBystanderClient owns the record that must survive it.
	cascadeBystanderClient = "cascade-bystander-client"

	// cascadeAbsentClient was never registered. Revoking by it is a
	// no-op, not an error.
	cascadeAbsentClient = "cascade-absent-client"
)

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var clientCascadeCases = []subtest{
	{"EveryClientKeyedSubstoreParticipates", clientCascadeParity},
	{"NoLiveRecordSurvivesTheDeletedClient", clientCascadeRetiresEverySubstore},
	{"AbsentClientIsANoOp", clientCascadeAbsentClientIsANoOp},
}

// clientKeyedSubstore describes one substore that holds records keyed on
// a client, in the terms the cascade needs: how to reach it, how to put
// a record in it for a given client, and how to tell whether that record
// is still one the OP would honour.
//
// live is deliberately not "present". Backends are free to delete or to
// mark, and both satisfy [store.RevokeByClient]; what the endpoints
// downstream depend on is only that the record stops counting.
type clientKeyedSubstore struct {
	name string

	// handle returns the substore the library would probe, or nil when
	// the backend does not host it.
	handle func(store.Store) any

	// seed stores one record with the given id, bound to clientID.
	seed func(t *testing.T, b Backend, id, clientID string)

	// live reports whether the record is still honoured.
	live func(t *testing.T, b Backend, id string) bool
}

//nolint:gochecknoglobals // the substore table the cases and the parity check share.
var clientKeyedSubstores = []clientKeyedSubstore{
	refreshCascade,
	grantCascade,
	accessTokenCascade,
	opaqueAccessTokenCascade,
}

//nolint:gochecknoglobals // one entry of [clientKeyedSubstores]; see its comment.
var refreshCascade = clientKeyedSubstore{
	name:   "RefreshTokens",
	handle: func(s store.Store) any { return s.RefreshTokens() },
	seed: func(t *testing.T, b Backend, id, clientID string) {
		t.Helper()
		rt := newRefresh(b.Now(), id, nil)
		rt.ClientID = clientID
		if err := b.Store.RefreshTokens().Save(context.Background(), rt); err != nil {
			t.Fatalf("RefreshTokens.Save %s: %v", id, err)
		}
	},
	live: func(t *testing.T, b Backend, id string) bool {
		t.Helper()
		got, err := b.Store.RefreshTokens().Find(context.Background(), id)
		if errors.Is(err, store.ErrNotFound) {
			return false
		}
		if err != nil {
			t.Fatalf("RefreshTokens.Find %s: %v", id, err)
		}
		return got.ConsumedAt == nil && !got.Revoked
	},
}

//nolint:gochecknoglobals // one entry of [clientKeyedSubstores]; see its comment.
var grantCascade = clientKeyedSubstore{
	name:   "Grants",
	handle: func(s store.Store) any { return s.Grants() },
	seed: func(t *testing.T, b Backend, id, clientID string) {
		t.Helper()
		// Each grant gets its own subject: a subject holds at most one
		// grant per client, and the case is about the client key.
		g := newGrant(b.Now(), id, "sub-"+id, clientID)
		if err := b.Store.Grants().Save(context.Background(), g); err != nil {
			t.Fatalf("Grants.Save %s: %v", id, err)
		}
	},
	live: func(t *testing.T, b Backend, id string) bool {
		t.Helper()
		_, err := b.Store.Grants().Find(context.Background(), id)
		if errors.Is(err, store.ErrNotFound) {
			return false
		}
		if err != nil {
			t.Fatalf("Grants.Find %s: %v", id, err)
		}
		return true
	},
}

//nolint:gochecknoglobals // one entry of [clientKeyedSubstores]; see its comment.
var accessTokenCascade = clientKeyedSubstore{
	name:   "AccessTokenRegistry",
	handle: func(s store.Store) any { return s.AccessTokens() },
	seed: func(t *testing.T, b Backend, id, clientID string) {
		t.Helper()
		rec := newAccessTokenRecord(b.Now(), id, "grant-"+id)
		rec.ClientID = clientID
		if err := b.Store.AccessTokens().Register(context.Background(), rec); err != nil {
			t.Fatalf("AccessTokens.Register %s: %v", id, err)
		}
	},
	live: func(t *testing.T, b Backend, id string) bool {
		t.Helper()
		got, ok := findAccessToken(t, b.Store.AccessTokens(), id)
		return ok && !got.Revoked
	},
}

//nolint:gochecknoglobals // one entry of [clientKeyedSubstores]; see its comment.
var opaqueAccessTokenCascade = clientKeyedSubstore{
	name:   "OpaqueAccessTokens",
	handle: func(s store.Store) any { return s.OpaqueAccessTokens() },
	seed: func(t *testing.T, b Backend, id, clientID string) {
		t.Helper()
		tok := newOpaqueAT(b.Now(), id, "grant-"+id)
		tok.ClientID = clientID
		if err := b.Store.OpaqueAccessTokens().Save(context.Background(), tok); err != nil {
			t.Fatalf("OpaqueAccessTokens.Save %s: %v", id, err)
		}
	},
	live: func(t *testing.T, b Backend, id string) bool {
		t.Helper()
		got, err := b.Store.OpaqueAccessTokens().Find(context.Background(), id)
		if errors.Is(err, store.ErrNotFound) {
			return false
		}
		if err != nil {
			t.Fatalf("OpaqueAccessTokens.Find %s: %v", id, err)
		}
		return !got.Revoked
	},
}

// cascadeParticipation splits the client-keyed substores a backend hosts
// into those that implement [store.RevokeByClient] and those that do
// not. Substores the backend does not host at all appear in neither.
func cascadeParticipation(s store.Store) (implementing, missing []string) {
	for _, sub := range clientKeyedSubstores {
		handle := sub.handle(s)
		if handle == nil {
			continue
		}
		if _, ok := handle.(store.RevokeByClient); ok {
			implementing = append(implementing, sub.name)
			continue
		}
		missing = append(missing, sub.name)
	}
	return implementing, missing
}

// clientCascadeParity is the case that makes an unimplemented substore
// visible, and it is the only one that can. The behavioural case can
// exercise a substore only through the interface, so a substore that
// does not implement it is invisible there — which is the whole defect.
// This case reads the participation of the hosted set instead, so a
// backend that implements the cascade for three substores and forgets
// the fourth fails here, naming the fourth.
func clientCascadeParity(t *testing.T, f Factory) {
	b := f(t)
	implementing, missing := cascadeParticipation(b.Store)
	if len(implementing) == 0 {
		t.Skipf(
			"backend %T implements store.RevokeByClient on none of its client-keyed substores (%v); "+
				"deleting a dynamically registered client leaves the cascade to the embedder's OnClientDeleted hook",
			b.Store, missing,
		)
	}
	if len(missing) > 0 {
		t.Fatalf(
			"backend %T implements store.RevokeByClient on %v but not on %v; "+
				"deleting a dynamically registered client would leave live records bound to it in the latter",
			b.Store, implementing, missing,
		)
	}
}

// participating resolves the [store.RevokeByClient] handles a backend
// offers, or ends the case when it offers none. Every case in the group
// needs the same preamble, and the skip has to be decided from the whole
// backend rather than one substore: declining the extension is a
// property of the backend, not of a substore.
func participating(t *testing.T, b Backend) map[string]store.RevokeByClient {
	t.Helper()
	implementing, _ := cascadeParticipation(b.Store)
	if len(implementing) == 0 {
		t.Skipf("backend %T implements store.RevokeByClient on none of its client-keyed substores", b.Store)
	}
	handles := make(map[string]store.RevokeByClient, len(implementing))
	for _, sub := range clientKeyedSubstores {
		handle := sub.handle(b.Store)
		if handle == nil {
			continue
		}
		if revoke, ok := handle.(store.RevokeByClient); ok {
			handles[sub.name] = revoke
		}
	}
	return handles
}

// clientCascadeRetiresEverySubstore is the behavioural case, and it runs
// every substore's cascade against one backend rather than one substore
// per case. That is the shape of the guarantee: DELETE
// /register/{client_id} fires all of them and then the deployment must
// hold nothing live for that client anywhere. Splitting it per substore
// would test four methods and still not pin the property they add up to
// — nor would it catch one substore's cascade reaching into another's
// records, which the bystander assertions here do.
//
// Every check reports with Errorf rather than Fatalf, so a run names
// every substore that got it wrong instead of stopping at the first.
func clientCascadeRetiresEverySubstore(t *testing.T, f Factory) {
	b := f(t)
	handles := participating(t, b)
	arranged := arrangeCascadeFixtures(t, b, handles)

	ctx := context.Background()
	for _, s := range arranged {
		if err := handles[s.sub.name].RevokeByClient(ctx, cascadeTargetClient); err != nil {
			t.Errorf("%s.RevokeByClient: %v", s.sub.name, err)
		}
	}

	for _, s := range arranged {
		assertCascadeReached(t, b, s)
	}
}

// cascadeFixture is what one substore holds going into the cascade: two
// records for the client about to be deleted and one for a client that
// stays registered.
type cascadeFixture struct {
	sub       clientKeyedSubstore
	targets   []string
	bystander string
}

// arrangeCascadeFixtures seeds every participating substore before any
// cascade runs, so each one executes against a store that holds records
// for both clients everywhere. A cascade that over-reaches then has
// something to hit.
func arrangeCascadeFixtures(
	t *testing.T,
	b Backend,
	handles map[string]store.RevokeByClient,
) []cascadeFixture {
	t.Helper()
	arranged := make([]cascadeFixture, 0, len(handles))
	for _, sub := range clientKeyedSubstores {
		if _, ok := handles[sub.name]; !ok {
			continue
		}
		fixture := cascadeFixture{
			sub:       sub,
			targets:   []string{sub.name + "-target-a", sub.name + "-target-b"},
			bystander: sub.name + "-bystander",
		}
		for _, id := range fixture.targets {
			sub.seed(t, b, id, cascadeTargetClient)
		}
		sub.seed(t, b, fixture.bystander, cascadeBystanderClient)
		arranged = append(arranged, fixture)
	}
	return arranged
}

func assertCascadeReached(t *testing.T, b Backend, fixture cascadeFixture) {
	t.Helper()
	for _, id := range fixture.targets {
		if fixture.sub.live(t, b, id) {
			t.Errorf(
				"%s record %q is still live after the client that owns it was deleted",
				fixture.sub.name, id,
			)
		}
	}
	if !fixture.sub.live(t, b, fixture.bystander) {
		t.Errorf(
			"the cascade for %q retired %s record %q, which belongs to %q",
			cascadeTargetClient, fixture.sub.name, fixture.bystander, cascadeBystanderClient,
		)
	}
}

// clientCascadeAbsentClientIsANoOp pins the half of the contract the
// endpoint depends on to stay linear: the library fires the cascade
// unconditionally once a substore implements it, and most deleted
// clients were never issued anything from most substores.
func clientCascadeAbsentClientIsANoOp(t *testing.T, f Factory) {
	b := f(t)
	handles := participating(t, b)
	ctx := context.Background()
	for name, revoke := range handles {
		if err := revoke.RevokeByClient(ctx, cascadeAbsentClient); err != nil {
			t.Errorf("%s.RevokeByClient(client with no records): want nil, got %v", name, err)
		}
	}
}
