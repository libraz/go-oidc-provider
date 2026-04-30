package composite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fakeClock returns a fixed instant so the inmem store's expiry checks remain
// deterministic during validation tests.
type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

func newInmem(t *testing.T) *inmem.Store {
	t.Helper()
	return inmem.New(inmem.WithClock(fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}))
}

// readOnlyStore wraps a [store.Store] and intentionally does NOT implement
// [store.Transactional]. The test factory uses it to simulate a backend that
// can serve clients or interactions but that cannot host the transactional
// cluster.
type readOnlyStore struct {
	store.Store
}

// Reaffirm that the wrapper hides Transactional even when the inner store
// implements it: the embedded type's BeginTx does NOT promote because we
// embed via the interface, not the concrete type. The constructor below adds
// no methods, so the Transactional assertion fails by design.
func newReadOnlyStore(t *testing.T) *readOnlyStore {
	t.Helper()
	return &readOnlyStore{Store: newInmem(t)}
}

func TestNew_AllDefault_OK(t *testing.T) {
	t.Parallel()
	s, err := composite.New(composite.WithDefault(newInmem(t)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil store")
	}
	// Sanity-check that the result satisfies store.Store.
	var _ store.Store = s
	// And store.Transactional, since the inmem default implements it.
	if _, ok := any(s).(store.Transactional); !ok {
		t.Fatal("composite must implement store.Transactional when default is transactional")
	}
}

func TestNew_TxClusterSplit(t *testing.T) {
	t.Parallel()
	persistent := newInmem(t)
	other := newInmem(t)

	_, err := composite.New(
		composite.WithDefault(persistent),
		composite.With(composite.RefreshTokens, other),
	)
	if !errors.Is(err, composite.ErrTxClusterSplit) {
		t.Fatalf("split tx cluster: want ErrTxClusterSplit, got %v", err)
	}
	// The diagnostic message must name the conflicting kinds and backend
	// types so operators can find the misconfiguration in logs.
	if msg := err.Error(); msg == "" {
		t.Fatal("error must carry a diagnostic message")
	}
}

func TestNew_TxAnchorNotTransactional(t *testing.T) {
	t.Parallel()
	// Build a backend that satisfies store.Store but not store.Transactional.
	nonTx := newReadOnlyStore(t)
	if _, ok := any(nonTx).(store.Transactional); ok {
		t.Fatal("test fixture incorrectly implements Transactional")
	}

	_, err := composite.New(composite.WithDefault(nonTx))
	if !errors.Is(err, composite.ErrTxAnchorNotTx) {
		t.Fatalf("non-tx anchor: want ErrTxAnchorNotTx, got %v", err)
	}
}

func TestNew_KindNotRouted(t *testing.T) {
	t.Parallel()
	persistent := newInmem(t)

	// No WithDefault, and we only route the Tx-cluster Kinds plus Clients.
	// ConsumedJTIs and Interactions are deliberately unrouted.
	_, err := composite.New(
		composite.With(composite.Clients, persistent),
		composite.With(composite.AuthorizationCodes, persistent),
		composite.With(composite.RefreshTokens, persistent),
		composite.With(composite.Grants, persistent),
		composite.With(composite.Sessions, persistent),
		composite.With(composite.PushedAuthRequests, persistent),
	)
	if !errors.Is(err, composite.ErrKindNotRouted) {
		t.Fatalf("missing route: want ErrKindNotRouted, got %v", err)
	}
}

func TestNew_DefaultPlusOverride_OK(t *testing.T) {
	t.Parallel()
	persistent := newInmem(t)
	ephemeral := newInmem(t)

	// All Tx-cluster Kinds resolve to persistent (via the default) and
	// the non-transactional Kinds resolve to ephemeral.
	s, err := composite.New(
		composite.WithDefault(persistent),
		composite.With(composite.Interactions, ephemeral),
		composite.With(composite.ConsumedJTIs, ephemeral),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Sanity: BeginTx works (anchor is persistent).
	tx, err := s.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
}

func TestNew_ClientsOverrideToReadOnlyBackend_OK(t *testing.T) {
	t.Parallel()
	persistent := newInmem(t)
	clientsOnly := newReadOnlyStore(t)

	// Default routes everything (including the Tx cluster) to persistent.
	// Clients is overridden to a backend that does NOT implement
	// Transactional. That is acceptable because Clients is outside the
	// transactional cluster: validation must succeed.
	s, err := composite.New(
		composite.WithDefault(persistent),
		composite.With(composite.Clients, clientsOnly),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The Clients-routed backend does not implement ClientRegistry, so the
	// composite must report the capability as absent rather than guessing.
	if _, ok := s.ClientRegistry(); ok {
		t.Fatal("ClientRegistry must be absent when the Clients backend lacks it")
	}
}

func TestStore_ClientRegistry_PresentWhenSupported(t *testing.T) {
	t.Parallel()
	persistent := newInmem(t) // inmem.Store implements store.ClientRegistry
	s, err := composite.New(composite.WithDefault(persistent))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	reg, ok := s.ClientRegistry()
	if !ok || reg == nil {
		t.Fatal("ClientRegistry must be present when Clients backend supports it")
	}
}

func TestStore_TypeAssertionToClientRegistryNotSupported(t *testing.T) {
	t.Parallel()
	// The composite must NOT satisfy store.ClientRegistry directly via
	// type assertion: callers go through Store.ClientRegistry().
	persistent := newInmem(t)
	s, err := composite.New(composite.WithDefault(persistent))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := any(s).(store.ClientRegistry); ok {
		t.Fatal("*Store must not satisfy store.ClientRegistry via type assertion")
	}
}

func TestStore_RoutesPerKind(t *testing.T) {
	t.Parallel()
	// Verify that each Kind returns a substore from the routed backend by
	// observing visible side effects on each backend independently.
	persistent := newInmem(t)
	ephemeral := newInmem(t)

	s, err := composite.New(
		composite.WithDefault(persistent),
		composite.With(composite.Interactions, ephemeral),
		composite.With(composite.ConsumedJTIs, ephemeral),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	// Save an interaction via the composite and read it back from the
	// ephemeral backend directly. If the composite mis-routed the call,
	// ephemeral would not contain the record.
	rec := &store.Interaction{
		ID: "i-1", ClientID: "c", Step: "consent", RawState: []byte("{}"),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.Interactions().Save(ctx, rec); err != nil {
		t.Fatalf("Save interaction: %v", err)
	}
	if _, err := ephemeral.Interactions().Find(ctx, "i-1"); err != nil {
		t.Fatalf("ephemeral.Find interaction: %v", err)
	}
	if _, err := persistent.Interactions().Find(ctx, "i-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("persistent must not see ephemeral interaction: %v", err)
	}
}

func TestKind_String(t *testing.T) {
	t.Parallel()
	cases := []struct {
		k    composite.Kind
		want string
	}{
		{composite.Clients, "Clients"},
		{composite.AuthorizationCodes, "AuthorizationCodes"},
		{composite.RefreshTokens, "RefreshTokens"},
		{composite.Grants, "Grants"},
		{composite.Sessions, "Sessions"},
		{composite.PushedAuthRequests, "PushedAuthRequests"},
		{composite.Interactions, "Interactions"},
		{composite.ConsumedJTIs, "ConsumedJTIs"},
		{composite.Users, "Users"},
		{composite.InitialAccessTokens, "InitialAccessTokens"},
		{composite.RegistrationAccessTokens, "RegistrationAccessTokens"},
		{composite.AccessTokens, "AccessTokens"},
		{composite.OpaqueAccessTokens, "OpaqueAccessTokens"},
		{composite.Kind(99), "Kind(99)"},
	}
	for _, tc := range cases {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("Kind(%d).String() = %q, want %q", int(tc.k), got, tc.want)
		}
	}
}

func TestNew_NilOptionsTolerated(t *testing.T) {
	t.Parallel()
	// nil Options must be ignored so callers can compose Option slices
	// conditionally without sprinkling nil checks at the call site.
	s, err := composite.New(nil, composite.WithDefault(newInmem(t)), nil)
	if err != nil {
		t.Fatalf("New with nil options: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil with nil options")
	}
}

func TestNew_NilStoreOptionsTolerated(t *testing.T) {
	t.Parallel()
	// Both With and WithDefault are no-ops when the supplied store is nil.
	// The result is the same as if the option had been omitted: validation
	// must still fire when a Kind ends up unrouted.
	_, err := composite.New(
		composite.WithDefault(nil),
		composite.With(composite.Clients, nil),
	)
	if !errors.Is(err, composite.ErrKindNotRouted) {
		t.Fatalf("nil store options: want ErrKindNotRouted, got %v", err)
	}
}

func TestNew_PerKindOverridesDefault(t *testing.T) {
	t.Parallel()
	// When both With and WithDefault are supplied for the same Kind, the
	// per-Kind override wins. Verify by routing Interactions to a backend
	// that we can observe independently of the default.
	persistent := newInmem(t)
	override := newInmem(t)

	s, err := composite.New(
		composite.WithDefault(persistent),
		composite.With(composite.Interactions, override),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	rec := &store.Interaction{
		ID: "i-x", ClientID: "c", Step: "consent",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.Interactions().Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := override.Interactions().Find(ctx, "i-x"); err != nil {
		t.Fatalf("override.Find: %v", err)
	}
}

func TestNew_LastWithWins(t *testing.T) {
	t.Parallel()
	first := newInmem(t)
	second := newInmem(t)

	s, err := composite.New(
		composite.WithDefault(newInmem(t)),
		composite.With(composite.Interactions, first),
		composite.With(composite.Interactions, second),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	rec := &store.Interaction{
		ID: "i-last", ClientID: "c", Step: "consent",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.Interactions().Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := second.Interactions().Find(ctx, "i-last"); err != nil {
		t.Fatalf("second.Find: %v", err)
	}
	if _, err := first.Interactions().Find(ctx, "i-last"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("first must not see record after override: %v", err)
	}
}

func TestStore_BeginTxPropagatesAnchorError(t *testing.T) {
	t.Parallel()
	persistent := newInmem(t)
	s, err := composite.New(composite.WithDefault(persistent))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.BeginTx(ctx); err == nil {
		t.Fatal("BeginTx with cancelled ctx must propagate the anchor error")
	}
}
