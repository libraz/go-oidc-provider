// Package contract provides a reusable test harness that exercises every
// guarantee declared on the substore interfaces in
// [github.com/libraz/go-oidc-provider/op/store]. Backend implementations call
// [Run] from a black-box test and the harness reports any deviation from the
// contract via the standard [testing.T] surface.
//
// The harness is intentionally pure stdlib: it depends on [testing] and the
// store package itself, nothing else. Backend authors are expected to seed
// records with timestamps drawn from [Reference] or whatever clock their
// adapter exposes; the harness deliberately avoids real-time waits so the
// suite is deterministic and fast.
package contract

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Reference is the fixed wall-clock instant used by the harness to populate
// CreatedAt / UpdatedAt / ExpiresAt fields. Backends whose own clock differs
// (e.g. a fake clock injected at construction time) must report it through
// the [Factory] result so the harness can pin records against the same
// reference.
//
// The constant is intentionally exported so adapter test files can construct
// records that round-trip through their backend.
//
//nolint:gochecknoglobals // reference time used by every contract test.
var Reference = time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

// Factory builds a fresh, isolated [store.Store] for a single sub-test. The
// harness invokes Factory once per sub-test; backends that need cleanup
// SHOULD register it via [testing.T.Cleanup] inside the factory.
type Factory func(t *testing.T) Backend

// Backend bundles a freshly constructed [store.Store] together with the
// wall-clock instant the backend treats as "now". The harness uses Now to
// build timestamps that survive expiry checks deterministically.
type Backend struct {
	// Store is the substore aggregate under test.
	Store store.Store

	// Now is the wall-clock the backend will report from its internal
	// clock. The harness uses Now+1h for ExpiresAt fields it wants alive
	// and Now-1h for fields it wants pre-expired.
	Now func() time.Time

	// Advance moves an injected backend clock forward. Backends with a
	// mutable test clock provide it so contracts can validate transitions
	// from live to expired without sleeping. Nil skips only those
	// transition-specific assertions.
	Advance func(time.Duration)

	// SeedUser installs a directory entry the password ceremony can
	// resolve against, together with the username it authenticates under
	// and its encoded password hash.
	//
	// It exists because [store.UserStore] is read-only by design — the
	// library never enrols a user — so the harness has no in-contract way
	// to arrange one. Backends that can populate their directory supply
	// this; a nil SeedUser skips the [store.UserPasswordStore] sub-tests
	// rather than failing them, so a passkey-only backend that
	// implements no password lookup at all stays green.
	SeedUser func(t *testing.T, u *store.User, username string, passwordHash []byte)
}

// runGroups is every group [Run] drives, in order.
//
//nolint:gochecknoglobals // group table; declared once so [Run] and the coverage check can iterate.
var runGroups = []struct {
	name  string
	cases []subtest
}{
	{"ClientStore", clientStoreCases},
	{"ClientRegistry", clientRegistryCases},
	{"StaticClientReconciler", staticClientReconcilerCases},
	{"AuthorizationCodeStore", authCodeCases},
	{"RefreshTokenStore", refreshCases},
	{"GrantStore", grantCases},
	{"SessionStore", sessionCases},
	{"PushedAuthRequestStore", parCases},
	{"InteractionStore", interactionCases},
	{"ConsumedJTIStore", jtiCases},
	{"InitialAccessTokenStore", iatCases},
	{"RegistrationAccessTokenStore", ratCases},
	{"AccessTokenRegistry", accessTokenRegistryCases},
	{"OpaqueAccessTokenStore", opaqueAccessTokenCases},
	{"GrantRevocationStore", grantRevocationCases},
	{"ClientDeletionCascade", clientCascadeCases},
	{"DeviceCodeStore", deviceCodeCases},
	{"CIBARequestStore", cibaRequestCases},
	{"MetadataStore", metadataStoreCases},
	{"UserStore", userStoreCases},
	{"ConsumeStates", consumeCases},
	{"Transactional", transactionalCases},
	{"Concurrency", concurrencyCases},
	{"SubstoreNamespace", namespaceCases},
}

// Run drives every contract sub-test against the backend produced by f. Each
// sub-test invokes f independently so backends remain isolated, and every
// sub-test calls [testing.T.Parallel] for fast aggregate runs.
func Run(t *testing.T, f Factory) {
	t.Helper()
	for _, g := range runGroups {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			runGroup(t, f, g.cases)
		})
	}
}

// RunInteractions runs only the InteractionStore contract subgroup
// against the supplied factory. Partial-coverage backends — for
// example, Redis adapters that host only InteractionStore and
// ConsumedJTIStore — call this in lieu of [Run] so the harness does
// not exercise out-of-scope substores.
func RunInteractions(t *testing.T, f Factory) {
	t.Helper()
	t.Run("InteractionStore", func(t *testing.T) {
		t.Parallel()
		runGroup(t, f, interactionCases)
	})
}

// RunConsumedJTIs runs only the ConsumedJTIStore contract subgroup
// against the supplied factory. See [RunInteractions] for the
// partial-coverage rationale.
func RunConsumedJTIs(t *testing.T, f Factory) {
	t.Helper()
	t.Run("ConsumedJTIStore", func(t *testing.T) {
		t.Parallel()
		runGroup(t, f, jtiCases)
	})
}

// RunSessions runs only the SessionStore contract subgroup against the
// supplied factory. Backends that host SessionStore alongside other
// volatile substores (Redis / Memcached) call this in lieu of [Run] so
// the harness does not exercise out-of-scope substores. Sessions are
// declared as a routable-on-its-own substore so partial-coverage
// backends are a first-class case.
func RunSessions(t *testing.T, f Factory) {
	t.Helper()
	t.Run("SessionStore", func(t *testing.T) {
		t.Parallel()
		runGroup(t, f, sessionCases)
	})
}

// RunSubstoreNamespace runs only the substore-namespace subgroup against
// the supplied factory. Partial-coverage backends call it in lieu of
// [Run]: the cases skip the substores the backend returns nil for, so a
// volatile cache hosting sessions, interactions and consumed JTIs still
// gets its keyspace disjointness checked across the three it does host.
func RunSubstoreNamespace(t *testing.T, f Factory) {
	t.Helper()
	t.Run("SubstoreNamespace", func(t *testing.T) {
		t.Parallel()
		runGroup(t, f, namespaceCases)
	})
}

// RunMetadata runs only the MetadataStore contract subgroup against the
// supplied factory. See [RunInteractions] for the partial-coverage
// rationale.
func RunMetadata(t *testing.T, f Factory) {
	t.Helper()
	t.Run("MetadataStore", func(t *testing.T) {
		t.Parallel()
		runGroup(t, f, metadataStoreCases)
	})
}

// subtest captures one named sub-test in the contract suite.
type subtest struct {
	name string
	fn   func(*testing.T, Factory)
}

// factorCase is [subtest] for the standalone substores whose Run* entry
// point takes its own backend type B instead of a [Factory].
type factorCase[B any] struct {
	name string
	run  func(*testing.T, B)
}

func runGroup(t *testing.T, f Factory, cases []subtest) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.fn(t, f)
		})
	}
}

// requireTransactional skips the current test when the backend does not
// implement [store.Transactional].
func requireTransactional(t *testing.T, s store.Store) store.Transactional {
	t.Helper()
	tx, ok := s.(store.Transactional)
	if !ok {
		t.Skipf("backend %T does not implement store.Transactional", s)
	}
	return tx
}
