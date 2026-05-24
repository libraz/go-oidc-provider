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
	"context"
	"errors"
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
}

// Run drives every contract sub-test against the backend produced by f. Each
// sub-test invokes f independently so backends remain isolated, and every
// sub-test calls [testing.T.Parallel] for fast aggregate runs.
func Run(t *testing.T, f Factory) {
	t.Helper()

	groups := []struct {
		name  string
		cases []subtest
	}{
		{"ClientStore", clientStoreCases},
		{"ClientRegistry", clientRegistryCases},
		{"AuthorizationCodeStore", authCodeCases},
		{"RefreshTokenStore", refreshCases},
		{"GrantStore", grantCases},
		{"SessionStore", sessionCases},
		{"PushedAuthRequestStore", parCases},
		{"InteractionStore", interactionCases},
		{"ConsumedJTIStore", jtiCases},
		{"InitialAccessTokenStore", iatCases},
		{"RegistrationAccessTokenStore", ratCases},
		{"OpaqueAccessTokenStore", opaqueAccessTokenCases},
		{"GrantRevocationStore", grantRevocationCases},
		{"DeviceCodeStore", deviceCodeCases},
		{"CIBARequestStore", cibaRequestCases},
		{"Transactional", transactionalCases},
	}

	for _, g := range groups {
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

// subtest captures one named sub-test in the contract suite.
type subtest struct {
	name string
	fn   func(*testing.T, Factory)
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

// requireRegistry skips the current test when the backend does not implement
// [store.ClientRegistry].
func requireRegistry(t *testing.T, s store.Store) store.ClientRegistry {
	t.Helper()
	registry, ok := s.(store.ClientRegistry)
	if !ok {
		t.Skipf("backend %T does not implement store.ClientRegistry", s)
	}
	return registry
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

// --- ClientStore -------------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var clientStoreCases = []subtest{
	{"RoundTrip", clientRoundTrip},
	{"Missing", clientMissing},
}

func clientRoundTrip(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	c := &store.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://rp.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	}
	ctx := context.Background()
	if err := registry.RegisterClient(ctx, c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	got, err := b.Store.Clients().GetClient(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ID != c.ID || len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://rp.example.com/cb" {
		t.Fatalf("unexpected client: %+v", got)
	}
}

func clientMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.Clients().GetClient(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetClient missing: want ErrNotFound, got %v", err)
	}
}

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var clientRegistryCases = []subtest{
	{"RegisterDuplicate", clientRegisterDuplicate},
	{"UpdateMissing", clientUpdateMissing},
	{"DeleteMissing", clientDeleteMissing},
	{"UpdateRoundTrip", clientUpdateRoundTrip},
}

func clientRegisterDuplicate(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	ctx := context.Background()
	c := &store.Client{ID: "dup"}
	if err := registry.RegisterClient(ctx, c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	err := registry.RegisterClient(ctx, c)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Register: want ErrAlreadyExists, got %v", err)
	}
}

func clientUpdateMissing(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	err := registry.UpdateClient(context.Background(), &store.Client{ID: "absent"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateClient missing: want ErrNotFound, got %v", err)
	}
}

func clientDeleteMissing(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	err := registry.DeleteClient(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteClient missing: want ErrNotFound, got %v", err)
	}
}

func clientUpdateRoundTrip(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	ctx := context.Background()
	original := &store.Client{ID: "upd", Scopes: []string{"openid"}}
	if err := registry.RegisterClient(ctx, original); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	updated := &store.Client{ID: "upd", Scopes: []string{"openid", "email"}}
	if err := registry.UpdateClient(ctx, updated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	got, err := b.Store.Clients().GetClient(ctx, "upd")
	if err != nil {
		t.Fatalf("GetClient after update: %v", err)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("UpdateClient did not persist new scopes: %+v", got)
	}
}

// --- AuthorizationCodeStore --------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var authCodeCases = []subtest{
	{"SaveFind", authCodeSaveFind},
	{"ConsumeOnce", authCodeConsumeOnce},
	{"FindMissing", authCodeFindMissing},
	{"ConsumeMissing", authCodeConsumeMissing},
	{"Expired", authCodeExpired},
	{"DuplicateSave", authCodeDuplicateSave},
}

func authCodeSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-1")
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.AuthorizationCodes().Find(ctx, "ac-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "ac-1" || got.ConsumedAt != nil {
		t.Fatalf("unexpected code: %+v", got)
	}
}

func authCodeConsumeOnce(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-2")
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	first, err := b.Store.AuthorizationCodes().Consume(ctx, "ac-2")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if first.ConsumedAt == nil {
		t.Fatal("first Consume returned record with nil ConsumedAt")
	}
	_, err = b.Store.AuthorizationCodes().Consume(ctx, "ac-2")
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
	got, err := b.Store.AuthorizationCodes().Find(ctx, "ac-2")
	if err != nil {
		t.Fatalf("Find after consume: %v", err)
	}
	if got.ConsumedAt == nil {
		t.Fatalf("Find after consume returned ConsumedAt=nil: %+v", got)
	}
}

func authCodeFindMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.AuthorizationCodes().Find(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find missing: want ErrNotFound, got %v", err)
	}
}

func authCodeConsumeMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.AuthorizationCodes().Consume(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume missing: want ErrNotFound, got %v", err)
	}
}

func authCodeExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-exp")
	code.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.AuthorizationCodes().Find(ctx, "ac-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
	if _, err := b.Store.AuthorizationCodes().Consume(ctx, "ac-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume expired: want ErrNotFound, got %v", err)
	}
}

func authCodeDuplicateSave(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-dup")
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	err := b.Store.AuthorizationCodes().Save(ctx, code)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Save: want ErrAlreadyExists, got %v", err)
	}
}

// --- RefreshTokenStore -------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var refreshCases = []subtest{
	{"SaveFindConsume", refreshSaveFindConsume},
	{"RevokeChain", refreshRevokeChain},
	{"RevokeChainMissing", refreshRevokeChainMissing},
}

func refreshSaveFindConsume(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	rt := newRefresh(b.Now(), "rt-1", nil)
	if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.RefreshTokens().Find(ctx, "rt-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "rt-1" {
		t.Fatalf("unexpected token: %+v", got)
	}
	consumed, err := b.Store.RefreshTokens().Consume(ctx, "rt-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("Consume returned ConsumedAt=nil")
	}
	_, err = b.Store.RefreshTokens().Consume(ctx, "rt-1")
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

func refreshRevokeChain(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	root := newRefresh(b.Now(), "root", nil)
	mid := newRefresh(b.Now(), "mid", strPtr("root"))
	leaf := newRefresh(b.Now(), "leaf", strPtr("mid"))
	other := newRefresh(b.Now(), "other", nil)
	for _, rt := range []*store.RefreshToken{root, mid, leaf, other} {
		if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
			t.Fatalf("Save %s: %v", rt.ID, err)
		}
	}
	if err := b.Store.RefreshTokens().RevokeChain(ctx, "root"); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	for _, id := range []string{"root", "mid", "leaf"} {
		assertRevoked(t, b.Store, id)
	}
	got, err := b.Store.RefreshTokens().Find(ctx, "other")
	if err != nil {
		t.Fatalf("Find other: %v", err)
	}
	if got.ConsumedAt != nil {
		t.Fatalf("unrelated token revoked: %+v", got)
	}
}

func refreshRevokeChainMissing(t *testing.T, f Factory) {
	b := f(t)
	err := b.Store.RefreshTokens().RevokeChain(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeChain missing: want ErrNotFound, got %v", err)
	}
}

// assertRevoked asserts that a refresh token is either absent or has
// ConsumedAt set. The contract permits backends to delete or to mark.
func assertRevoked(t *testing.T, s store.Store, id string) {
	t.Helper()
	got, err := s.RefreshTokens().Find(context.Background(), id)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatalf("Find %s: %v", id, err)
	}
	if got.ConsumedAt == nil {
		t.Fatalf("token %s expected revoked, got ConsumedAt=nil", id)
	}
}

// --- GrantStore --------------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var grantCases = []subtest{
	{"SaveFind", grantSaveFind},
	{"FindMissing", grantFindMissing},
	{"FindBySubjectClient", grantFindBySubjectClient},
	{"FindBySubjectClientMissing", grantFindBySubjectClientMissing},
	{"ListBySubject", grantListBySubject},
	{"ListBySubjectEmpty", grantListBySubjectEmpty},
	{"Delete", grantDelete},
}

func grantSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	g := newGrant(b.Now(), "g-1", "sub-1", "client-1")
	if err := b.Store.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.Grants().Find(ctx, "g-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.Subject != "sub-1" || got.ClientID != "client-1" {
		t.Fatalf("unexpected grant: %+v", got)
	}
}

func grantFindMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.Grants().Find(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find missing: want ErrNotFound, got %v", err)
	}
}

func grantFindBySubjectClient(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	older := newGrant(b.Now().Add(-2*time.Hour), "g-old", "sub", "client")
	older.UpdatedAt = b.Now().Add(-2 * time.Hour)
	newer := newGrant(b.Now(), "g-new", "sub", "client")
	newer.UpdatedAt = b.Now()
	for _, g := range []*store.Grant{older, newer} {
		if err := b.Store.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}
	got, err := b.Store.Grants().FindBySubjectClient(ctx, "sub", "client")
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	if got.ID != "g-new" {
		t.Fatalf("FindBySubjectClient returned older grant: %+v", got)
	}
}

func grantFindBySubjectClientMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.Grants().FindBySubjectClient(context.Background(), "absent", "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindBySubjectClient missing: want ErrNotFound, got %v", err)
	}
}

func grantListBySubject(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	rows := []*store.Grant{
		newGrant(b.Now(), "g-a", "sub", "client-a"),
		newGrant(b.Now(), "g-b", "sub", "client-b"),
		newGrant(b.Now(), "g-other", "other-sub", "client-a"),
	}
	for _, g := range rows {
		if err := b.Store.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}
	got, err := b.Store.Grants().ListBySubject(ctx, "sub")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	clients := make(map[string]struct{}, len(got))
	for _, g := range got {
		if g.Subject != "sub" {
			t.Fatalf("ListBySubject returned wrong subject: %+v", g)
		}
		clients[g.ClientID] = struct{}{}
	}
	if len(clients) != 2 {
		t.Fatalf("ListBySubject got %d distinct clients, want 2: %+v", len(clients), got)
	}
	if _, ok := clients["client-a"]; !ok {
		t.Fatalf("ListBySubject missing client-a")
	}
	if _, ok := clients["client-b"]; !ok {
		t.Fatalf("ListBySubject missing client-b")
	}
}

func grantListBySubjectEmpty(t *testing.T, f Factory) {
	b := f(t)
	got, err := b.Store.Grants().ListBySubject(context.Background(), "absent")
	if err != nil {
		t.Fatalf("ListBySubject empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListBySubject empty: want 0 entries, got %d", len(got))
	}
}

func grantDelete(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	g := newGrant(b.Now(), "g-del", "sub", "client")
	if err := b.Store.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := b.Store.Grants().Delete(ctx, "g-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	err := b.Store.Grants().Delete(ctx, "g-del")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("repeat Delete: want ErrNotFound, got %v", err)
	}
}
