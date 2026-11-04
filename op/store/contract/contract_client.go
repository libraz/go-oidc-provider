package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// clientRegistryProvider and staticClientReconcilerProvider are the
// conditional capability accessors a composite store exposes instead of the
// plain interfaces: its concrete method set cannot honestly claim a
// capability that depends on which backend is routed for Clients.
//
// The harness has to probe them for the same reason the library does. A
// bare type assertion reports "not implemented" for a composite and skips
// the group, so a store shape the library fully supports would go through
// the contract suite untested — silently, since a skip reads as a pass.
type (
	clientRegistryProvider interface {
		ClientRegistry() (store.ClientRegistry, bool)
	}
	staticClientReconcilerProvider interface {
		StaticClientReconciler() (store.StaticClientReconciler, bool)
	}
)

// requireRegistry skips the current test when the backend provides no
// [store.ClientRegistry], through either the interface or the accessor.
func requireRegistry(t *testing.T, s store.Store) store.ClientRegistry {
	t.Helper()
	if registry, ok := s.(store.ClientRegistry); ok {
		return registry
	}
	if provider, ok := s.(clientRegistryProvider); ok {
		if registry, ok := provider.ClientRegistry(); ok {
			return registry
		}
	}
	t.Skipf("backend %T provides no store.ClientRegistry", s)
	return nil
}

// requireStaticClientReconciler skips the current test when the backend
// provides no [store.StaticClientReconciler], through either the interface
// or the accessor.
func requireStaticClientReconciler(t *testing.T, s store.Store) store.StaticClientReconciler {
	t.Helper()
	if reconciler, ok := s.(store.StaticClientReconciler); ok {
		return reconciler
	}
	if provider, ok := s.(staticClientReconcilerProvider); ok {
		if reconciler, ok := provider.StaticClientReconciler(); ok {
			return reconciler
		}
	}
	t.Skipf("backend %T provides no store.StaticClientReconciler", s)
	return nil
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
	{"UpdateUnchanged", clientUpdateUnchanged},
	{"PreviousSecretRoundTrip", clientPreviousSecretRoundTrip},
	{"TLSClientAuthMatcherRoundTrip", clientTLSClientAuthMatcherRoundTrip},
}

// clientTLSClientAuthMatcherRoundTrip pins that the five RFC 8705 §2.1.2
// tls_client_auth matcher fields survive a write and a read verbatim on
// every backend, and that an update can replace one with another.
func clientTLSClientAuthMatcherRoundTrip(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	ctx := context.Background()
	c := &store.Client{ //nolint:gosec // G101 false positive: "tls_client_auth" is an auth-method name, not a credential.
		ID:                      "mtls-pki",
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "tls_client_auth",
		TLSClientAuthSubjectDN:  "CN=mtls-pki,O=Example,C=JP",
		TLSClientAuthSANDNS:     "client.example.com",
		TLSClientAuthSANURI:     "spiffe://example.com/client",
		TLSClientAuthSANIP:      "2001:db8::1",
		TLSClientAuthSANEmail:   "client@example.com",
	}
	if err := registry.RegisterClient(ctx, c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	got, err := b.Store.Clients().GetClient(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	for _, field := range []struct{ name, got, want string }{
		{"TLSClientAuthSubjectDN", got.TLSClientAuthSubjectDN, c.TLSClientAuthSubjectDN},
		{"TLSClientAuthSANDNS", got.TLSClientAuthSANDNS, c.TLSClientAuthSANDNS},
		{"TLSClientAuthSANURI", got.TLSClientAuthSANURI, c.TLSClientAuthSANURI},
		{"TLSClientAuthSANIP", got.TLSClientAuthSANIP, c.TLSClientAuthSANIP},
		{"TLSClientAuthSANEmail", got.TLSClientAuthSANEmail, c.TLSClientAuthSANEmail},
	} {
		if field.got != field.want {
			t.Fatalf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}

	got.TLSClientAuthSubjectDN = ""
	got.TLSClientAuthSANDNS = "other.example.com"
	got.TLSClientAuthSANURI, got.TLSClientAuthSANIP, got.TLSClientAuthSANEmail = "", "", ""
	if err := registry.UpdateClient(ctx, got); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	updated, err := b.Store.Clients().GetClient(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetClient after update: %v", err)
	}
	if updated.TLSClientAuthSubjectDN != "" || updated.TLSClientAuthSANDNS != "other.example.com" ||
		updated.TLSClientAuthSANURI != "" || updated.TLSClientAuthSANIP != "" || updated.TLSClientAuthSANEmail != "" {
		t.Fatalf("matchers after update = %q/%q/%q/%q/%q, want only SANDNS other.example.com",
			updated.TLSClientAuthSubjectDN, updated.TLSClientAuthSANDNS, updated.TLSClientAuthSANURI,
			updated.TLSClientAuthSANIP, updated.TLSClientAuthSANEmail)
	}
}

// clientPreviousSecretRoundTrip pins that the rotation overlap survives a
// write and a read on every backend: the previous hash verbatim and its
// expiry at second precision, and that an update can clear both.
func clientPreviousSecretRoundTrip(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	ctx := context.Background()
	expires := time.Date(2090, 1, 2, 3, 4, 5, 0, time.UTC)
	c := &store.Client{
		ID:                      "rotating",
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              "current-hash",
		PreviousSecretHash:      "previous-hash",
		PreviousSecretExpiresAt: expires,
	}
	if err := registry.RegisterClient(ctx, c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	got, err := b.Store.Clients().GetClient(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.PreviousSecretHash != "previous-hash" {
		t.Fatalf("PreviousSecretHash = %q, want %q", got.PreviousSecretHash, "previous-hash")
	}
	if got.PreviousSecretExpiresAt.Unix() != expires.Unix() {
		t.Fatalf("PreviousSecretExpiresAt = %v, want %v", got.PreviousSecretExpiresAt, expires)
	}

	got.PreviousSecretHash = ""
	got.PreviousSecretExpiresAt = time.Time{}
	if err := registry.UpdateClient(ctx, got); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	cleared, err := b.Store.Clients().GetClient(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetClient after clear: %v", err)
	}
	if cleared.PreviousSecretHash != "" || !cleared.PreviousSecretExpiresAt.IsZero() {
		t.Fatalf("previous secret not cleared: hash=%q expires=%v", cleared.PreviousSecretHash, cleared.PreviousSecretExpiresAt)
	}
}

// clientUpdateUnchanged pins that ErrNotFound reports absence and
// nothing else. Re-submitting a client's current metadata is the normal
// behaviour of a configuration reconcile loop, and a backend that reads
// its verdict off an affected-row count sees zero rows changed for it —
// which reaches the embedder as a 401 from PUT /register/{client_id} on
// that backend alone, while another engine answers 200 for the same
// request.
func clientUpdateUnchanged(t *testing.T, f Factory) {
	b := f(t)
	registry := requireRegistry(t, b.Store)
	ctx := context.Background()
	c := &store.Client{
		ID:           "upd-noop",
		RedirectURIs: []string{"https://rp.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	}
	if err := registry.RegisterClient(ctx, c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	stored, err := b.Store.Clients().GetClient(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := registry.UpdateClient(ctx, stored); err != nil {
			t.Fatalf("UpdateClient with unchanged metadata (attempt %d): %v", attempt, err)
		}
	}
	if _, err := b.Store.Clients().GetClient(ctx, c.ID); err != nil {
		t.Fatalf("GetClient after unchanged updates: %v", err)
	}
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

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var staticClientReconcilerCases = []subtest{
	{"EquivalentIsIdempotent", staticClientReconcileEquivalent},
	{"ConflictIsAtomic", staticClientReconcileConflictIsAtomic},
	{"ConcurrentEquivalentReconcileSucceeds", staticClientReconcileConcurrent},
}

func staticClientReconcileEquivalent(t *testing.T, f Factory) {
	b := f(t)
	reconciler := requireStaticClientReconciler(t, b.Store)
	ctx := context.Background()
	initial := &store.Client{
		ID:           "static-idempotent",
		PublicClient: true,
		Source:       store.ClientSourceStatic,
	}
	if err := reconciler.ReconcileStaticClients(ctx, []*store.Client{initial}); err != nil {
		t.Fatalf("first ReconcileStaticClients: %v", err)
	}
	equivalent := &store.Client{
		ID:           initial.ID,
		Scopes:       []string{},
		PublicClient: true,
	}
	if err := reconciler.ReconcileStaticClients(ctx, []*store.Client{equivalent}); err != nil {
		t.Fatalf("equivalent ReconcileStaticClients: %v", err)
	}
	got, err := b.Store.Clients().GetClient(ctx, initial.ID)
	if err != nil {
		t.Fatalf("GetClient after equivalent reconcile: %v", err)
	}
	if !store.StaticClientEquivalent(got, initial) {
		t.Fatalf("equivalent reconcile changed client: got %+v want %+v", got, initial)
	}
}

func staticClientReconcileConflictIsAtomic(t *testing.T, f Factory) {
	b := f(t)
	reconciler := requireStaticClientReconciler(t, b.Store)
	ctx := context.Background()
	existing := &store.Client{
		ID:           "static-existing",
		Scopes:       []string{"openid"},
		PublicClient: true,
		Source:       store.ClientSourceStatic,
	}
	if err := reconciler.ReconcileStaticClients(ctx, []*store.Client{existing}); err != nil {
		t.Fatalf("seed existing client: %v", err)
	}
	err := reconciler.ReconcileStaticClients(ctx, []*store.Client{
		{
			ID:           "static-missing",
			PublicClient: true,
			Source:       store.ClientSourceStatic,
		},
		{
			ID:           existing.ID,
			Scopes:       []string{"openid", "profile"},
			PublicClient: true,
			Source:       store.ClientSourceStatic,
		},
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("conflicting ReconcileStaticClients: want ErrConflict, got %v", err)
	}
	if _, err := b.Store.Clients().GetClient(ctx, "static-missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("batch inserted preceding client despite conflict: want ErrNotFound, got %v", err)
	}
	got, err := b.Store.Clients().GetClient(ctx, existing.ID)
	if err != nil {
		t.Fatalf("GetClient existing after conflict: %v", err)
	}
	if !store.StaticClientEquivalent(got, existing) {
		t.Fatalf("conflicting reconcile changed existing client: got %+v want %+v", got, existing)
	}
}

// staticClientReconcileConcurrent pins the replica-startup case: several
// processes reconciling the same set at once all succeed and leave
// exactly that set. A lost insert race must be re-evaluated against the
// winner's record, not reported as a conflict.
func staticClientReconcileConcurrent(t *testing.T, f Factory) {
	b := f(t)
	reconciler := requireStaticClientReconciler(t, b.Store)
	ctx := context.Background()
	set := func() []*store.Client {
		return []*store.Client{
			{ID: "static-race-a", Scopes: []string{"openid"}, PublicClient: true, Source: store.ClientSourceStatic},
			{ID: "static-race-b", Scopes: []string{"openid", "profile"}, PublicClient: true, Source: store.ClientSourceStatic},
		}
	}
	errs := race(
		func() { _, _ = b.Store.Clients().GetClient(ctx, "static-race-warmup") },
		everyRacer(func(int) error { return reconciler.ReconcileStaticClients(ctx, set()) })...,
	)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent ReconcileStaticClients %d with an equivalent set: %v", i, err)
		}
	}
	for _, want := range set() {
		got, err := b.Store.Clients().GetClient(ctx, want.ID)
		if err != nil {
			t.Fatalf("GetClient %s after concurrent reconcile: %v", want.ID, err)
		}
		if !store.StaticClientEquivalent(got, want) {
			t.Fatalf("concurrent reconcile left %s as %+v, want %+v", want.ID, got, want)
		}
	}
}
