package op

import (
	"context"
	"errors"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

// seedStaticClients reconciles the complete [WithStaticClients] set through
// one atomic [store.StaticClientReconciler] call. New invokes it after every
// other fallible construction step except the subject-mode marker commit,
// which runs last so a build that fails here never pins the store's subject
// mode. A failure in that commit can leave the seeded records behind; the
// reconcile is idempotent, so the next successful build accepts them.
func seedStaticClients(cfg *config) error {
	if len(cfg.staticClients) == 0 {
		return nil
	}
	reconciler, err := resolveStaticClientReconciler(cfg.store)
	if err != nil {
		return err
	}
	ctx := context.Background()
	desired := make([]*store.Client, 0, len(cfg.staticClients))
	for i := range cfg.staticClients {
		client, normalizeErr := normalizeStaticClientSeed(ctx, cfg, reconciler, cfg.staticClients[i])
		if normalizeErr != nil {
			return normalizeErr
		}
		desired = append(desired, client)
	}
	if err := reconciler.ReconcileStaticClients(ctx, desired); err != nil {
		return newConfigurationError("WithStaticClients: atomic reconciliation failed", err)
	}
	return nil
}

func normalizeStaticClientSeed(
	ctx context.Context,
	cfg *config,
	reconciler store.StaticClientReconciler,
	desired store.Client,
) (*store.Client, error) {
	existing, err := reconciler.GetClient(ctx, desired.ID)
	if errors.Is(err, store.ErrNotFound) {
		return &desired, nil
	}
	if err != nil {
		return nil, newConfigurationError("WithStaticClients: reading existing client "+desired.ID, err)
	}
	if existing.Source != "" && existing.Source != store.ClientSourceStatic {
		return nil, staticClientConflict(desired.ID, "is stored as a "+string(existing.Source)+
			" client, which a static seed never replaces; seed a different client ID")
	}
	if existing.Source == "" {
		desired.Source = ""
	}
	secrets := cfg.staticClientSecrets[desired.ID]
	if plaintext := secrets.current; plaintext != "" {
		if err := (&clientauth.Argon2id{}).Verify(plaintext, existing.SecretHash); err != nil {
			return nil, staticClientConflict(desired.ID, "has a stored secret hash that the seeded Secret does not verify against; "+
				"apply the new secret with op.SyncStaticClients before starting")
		}
		desired.SecretHash = existing.SecretHash
	}
	if plaintext := secrets.previous; plaintext != "" {
		if hash, found := verifiedPreviousHash(plaintext, existing); found {
			desired.PreviousSecretHash = hash
		}
	}
	if diff := store.StaticClientDifferences(existing, &desired); len(diff) > 0 {
		return nil, staticClientConflict(desired.ID, "differs from its static seed in "+strings.Join(diff, ", ")+
			"; apply the change with op.SyncStaticClients before starting")
	}
	return &desired, nil
}

// staticClientConflict reports a stored client the seed cannot take over;
// reason states the cause and the remedy.
func staticClientConflict(id, reason string) error {
	return newConfigurationError("WithStaticClients: stored client "+id, seedConflict(reason))
}

// seedConflict matches [store.ErrConflict] without printing the sentinel's
// text, which names a concurrent write rather than a diverged seed.
type seedConflict string

func (c seedConflict) Error() string { return string(c) }

func (seedConflict) Unwrap() error { return store.ErrConflict }

// staticClientReconcilerProvider is the conditional capability accessor used
// by composite stores whose concrete method set cannot honestly implement
// [store.StaticClientReconciler] for every possible Clients route.
type staticClientReconcilerProvider interface {
	StaticClientReconciler() (store.StaticClientReconciler, bool)
}

// clientRegistryProvider is the conditional capability accessor used by
// composite stores whose concrete method set cannot honestly implement
// [store.ClientRegistry] for every possible Clients route. A composite
// deliberately withholds the plain interface so a read-only backend is
// not mistaken for a writable registry; the accessor reports the
// capability of the backend actually routed for Clients.
type clientRegistryProvider interface {
	ClientRegistry() (store.ClientRegistry, bool)
}

// resolveClientRegistry returns the [store.ClientRegistry] view of s,
// consulting the direct interface first and the conditional accessor
// second. Both the construction-time validation
// ([config.validateRegistration]) and the router
// ([mountRegistrationEndpoint]) go through it so a store that only
// exposes the accessor — the documented hot/cold composite layout — can
// serve Dynamic Client Registration instead of failing op.New with an
// error that reads like a store defect.
func resolveClientRegistry(s store.Store) (store.ClientRegistry, bool) {
	if registry, ok := s.(store.ClientRegistry); ok {
		return registry, true
	}
	if provider, ok := s.(clientRegistryProvider); ok {
		return provider.ClientRegistry()
	}
	return nil, false
}

func resolveStaticClientReconciler(s store.Store) (store.StaticClientReconciler, error) {
	if reconciler, ok := s.(store.StaticClientReconciler); ok {
		return reconciler, nil
	}
	if provider, ok := s.(staticClientReconcilerProvider); ok {
		if reconciler, has := provider.StaticClientReconciler(); has {
			return reconciler, nil
		}
	}
	return nil, newConfigurationError("WithStaticClients requires a Store that implements "+
		"store.StaticClientReconciler for atomic startup seeding", nil)
}
