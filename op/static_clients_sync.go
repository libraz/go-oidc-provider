package op

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

// StaticClientSyncAction names what [SyncStaticClients] did for one seed.
//
// Stable since v1.5.
type StaticClientSyncAction string

const (
	// StaticClientInserted means no client with the seed's ID existed and
	// the record was registered.
	//
	// Stable since v1.5.
	StaticClientInserted StaticClientSyncAction = "inserted"

	// StaticClientUpdated means a static client with the seed's ID existed
	// with different metadata or a different secret, and was replaced.
	//
	// Stable since v1.5.
	StaticClientUpdated StaticClientSyncAction = "updated"

	// StaticClientUnchanged means the stored record already matched the
	// seed and nothing was written.
	//
	// Stable since v1.5.
	StaticClientUnchanged StaticClientSyncAction = "unchanged"
)

// StaticClientSyncResult reports the outcome of [SyncStaticClients] for
// one seed. Results come back in seed order.
//
// Stable since v1.5.
type StaticClientSyncResult struct {
	// ID is the client_id of the seed.
	ID string

	// Action is what the sync did for that client.
	Action StaticClientSyncAction
}

// SyncStaticClients brings the static clients in st in line with seeds:
// a missing client is inserted, a static client whose metadata or secret
// differs is updated, and an identical one is left alone. It is the
// explicit administration path for changing a static client that
// [WithStaticClients] would otherwise refuse to overwrite at startup.
//
// Run it from a deploy job or an admin command before [New], with the
// same seeds the Provider is built with. It takes no part in request
// handling and MUST NOT be reachable from an HTTP route: it rewrites
// client credentials, so exposing it would let a request replace a
// client's secret.
//
// A client whose stored Source is not static (dynamically registered or
// admin-created) is never touched. If any seed meets one, the call
// returns an error wrapping [store.ErrConflict] and writes nothing. All
// seeds are checked before the first write, so a conflict anywhere leaves
// the whole set unwritten.
//
// The writes themselves are not atomic: a backend failure part-way
// leaves some clients written. The call returns the results of the
// clients written before the failure together with the error, and
// running it again converges, because already-written clients then
// compare as unchanged.
//
// SyncStaticClients never deletes. A client dropped from the seed list
// stays in the store; retire it with [store.ClientRegistry.DeleteClient].
//
// A [ConfidentialClient] seeded with Secret is stored as an Argon2id
// hash, and an existing hash that already verifies the plaintext is kept
// so a re-run does not churn the stored value. Under
// [WithHighEntropyClientSecrets], seed with SecretHash instead: [New]
// refuses a store whose static client carries an Argon2id hash there, and
// SyncStaticClients does not see that option.
//
// The seeds are validated for shape (nil, empty secret, duplicate IDs),
// but the metadata checks that depend on the Provider's options run in
// [New].
//
// The store must expose a writable client registry; otherwise the call
// returns a configuration error. Passing no seeds returns an empty result.
//
// Stable since v1.5.
func SyncStaticClients(ctx context.Context, st store.Store, seeds ...ClientSeed) ([]StaticClientSyncResult, error) {
	registry, ok := resolveClientRegistry(st)
	if !ok {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "store has no writable client registry",
		}
	}
	records, plaintexts, err := collectStaticClientSeeds(seeds)
	if err != nil {
		return nil, err
	}

	results := make([]StaticClientSyncResult, len(records))
	for i := range records {
		action, err := classifyStaticClient(ctx, registry, &records[i], plaintexts)
		if err != nil {
			return nil, err
		}
		results[i] = StaticClientSyncResult{ID: records[i].ID, Action: action}
	}
	return applyStaticClientSync(ctx, registry, records, results)
}

// classifyStaticClient decides what the sync does with desired, without
// writing. A stored record from a non-static source is a conflict. A
// re-seeded plaintext keeps the stored hash when it still verifies, so an
// identical re-run is a no-op.
func classifyStaticClient(
	ctx context.Context,
	registry store.ClientRegistry,
	desired *store.Client,
	plaintexts map[string]string,
) (StaticClientSyncAction, error) {
	existing, err := registry.GetClient(ctx, desired.ID)
	if errors.Is(err, store.ErrNotFound) {
		return StaticClientInserted, nil
	}
	if err != nil {
		return "", &Error{
			Code:        codeConfiguration,
			Description: "SyncStaticClients: reading existing client " + desired.ID,
			Cause:       err,
		}
	}
	if existing.Source != "" && existing.Source != store.ClientSourceStatic {
		return "", &Error{
			Code: codeConfiguration,
			Description: "SyncStaticClients: stored client " + desired.ID +
				" is not a static client and is not overwritten",
			Cause: store.ErrConflict,
		}
	}
	if existing.Source == "" {
		desired.Source = ""
	}
	if plaintext, has := plaintexts[desired.ID]; has {
		if (&clientauth.Argon2id{}).Verify(plaintext, existing.SecretHash) == nil {
			desired.SecretHash = existing.SecretHash
		}
	}
	if store.StaticClientEquivalent(existing, desired) {
		return StaticClientUnchanged, nil
	}
	return StaticClientUpdated, nil
}

// applyStaticClientSync writes the records the classification marked as
// inserted or updated, in order, and stops at the first failure.
func applyStaticClientSync(
	ctx context.Context,
	registry store.ClientRegistry,
	records []store.Client,
	results []StaticClientSyncResult,
) ([]StaticClientSyncResult, error) {
	for i := range records {
		var err error
		switch results[i].Action {
		case StaticClientInserted:
			err = registry.RegisterClient(ctx, &records[i])
		case StaticClientUpdated:
			err = registry.UpdateClient(ctx, &records[i])
		case StaticClientUnchanged:
		}
		if err != nil {
			return results[:i], &Error{
				Code:        codeConfiguration,
				Description: "SyncStaticClients: writing client " + records[i].ID,
				Cause:       err,
			}
		}
	}
	return results, nil
}
