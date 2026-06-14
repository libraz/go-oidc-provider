package store

import (
	"context"
	"time"
)

// RecoveryCode is a single entry in a user's recovery-code batch. The
// library never persists the plaintext value: Hash is the modular-crypt
// argon2id encoding produced by internal/authn/recovery, and ConsumedAt
// is stamped the first (and only) time the user redeems the code.
// Backends MUST treat the struct as opaque. In particular, Hash is a
// self-describing argon2id encoding and the backend MUST NOT inspect or
// re-encode it.
type RecoveryCode struct {
	// Hash is the argon2id modular-crypt encoding ("$argon2id$...$salt$hash")
	// of the plaintext code. The format and parameters are owned by
	// internal/authn/recovery and are intentionally not configurable in
	// v1.0; backends store and return the string verbatim.
	Hash string

	// ConsumedAt is the wall-clock time the user redeemed this slot. A
	// zero value means "still available". The library stamps the field
	// on a successful Verify and writes the whole batch back through
	// [RecoveryStore.Put]; once stamped the slot can never be redeemed
	// again (single-use semantics).
	ConsumedAt time.Time
}

// RecoveryBatch is the persistent representation of a user's recovery
// codes. The library reads it on every Verify, mutates the slots in
// place, and writes the new state back through [RecoveryStore.Put]. A
// fresh Generate replaces the whole batch: callers MUST overwrite the
// previous record rather than appending.
// The struct is a plain data carrier; every policy decision (batch size,
// argon2id parameters, alphabet) lives in internal/authn/recovery.
type RecoveryBatch struct {
	// Subject is the OP-internal stable user identifier the batch
	// belongs to (the same value that becomes the "sub" claim of issued
	// tokens). It is the primary key of the record.
	Subject string

	// Codes is the slot list. The library always emits exactly the
	// batch size internal/authn/recovery is configured for (10 in v1.0)
	// and never resizes the slice; backends store and return it
	// verbatim.
	Codes []RecoveryCode

	// GeneratedAt is the wall-clock time the batch was minted. It is
	// informational — the library does not enforce a TTL on recovery
	// codes — but backends SHOULD surface it in account-management UIs
	// so users can reason about whether their stored codes are stale.
	GeneratedAt time.Time
}

// RecoveryStore is the substore for last-resort recovery codes. It is a
// transactional substore in spirit — every redeemed code rewrites the
// batch — but the library accesses it through a non-transactional handle
// today because the writes are localised to a single row and do not need
// to be atomic with token issuance.
// Recovery codes are NOT a primary authentication path: per
// 02-product-design.md §O.3, full account recovery (lost
// device AND lost recovery codes) requires out-of-band support and is
// intentionally not automated by the library. Backends MUST NOT log or
// audit Hash values: they are display-once material and a leak in the
// log pipeline is equivalent to a credential leak.
type RecoveryStore interface {
	// Get returns the batch for subject. It MUST return [ErrNotFound]
	// when no batch has ever been generated; any other non-nil error
	// indicates a backend fault.
	Get(ctx context.Context, subject string) (*RecoveryBatch, error)

	// Put creates or replaces the batch for b.Subject. Backends
	// implement upsert semantics: the library uses Put both for the
	// initial Generate and for every Verify-driven slot consumption.
	// Regenerating a fresh batch overwrites the previous one wholesale.
	Put(ctx context.Context, b *RecoveryBatch) error

	// Consume atomically marks one recovery-code slot as consumed. It
	// MUST succeed for at most one caller per slot and MUST return
	// [ErrAlreadyConsumed] when the stored slot already has ConsumedAt
	// set. The index is the slot index returned by the recovery
	// verifier for the same batch.
	Consume(ctx context.Context, b *RecoveryBatch, index int) error

	// Delete removes the batch for subject. It MUST return [ErrNotFound]
	// if no such batch exists so callers can distinguish a no-op delete
	// from a successful one. The library invokes Delete when the user
	// disables recovery codes from the account-management UI.
	Delete(ctx context.Context, subject string) error
}
