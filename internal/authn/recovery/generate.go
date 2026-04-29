package recovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// GenerationResult bundles the freshly minted batch and the plaintext
// codes that produced it. The two fields are deliberately separated so
// the caller cannot accidentally persist plaintext: handing Batch alone
// to [store.RecoveryStore.Put] is safe, while PlaintextCodes is the
// display-once material the caller MUST surface to the user exactly
// once and then drop.
//
// The plaintext slice and the batch's Codes slice share an index: the
// hash at Batch.Codes[i] matches PlaintextCodes[i]. Callers SHOULD NOT
// rely on the order beyond display purposes; the order has no security
// significance.
type GenerationResult struct {
	// Batch is the persistent representation. Every entry has Hash
	// populated and ConsumedAt zero. GeneratedAt is stamped with the
	// verifier's clock reading.
	Batch *store.RecoveryBatch

	// PlaintextCodes are the human-readable codes returned to the
	// user exactly once. The caller MUST NOT log, audit, or persist
	// these values; their only sanctioned destination is the user's
	// browser / printer.
	PlaintextCodes []string
}

// Generate mints a fresh batch of ten recovery codes for subject. The
// returned [GenerationResult] carries the persistent batch (hashes
// only) and the plaintext codes (display-once). Callers MUST overwrite
// any pre-existing batch for subject with the returned one — recovery
// codes have batch-replace semantics, never append-or-merge.
//
// The function reads from crypto/rand (for code generation) and CPU
// (for argon2id hashing); on a typical server the ten hashes complete
// in well under a second. It is therefore safe to call inline from a
// HTTP handler, though embedders that want sub-100ms response times
// SHOULD generate batches asynchronously and stream the plaintext to
// the user via a follow-up GET.
//
// The ctx parameter is accepted for symmetry with the storage API and
// future cancellation but is not consulted today.
func (v *Verifier) Generate(_ context.Context, subject string) (*GenerationResult, error) {
	plaintext, err := GenerateBatch()
	if err != nil {
		return nil, err
	}
	codes := make([]store.RecoveryCode, 0, len(plaintext))
	for _, p := range plaintext {
		h, err := hashCode(p)
		if err != nil {
			return nil, err
		}
		codes = append(codes, store.RecoveryCode{Hash: h})
	}
	batch := &store.RecoveryBatch{
		Subject:     subject,
		Codes:       codes,
		GeneratedAt: v.clock().Now(),
	}
	return &GenerationResult{
		Batch:          batch,
		PlaintextCodes: plaintext,
	}, nil
}

// Replace generates a fresh batch and persists it through the supplied
// [store.RecoveryStore], overwriting any prior batch for subject in a
// single Put call. The function is the documented entry point for
// "the user wants to invalidate every previously printed code and
// receive a new sheet": the prior hashes are wiped and the displayed
// plaintext codes are returned exactly once on the
// [GenerationResult.PlaintextCodes] field.
//
// Atomicity: the [store.RecoveryStore.Put] call is upsert-style, so
// the new batch overwrites the prior one in a single round trip.
// Callers fronting the call with a transactional store get full
// atomicity for free; callers running the inmem reference get the
// same guarantee through the in-memory mutex. A failure during Put
// returns the error verbatim and the [GenerationResult] is nil so a
// caller cannot accidentally surface plaintext that was never
// persisted.
//
// The ctx parameter is forwarded to the store so a caller's
// cancellation propagates to the backend.
func (v *Verifier) Replace(ctx context.Context, recStore store.RecoveryStore, subject string) (*GenerationResult, error) {
	if recStore == nil {
		return nil, errors.New("recovery: store is required")
	}
	if subject == "" {
		return nil, errors.New("recovery: subject is required")
	}
	res, err := v.Generate(ctx, subject)
	if err != nil {
		return nil, err
	}
	if err := recStore.Put(ctx, res.Batch); err != nil {
		return nil, fmt.Errorf("recovery: persist replacement batch: %w", err)
	}
	return res, nil
}
