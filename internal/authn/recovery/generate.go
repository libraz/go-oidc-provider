package recovery

import (
	"context"

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
