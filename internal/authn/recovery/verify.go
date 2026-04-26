package recovery

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Outcome enumerates the verdicts [Verifier.Verify] returns alongside
// the mutated batch. The orchestrator branches on it to decide whether
// to advance the authenticator chain, prompt the user to retry, or
// route to the support-driven recovery flow per
// docs/plans/002-product-design.md §O.3.
type Outcome int

const (
	// OutcomeSuccess means the supplied code matched an unconsumed
	// slot, that slot has been stamped ConsumedAt = now, and the
	// caller MUST persist the mutated batch through
	// [store.RecoveryStore.Put] before returning to the user.
	OutcomeSuccess Outcome = iota + 1

	// OutcomeInvalid means the supplied code did not match any
	// unconsumed slot. The batch is unchanged; the caller MAY skip
	// re-Put. The orchestrator SHOULD apply the same rate limit it
	// applies to other authenticators since recovery codes are
	// brute-forceable in principle (50-bit search per code).
	OutcomeInvalid

	// OutcomeAllConsumed means every slot in the batch is already
	// stamped ConsumedAt. The user has exhausted the batch and MUST
	// be steered to either regeneration (if they still hold a primary
	// MFA factor) or out-of-band support (if they do not, per §O.3).
	OutcomeAllConsumed

	// OutcomeNoCodes means the persisted batch carries an empty Codes
	// slice. This is a configuration error from the embedder's point
	// of view — the library never stores an empty batch — but the
	// outcome is exposed so the orchestrator does not have to inspect
	// the batch shape itself.
	OutcomeNoCodes
)

// Sentinel errors. Returned values are wrapped through [errors.Is] so
// the orchestrator can dispatch on them without string matching.
var (
	// ErrNoCodes is returned when [Verifier.Verify] is called against
	// a batch whose Codes slice is empty (or against a nil batch).
	// The Outcome equals [OutcomeNoCodes].
	ErrNoCodes = errors.New("recovery: batch has no codes")

	// ErrAllConsumed is returned when every slot in the batch is
	// already stamped ConsumedAt. The Outcome equals
	// [OutcomeAllConsumed].
	ErrAllConsumed = errors.New("recovery: every code already consumed")

	// ErrCodeInvalid is returned when the supplied code does not match
	// any unconsumed slot. The Outcome equals [OutcomeInvalid]. The
	// error is intentionally identical for "wrong code" and "code
	// matched a consumed slot": leaking the latter would let an
	// attacker with a partial code list distinguish used-vs-unused
	// codes by polling.
	ErrCodeInvalid = errors.New("recovery: code did not match")
)

// Result is the verdict bundle [Verifier.Verify] returns. The Batch
// pointer is the same pointer the caller supplied, mutated in place on
// success, so the caller may pass it straight to
// [store.RecoveryStore.Put]. Index is the zero-based slot number that
// was consumed on a successful verify, or -1 otherwise; the orchestrator
// SHOULD record it in the audit trail (the slot, never the code) so
// support can correlate user reports.
type Result struct {
	// Outcome is the high-level verdict. See the [Outcome] constants.
	Outcome Outcome

	// Batch is the (possibly mutated) batch the caller passed in. On
	// OutcomeSuccess the matched slot's ConsumedAt has been stamped
	// with the verifier's clock reading; on every other Outcome the
	// batch is unchanged.
	Batch *store.RecoveryBatch

	// Index is the zero-based slot number that was consumed on
	// OutcomeSuccess, and -1 on any other Outcome. It is exposed so
	// the caller can write an audit event referencing the slot
	// position (not the code material).
	Index int
}

// Verifier verifies recovery codes against a persisted
// [store.RecoveryBatch] and stamps the consumed slot. The zero value is
// usable: Clock falls back to [timex.SystemClock]. The Verifier is
// immutable after construction and safe for concurrent use, but the
// per-user batch is the mutable shared state and the caller is
// responsible for serialising writes to it.
type Verifier struct {
	// Clock supplies the wall-clock reading used to stamp the
	// ConsumedAt field on a successful match. A nil value falls back
	// to [timex.SystemClock].
	Clock timex.Clock
}

// Verify checks presented against every unconsumed slot in batch and,
// on the first match, stamps that slot's ConsumedAt with the Verifier's
// clock reading. The caller is responsible for persisting the mutated
// batch through [store.RecoveryStore.Put] when the outcome is
// [OutcomeSuccess]; on every other outcome the batch is unchanged and
// Put is unnecessary.
//
// The function performs the following sequence:
//
//  1. Reject the call with [ErrNoCodes] if batch is nil or batch.Codes
//     is empty.
//  2. Walk the slot list. For every slot whose ConsumedAt is zero, run
//     [verifyCode] in constant time against the slot's Hash. Stop at
//     the first match.
//  3. If a match was found, stamp ConsumedAt = clock.Now() on that
//     slot and return [OutcomeSuccess] with the slot index.
//  4. If every slot's ConsumedAt is non-zero (no unconsumed slot was
//     ever inspected), return [ErrAllConsumed].
//  5. Otherwise return [ErrCodeInvalid].
//
// Verify never panics on a nil batch; it returns [ErrNoCodes]. The ctx
// parameter is accepted for symmetry with the storage API and future
// cancellation but is not consulted today.
func (v *Verifier) Verify(_ context.Context, batch *store.RecoveryBatch, presented string) (*Result, error) {
	if batch == nil || len(batch.Codes) == 0 {
		return &Result{Outcome: OutcomeNoCodes, Batch: batch, Index: -1}, ErrNoCodes
	}

	anyUnconsumed := false
	for i := range batch.Codes {
		slot := &batch.Codes[i]
		if !slot.ConsumedAt.IsZero() {
			continue
		}
		anyUnconsumed = true
		err := verifyCode(presented, slot.Hash)
		switch {
		case err == nil:
			slot.ConsumedAt = v.clock().Now()
			return &Result{Outcome: OutcomeSuccess, Batch: batch, Index: i}, nil
		case errors.Is(err, ErrCodeInvalid):
			continue
		default:
			// A malformed hash on a slot is a backend integrity
			// failure: surface it rather than silently treating it
			// as a miss.
			return &Result{Outcome: OutcomeInvalid, Batch: batch, Index: -1}, err
		}
	}

	if !anyUnconsumed {
		return &Result{Outcome: OutcomeAllConsumed, Batch: batch, Index: -1}, ErrAllConsumed
	}
	return &Result{Outcome: OutcomeInvalid, Batch: batch, Index: -1}, ErrCodeInvalid
}

func (v *Verifier) clock() timex.Clock {
	if v.Clock == nil {
		return timex.SystemClock
	}
	return v.Clock
}
