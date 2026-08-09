package recovery

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/argon2id"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Outcome enumerates the verdicts [Verifier.Verify] returns alongside
// the mutated batch. The orchestrator branches on it to decide whether
// to advance the authenticator chain, prompt the user to retry, or
// route to the out-of-band, support-driven recovery flow.
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
	// MFA factor) or out-of-band support (if they do not).
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

	// ErrBatchOversized is returned when the persisted batch carries
	// more than [maxBatchSize] slots. The library never generates such
	// a batch, so the condition is treated as store corruption — the
	// verifier refuses to walk the oversized list because every slot
	// costs a parse and a constant-time compare, and an unbounded slot
	// count is an amplification vector. The outcome equals
	// [OutcomeInvalid] so the orchestrator routes the failure through
	// the same "this is broken, alert the operator" path it uses for
	// hash-format faults.
	ErrBatchOversized = errors.New("recovery: batch exceeds maxBatchSize")
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
// on a match, stamps that slot's ConsumedAt with the Verifier's clock
// reading. The caller is responsible for persisting the mutated batch
// through [store.RecoveryStore.Put] when the outcome is
// [OutcomeSuccess]; on every other outcome the batch is unchanged and
// Put is unnecessary.
// The function performs the following sequence:
//  1. Reject the call with [ErrNoCodes] if batch is nil or batch.Codes
//     is empty, and with [ErrBatchOversized] if it carries more than
//     [maxBatchSize] slots.
//  2. Collect the unconsumed slots and parse each one. Parsing spends
//     no work factor; a slot the [verifyPolicy] fence rejects surfaces
//     as [ErrInvalidHash].
//  3. Derive the presented code and compare it against every candidate
//     slot in constant time — once for the whole batch when the slots
//     share a derivation input, once per slot on the legacy layout
//     described in [match].
//  4. If a slot matched, stamp ConsumedAt = clock.Now() on it and
//     return [OutcomeSuccess] with the slot index.
//  5. If every slot's ConsumedAt is non-zero, return [ErrAllConsumed].
//  6. Otherwise return [ErrCodeInvalid].
//
// # Cost of a wrong guess
//
// One argon2id derivation for any batch [hashCodes] minted, whatever
// the batch size. That is the whole reason a batch shares one salt:
// with a salt per slot the only way to answer a guess is to derive once
// per slot, and ten 64 MiB derivations per submitted string is a memory
// amplifier an attacker drives with one short input. Batches carrying
// the pre-shared-salt layout still cost one derivation per unconsumed
// slot — see [match] for why they are verified rather than refused.
//
// # Why the match scan stays constant-time
//
// The derived key is compared against every candidate slot with
// [subtle.ConstantTimeCompare], and the loop does not stop early on
// either layout: the matching index is selected without a branch. A
// right code and a wrong code therefore run the same number of
// derivations and the same number of compares, and neither the response
// time nor the error distinguishes "no slot matched" from "slot 7
// matched". The work depends on how many slots are still unconsumed,
// which the prompt already tells the user.
//
// Verify never panics on a nil batch; it returns [ErrNoCodes]. The ctx
// parameter is accepted for symmetry with the storage API and future
// cancellation but is not consulted today.
func (v *Verifier) Verify(_ context.Context, batch *store.RecoveryBatch, presented string) (*Result, error) {
	if batch == nil || len(batch.Codes) == 0 {
		return &Result{Outcome: OutcomeNoCodes, Batch: batch, Index: -1}, ErrNoCodes
	}
	if len(batch.Codes) > maxBatchSize {
		// A batch that claims more than maxBatchSize slots is store
		// corruption — the generator never emits one. Refusing to walk
		// it before anything is parsed or derived means a corrupted
		// persistence layer cannot be turned into a CPU / memory
		// amplifier through one verify call.
		return &Result{Outcome: OutcomeInvalid, Batch: batch, Index: -1}, ErrBatchOversized
	}

	slots, err := candidates(batch)
	if err != nil {
		return &Result{Outcome: OutcomeInvalid, Batch: batch, Index: -1}, err
	}
	if len(slots) == 0 {
		return &Result{Outcome: OutcomeAllConsumed, Batch: batch, Index: -1}, ErrAllConsumed
	}

	index, found := match(presented, slots)
	if found {
		batch.Codes[index].ConsumedAt = v.clock().Now()
		return &Result{Outcome: OutcomeSuccess, Batch: batch, Index: index}, nil
	}
	return &Result{Outcome: OutcomeInvalid, Batch: batch, Index: -1}, ErrCodeInvalid
}

// candidate is one unconsumed slot: its position in the batch, the
// parameters its stored encoding declares, and the key stored for it.
type candidate struct {
	index  int
	params argon2id.PHCParams
	key    []byte
}

// candidates parses the unconsumed slots of batch. It returns
// [ErrInvalidHash] when a slot cannot be parsed under [verifyPolicy] —
// an integrity fault rather than a user error, and one that leaks
// nothing about the presented code because a slot hash is not
// attacker-supplied.
//
// An empty result means every slot is consumed; the caller maps that
// onto [ErrAllConsumed].
func candidates(batch *store.RecoveryBatch) ([]candidate, error) {
	out := make([]candidate, 0, len(batch.Codes))
	for i := range batch.Codes {
		if !batch.Codes[i].ConsumedAt.IsZero() {
			continue
		}
		parsed, err := parseStoredHash(batch.Codes[i].Hash)
		if err != nil {
			return nil, err
		}
		out = append(out, candidate{index: i, params: parsed, key: parsed.Hash})
	}
	return out, nil
}

// match derives presented and returns the index of the first slot whose
// stored key it equals. slots MUST be non-empty.
//
// # Two layouts
//
// A batch [hashCodes] minted shares one derivation input across its
// slots, so one derivation answers the whole batch. That is the design
// and the reason a wrong guess costs a fixed amount of work.
//
// A batch whose slots carry a salt each is the layout this package
// minted before the shared salt, and it is verified by deriving once
// per slot. That is deliberately kept rather than refused: the OP
// stores hashes only, so it cannot re-hash a batch it did not mint the
// plaintext for, and there is no migration an operator could run. The
// alternative to this path is every already-enrolled user losing their
// printed sheet on upgrade — discovering it at the moment they needed
// the break-glass credential. Availability of a last-resort factor
// outweighs closing an amplification that the cross-factor lockout
// counter already rate-limits and that [maxBatchSize] already bounds.
// The legacy population shrinks on its own as users regenerate.
//
// The cost profile of the legacy path is the old one: one 64 MiB
// derivation per unconsumed slot per guess. Do not "simplify" the two
// branches into the per-slot form — that is the amplification the
// shared salt removed.
//
// # Constant time on both layouts
//
// Every candidate is compared even after a match is found, and the
// winner is selected arithmetically, so the elapsed time carries no
// information about which slot matched — or whether one did. The legacy
// branch derives for every candidate for the same reason: stopping at
// the match would make a successful verify cost less than a failed one
// in proportion to the matched slot's position, which is a direct read
// of the index.
func match(presented string, slots []candidate) (int, bool) {
	shared, uniform := sharedDerivation(slots)
	var sharedKey []byte
	if uniform {
		sharedKey = deriveKey(presented, shared.Salt, paramsOf(shared))
	}

	index, found := -1, 0
	for _, slot := range slots {
		key := sharedKey
		if !uniform {
			key = deriveKey(presented, slot.params.Salt, paramsOf(slot.params))
		}
		equal := subtle.ConstantTimeCompare(key, slot.key)
		// take is 1 only for the first matching slot: later matches
		// (which random 50-bit codes make astronomically unlikely) are
		// masked out rather than allowed to move the index.
		take := equal &^ found
		index = subtle.ConstantTimeSelect(take, slot.index, index)
		found |= equal
	}
	return index, found == 1
}

// sharedDerivation reports whether every slot derives under identical
// inputs and, if so, returns them. It reads stored material only, never
// the presented code, so the branch it drives leaks nothing about a
// guess: which layout a batch has is a property of the batch.
func sharedDerivation(slots []candidate) (argon2id.PHCParams, bool) {
	ref := slots[0].params
	for _, slot := range slots[1:] {
		if !sameDerivation(ref, slot.params) {
			return argon2id.PHCParams{}, false
		}
	}
	return ref, true
}

func (v *Verifier) clock() timex.Clock {
	if v.Clock == nil {
		return timex.SystemClock
	}
	return v.Clock
}
