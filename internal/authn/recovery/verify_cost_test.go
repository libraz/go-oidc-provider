package recovery_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/op/store"
)

// batchFrom builds a persisted batch out of codes minted together, so
// every slot shares the salt the verifier requires.
func batchFrom(t *testing.T, plain []string) *store.RecoveryBatch {
	t.Helper()
	hashes, err := recovery.HashBatchForTest(plain)
	if err != nil {
		t.Fatalf("HashBatchForTest: %v", err)
	}
	slots := make([]store.RecoveryCode, 0, len(hashes))
	for _, h := range hashes {
		slots = append(slots, store.RecoveryCode{Hash: h})
	}
	return &store.RecoveryBatch{Subject: "user-alice", Codes: slots}
}

// allocatedBytes reports how many bytes fn caused the runtime to
// allocate. TotalAlloc is cumulative and unaffected by collection, so
// the reading measures work done rather than sampling a wall clock: one
// argon2id derivation at m=64MiB allocates its whole cost block, and
// nothing else on the verify path is within two orders of magnitude of
// that.
func allocatedBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestVerify_WrongCodeCostDoesNotGrowWithBatchSize is the property that
// matters for a factor with no rate limit in front of it by default: a
// single mistyped code must not buy the attacker one 64 MiB argon2id
// derivation per stored slot. The assertion is on the ratio between a
// one-slot batch and a full ten-slot batch rather than on a duration,
// so it pins the algorithm and not the machine it runs on. A verifier
// that derives per slot lands at a ratio near ten.
//
//nolint:paralleltest // the measurement reads process-wide allocation counters; a parallel sibling would be counted into it.
func TestVerify_WrongCodeCostDoesNotGrowWithBatchSize(t *testing.T) {
	plain, err := recovery.GenerateBatch()
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	ten := batchFrom(t, plain)
	// The head of the same batch: one slot, same salt, no extra hashing.
	one := &store.RecoveryBatch{Subject: ten.Subject, Codes: ten.Codes[:1]}

	v := &recovery.Verifier{}
	const wrong = "ZZZZZ-ZZZZZ"
	guess := func(b *store.RecoveryBatch) func() {
		return func() {
			if _, err := v.Verify(context.Background(), b, wrong); !errors.Is(err, recovery.ErrCodeInvalid) {
				t.Errorf("Verify(wrong) err=%v want ErrCodeInvalid", err)
			}
		}
	}

	// Warm up so first-call lazy allocations land outside the reading.
	guess(one)()
	oneSlot := allocatedBytes(guess(one))
	tenSlots := allocatedBytes(guess(ten))
	if oneSlot == 0 {
		t.Fatal("the one-slot guess allocated nothing; the measurement is not observing the derivation")
	}
	// Two derivations' worth of headroom: the property is "constant",
	// and the bound only has to exclude "linear in the batch size".
	if tenSlots > 2*oneSlot {
		t.Errorf("wrong guess allocated %d bytes against 10 slots and %d against 1: the cost scales with the batch size",
			tenSlots, oneSlot)
	}
}

// legacyBatch builds a batch in the layout this package minted before
// the slots of a batch shared a salt: each slot hashed on its own, so
// each carries its own salt. It is what an installation that enrolled
// users under an earlier release has in storage.
func legacyBatch(t *testing.T, plain []string) *store.RecoveryBatch {
	t.Helper()
	slots := make([]store.RecoveryCode, 0, len(plain))
	for _, code := range plain {
		h, err := recovery.HashCodeForTest(code)
		if err != nil {
			t.Fatalf("HashCodeForTest: %v", err)
		}
		slots = append(slots, store.RecoveryCode{Hash: h})
	}
	return &store.RecoveryBatch{Subject: "user-legacy", Codes: slots}
}

// TestVerify_LegacyPerSlotSaltBatchStillVerifies is the compatibility
// guarantee the shared-salt layout is not allowed to break. Only hashes
// are stored, so nothing can re-hash a sheet the OP never held the
// plaintext for: refusing the old layout would void every printed sheet
// already in users' hands, and they would find out at the moment they
// needed the break-glass credential. The verifier therefore derives per
// slot for these batches — the old cost profile, kept on purpose.
func TestVerify_LegacyPerSlotSaltBatchStillVerifies(t *testing.T) {
	t.Parallel()

	plain := []string{"ABCDE-12345", "FGHJK-67890", "MNPQR-STVWX"}
	batch := legacyBatch(t, plain)
	clk := &fakeClock{t: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	v := &recovery.Verifier{Clock: clk}

	// A code from the last slot redeems its own slot, so the per-slot
	// derivation is reaching every candidate rather than only the first.
	res, err := v.Verify(context.Background(), batch, plain[2])
	if err != nil {
		t.Fatalf("Verify(legacy plaintext): %v", err)
	}
	if res.Outcome != recovery.OutcomeSuccess {
		t.Errorf("outcome=%v want Success", res.Outcome)
	}
	if res.Index != 2 {
		t.Errorf("Index=%d want 2", res.Index)
	}
	if got := batch.Codes[2].ConsumedAt; !got.Equal(clk.t) {
		t.Errorf("ConsumedAt=%v want %v", got, clk.t)
	}

	// Single-use still holds on the legacy layout: the consumed slot is
	// out of the candidate set, so replaying it reads as a wrong code.
	if _, err := v.Verify(context.Background(), batch, plain[2]); !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Errorf("replay of a consumed legacy code err=%v want ErrCodeInvalid", err)
	}
	// And an unconsumed slot is still redeemable afterwards.
	again, err := v.Verify(context.Background(), batch, plain[0])
	if err != nil {
		t.Fatalf("Verify(second legacy plaintext): %v", err)
	}
	if again.Index != 0 {
		t.Errorf("Index=%d want 0", again.Index)
	}
}

// TestVerify_LegacyBatchRejectsWrongCode pins the other half: the
// compatibility path must still refuse a guess, and must not consume a
// slot while doing it.
func TestVerify_LegacyBatchRejectsWrongCode(t *testing.T) {
	t.Parallel()

	batch := legacyBatch(t, []string{"ABCDE-12345", "FGHJK-67890"})
	res, err := (&recovery.Verifier{}).Verify(context.Background(), batch, "ZZZZZ-ZZZZZ")
	if !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Fatalf("err=%v want ErrCodeInvalid", err)
	}
	if res.Outcome != recovery.OutcomeInvalid || res.Index != -1 {
		t.Errorf("outcome=%v index=%d want Invalid/-1", res.Outcome, res.Index)
	}
	for i, slot := range batch.Codes {
		if !slot.ConsumedAt.IsZero() {
			t.Errorf("Codes[%d] was consumed by a rejected guess", i)
		}
	}
}

// TestVerify_RejectsParameterInflatedSlot pins the ceiling on the work
// factor: it comes from the parameters this package mints, not from
// whatever a stored row claims. A slot declaring a memory cost above
// the minted one is refused before any derivation runs, so a corrupted
// store cannot inflate the price of a guess — on either layout.
func TestVerify_RejectsParameterInflatedSlot(t *testing.T) {
	t.Parallel()

	// m=128MiB is double what the generator mints and well inside the
	// shared argon2id policy's own 1 GiB ceiling. The key bytes are
	// filler: the parameters are refused before anything is compared.
	const inflated = "$argon2id$v=19$m=131072,t=3,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"
	batch := &store.RecoveryBatch{
		Subject: "user-alice",
		Codes:   []store.RecoveryCode{{Hash: inflated}},
	}

	res, err := (&recovery.Verifier{}).Verify(context.Background(), batch, "ABCDE-12345")
	if !errors.Is(err, recovery.ErrInvalidHash) {
		t.Fatalf("err=%v want ErrInvalidHash", err)
	}
	if res.Outcome != recovery.OutcomeInvalid {
		t.Errorf("outcome=%v want OutcomeInvalid", res.Outcome)
	}
}
