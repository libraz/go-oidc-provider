package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fakeClock returns a fixed instant so the ConsumedAt stamp is
// deterministic.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// fixture wires a Verifier with a fresh batch produced by
// Verifier.Generate. The plaintext codes are kept around in the test so
// the success / failure paths can drive Verify against known inputs.
type fixture struct {
	clock     *fakeClock
	verifier  *recovery.Verifier
	batch     *store.RecoveryBatch
	plaintext []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	v := &recovery.Verifier{Clock: clk}
	res, err := v.Generate(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return &fixture{
		clock:     clk,
		verifier:  v,
		batch:     res.Batch,
		plaintext: res.PlaintextCodes,
	}
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	res, err := f.verifier.Verify(context.Background(), f.batch, f.plaintext[3])
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Outcome != recovery.OutcomeSuccess {
		t.Errorf("outcome=%v want Success", res.Outcome)
	}
	if res.Index != 3 {
		t.Errorf("Index=%d want 3", res.Index)
	}
	if got := f.batch.Codes[3].ConsumedAt; !got.Equal(f.clock.t) {
		t.Errorf("ConsumedAt=%v want %v", got, f.clock.t)
	}
	for i := range f.batch.Codes {
		if i == 3 {
			continue
		}
		if !f.batch.Codes[i].ConsumedAt.IsZero() {
			t.Errorf("Codes[%d].ConsumedAt=%v want zero (only one slot consumed)", i, f.batch.Codes[i].ConsumedAt)
		}
	}
}

func TestVerify_RejectsConsumedCode(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	// Consume slot 0 then attempt to redeem it again.
	if _, err := f.verifier.Verify(context.Background(), f.batch, f.plaintext[0]); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	res, err := f.verifier.Verify(context.Background(), f.batch, f.plaintext[0])
	if !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Fatalf("err=%v want ErrCodeInvalid", err)
	}
	if res.Outcome != recovery.OutcomeInvalid {
		t.Errorf("outcome=%v want Invalid", res.Outcome)
	}
	if res.Index != -1 {
		t.Errorf("Index=%d want -1", res.Index)
	}
}

func TestVerify_AllConsumedAfterExhaustion(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	for i, code := range f.plaintext {
		if _, err := f.verifier.Verify(context.Background(), f.batch, code); err != nil {
			t.Fatalf("Verify slot %d: %v", i, err)
		}
	}
	// Any further attempt MUST surface ErrAllConsumed, not ErrCodeInvalid.
	res, err := f.verifier.Verify(context.Background(), f.batch, f.plaintext[0])
	if !errors.Is(err, recovery.ErrAllConsumed) {
		t.Fatalf("err=%v want ErrAllConsumed", err)
	}
	if res.Outcome != recovery.OutcomeAllConsumed {
		t.Errorf("outcome=%v want AllConsumed", res.Outcome)
	}
}

func TestVerify_RejectsWrongCode(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	res, err := f.verifier.Verify(context.Background(), f.batch, "ZZZZZ-ZZZZZ")
	if !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Fatalf("err=%v want ErrCodeInvalid", err)
	}
	if res.Outcome != recovery.OutcomeInvalid {
		t.Errorf("outcome=%v want Invalid", res.Outcome)
	}
	for i, slot := range f.batch.Codes {
		if !slot.ConsumedAt.IsZero() {
			t.Errorf("Codes[%d].ConsumedAt=%v want zero (no slot should be stamped)", i, slot.ConsumedAt)
		}
	}
}

func TestVerify_NoCodesOnEmptyBatch(t *testing.T) {
	t.Parallel()

	v := &recovery.Verifier{}
	for _, name := range []string{"nil", "empty"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var b *store.RecoveryBatch
			if name == "empty" {
				b = &store.RecoveryBatch{Subject: "user-alice"}
			}
			res, err := v.Verify(context.Background(), b, "anything")
			if !errors.Is(err, recovery.ErrNoCodes) {
				t.Fatalf("err=%v want ErrNoCodes", err)
			}
			if res.Outcome != recovery.OutcomeNoCodes {
				t.Errorf("outcome=%v want NoCodes", res.Outcome)
			}
		})
	}
}

// TestVerify_RejectsOversizedBatch pins audit finding S-10's batch
// amplification gate: a persisted batch carrying more than the
// in-tree maxBatchSize (16) is treated as store corruption and
// refused before any argon2id derivation runs. Without the gate, a
// single verify call would invoke argon2id once per slot, turning
// the batch length into a CPU / memory amplifier.
func TestVerify_RejectsOversizedBatch(t *testing.T) {
	t.Parallel()

	// Build a 17-slot batch. Each slot's Hash is a placeholder PHC —
	// it never gets parsed because the cap fires first. The string
	// MUST not be empty so a buggy gate that walks the slots would
	// at least try to derive (and the test would observe a hang).
	const placeholder = "$argon2id$v=19$m=19456,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"
	slots := make([]store.RecoveryCode, 17)
	for i := range slots {
		slots[i] = store.RecoveryCode{Hash: placeholder}
	}
	batch := &store.RecoveryBatch{Subject: "user-alice", Codes: slots}

	v := &recovery.Verifier{}
	res, err := v.Verify(context.Background(), batch, "anything")
	if !errors.Is(err, recovery.ErrBatchOversized) {
		t.Fatalf("err=%v want ErrBatchOversized", err)
	}
	if res.Outcome != recovery.OutcomeInvalid {
		t.Errorf("outcome=%v want OutcomeInvalid", res.Outcome)
	}
}

func TestVerify_NormalisesUserInput(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	// User types the same code in lowercase, without the formatting
	// hyphen, with stray spaces. Normalisation in the hash layer must
	// still match.
	original := f.plaintext[5]
	if len(original) != 11 || original[5] != '-' {
		t.Fatalf("unexpected code shape %q", original)
	}
	munged := "  " + string([]byte{
		original[0] | 0x20,
		original[1] | 0x20,
		original[2] | 0x20,
		original[3] | 0x20,
		original[4] | 0x20,
	}) + " " + original[6:] + "  "
	res, err := f.verifier.Verify(context.Background(), f.batch, munged)
	if err != nil {
		t.Fatalf("Verify munged=%q: %v", munged, err)
	}
	if res.Index != 5 {
		t.Errorf("Index=%d want 5", res.Index)
	}
}

func TestGenerate_ProducesTenHashedCodes(t *testing.T) {
	t.Parallel()

	clk := &fakeClock{t: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	v := &recovery.Verifier{Clock: clk}
	res, err := v.Generate(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got := len(res.Batch.Codes); got != 10 {
		t.Errorf("len(Codes)=%d want 10", got)
	}
	if got := len(res.PlaintextCodes); got != 10 {
		t.Errorf("len(PlaintextCodes)=%d want 10", got)
	}
	if !res.Batch.GeneratedAt.Equal(clk.t) {
		t.Errorf("GeneratedAt=%v want %v", res.Batch.GeneratedAt, clk.t)
	}
	if res.Batch.Subject != "user-alice" {
		t.Errorf("Subject=%q want user-alice", res.Batch.Subject)
	}
	for i, slot := range res.Batch.Codes {
		if slot.Hash == "" {
			t.Errorf("Codes[%d].Hash is empty", i)
		}
		if !slot.ConsumedAt.IsZero() {
			t.Errorf("Codes[%d].ConsumedAt=%v want zero on a fresh batch", i, slot.ConsumedAt)
		}
	}
	// A single plaintext verifies against its corresponding hash.
	// Hashing is intentionally slow (argon2id m=64MiB, t=3); driving
	// the full batch through Verify here would dominate test runtime
	// without adding coverage that TestVerify_HappyPath does not
	// already provide.
	const probeIndex = 7
	out, err := v.Verify(context.Background(), res.Batch, res.PlaintextCodes[probeIndex])
	if err != nil {
		t.Fatalf("Verify plaintext[%d]: %v", probeIndex, err)
	}
	if out.Index != probeIndex {
		t.Errorf("Verify plaintext[%d] returned Index=%d want %d", probeIndex, out.Index, probeIndex)
	}
}

func TestVerify_DefaultsClockToSystem(t *testing.T) {
	t.Parallel()

	v := &recovery.Verifier{}
	res, err := v.Generate(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out, err := v.Verify(context.Background(), res.Batch, res.PlaintextCodes[0])
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Outcome != recovery.OutcomeSuccess {
		t.Errorf("outcome=%v want Success", out.Outcome)
	}
	if res.Batch.Codes[0].ConsumedAt.IsZero() {
		t.Errorf("ConsumedAt is zero — default clock did not stamp slot")
	}
}

// fakeRecoveryStore is a minimal in-process [store.RecoveryStore] for
// the Replace test. It captures the most recent Put so the assertion
// can verify the prior batch was wiped.
type fakeRecoveryStore struct {
	current *store.RecoveryBatch
}

func (f *fakeRecoveryStore) Get(_ context.Context, subject string) (*store.RecoveryBatch, error) {
	if f.current == nil || f.current.Subject != subject {
		return nil, store.ErrNotFound
	}
	cp := *f.current
	cp.Codes = append([]store.RecoveryCode(nil), f.current.Codes...)
	return &cp, nil
}

func (f *fakeRecoveryStore) Put(_ context.Context, b *store.RecoveryBatch) error {
	cp := *b
	cp.Codes = append([]store.RecoveryCode(nil), b.Codes...)
	f.current = &cp
	return nil
}

func (f *fakeRecoveryStore) Delete(_ context.Context, _ string) error {
	f.current = nil
	return nil
}

// TestReplace_BatchWipesOldCodes asserts the Replace API generates a
// fresh batch, persists it via Put, and that codes from the prior
// batch fail to verify against the new one (M-RECOVERY).
func TestReplace_BatchWipesOldCodes(t *testing.T) {
	t.Parallel()

	clk := &fakeClock{t: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	v := &recovery.Verifier{Clock: clk}
	st := &fakeRecoveryStore{}

	first, err := v.Generate(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("Generate first: %v", err)
	}
	if err := st.Put(context.Background(), first.Batch); err != nil {
		t.Fatalf("Put first: %v", err)
	}

	clk.t = clk.t.Add(time.Hour)
	second, err := v.Replace(context.Background(), st, "user-alice")
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if second == nil || second.Batch == nil {
		t.Fatal("Replace returned nil result")
	}
	if !second.Batch.GeneratedAt.Equal(clk.t) {
		t.Errorf("GeneratedAt=%v want %v", second.Batch.GeneratedAt, clk.t)
	}

	// Confirm the persisted batch is the new one, not the old.
	persisted, err := st.Get(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("Get after Replace: %v", err)
	}
	if persisted.Codes[0].Hash != second.Batch.Codes[0].Hash {
		t.Error("persisted batch is not the replacement batch")
	}

	// A previously issued code must now be rejected against the
	// persisted replacement batch. The full wipe is established by the
	// Put/get assertion above; probing every old code would repeat the
	// same expensive argon2id miss under -race and can exceed the
	// package timeout on developer machines.
	_, vErr := v.Verify(context.Background(), persisted, first.PlaintextCodes[0])
	if !errors.Is(vErr, recovery.ErrCodeInvalid) {
		t.Errorf("old code err=%v want ErrCodeInvalid", vErr)
	}
}

// TestReplace_RequiresStoreAndSubject asserts the construction-time
// guards on Replace.
func TestReplace_RequiresStoreAndSubject(t *testing.T) {
	t.Parallel()

	v := &recovery.Verifier{Clock: &fakeClock{t: time.Now()}}
	if _, err := v.Replace(context.Background(), nil, "user-alice"); err == nil {
		t.Error("Replace with nil store accepted")
	}
	st := &fakeRecoveryStore{}
	if _, err := v.Replace(context.Background(), st, ""); err == nil {
		t.Error("Replace with empty subject accepted")
	}
}
