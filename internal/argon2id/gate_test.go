//nolint:testpackage // drives derivationSlots directly; the gate is unobservable from outside.
package argon2id

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// gateTestParams are the derivation parameters the gate tests use:
// the smallest values argon2 accepts, so a derivation costs
// microseconds. The gate is indifferent to the work factor — it counts
// callers, not bytes — and using production parameters would make
// every case below allocate 64 MiB to observe a channel.
const (
	gateTestMemory      uint32 = 8
	gateTestIterations  uint32 = 1
	gateTestParallelism uint8  = 1
	gateTestKeyLength   uint32 = 32
)

// fillGate reserves every slot and registers the release, so a test can
// observe what [Key] does with none available. Draining on cleanup
// matters more than it looks: a slot left held would shrink the gate
// for every later test in the package, and the symptom would be a
// timeout somewhere else entirely.
func fillGate(t *testing.T) {
	t.Helper()
	held := 0
	t.Cleanup(func() {
		for range held {
			<-derivationSlots
		}
	})
	for range cap(derivationSlots) {
		derivationSlots <- struct{}{}
		held++
	}
}

// TestKey_BlocksWhenNoSlotIsFree pins the gate's only externally
// meaningful behaviour: past capacity, callers wait instead of
// deriving. The negative half of the assertion has to be a timeout —
// "did not happen" has no other shape — but it is not a race against a
// slow machine: with gateTestParams a derivation completes in
// microseconds, so an ungated call would already have finished several
// thousand times over by the time the window closes.
//
//nolint:paralleltest // reserves the process-wide gate; cannot share it with another test.
func TestKey_BlocksWhenNoSlotIsFree(t *testing.T) {
	fillGate(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		Key([]byte("secret"), []byte("saltsaltsaltsalt"),
			gateTestIterations, gateTestMemory, gateTestParallelism, gateTestKeyLength)
	}()

	select {
	case <-done:
		t.Fatal("Key derived while the gate was full; the capacity bound does not hold")
	case <-time.After(50 * time.Millisecond):
	}

	// Free exactly one slot: the blocked caller should take it and no
	// other slot should be needed.
	<-derivationSlots
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Key did not proceed after a slot was released")
	}
	derivationSlots <- struct{}{}
}

// TestKey_ReleasesItsSlotOnPanic covers the failure that would be
// invisible until the process wedged. A derivation that panics must
// still hand its slot back; if it did not, capacity would fall by one
// per panic and a single-slot gate (GOMAXPROCS=1) would deadlock every
// subsequent authentication with no error and no log line.
//
// parallelism=0 is the trigger: the derivation divides the memory cost
// by the lane count before doing any work. The gate deliberately does
// not validate parameters — [ParsePHC] does that for stored hashes —
// so this reaches the panic rather than an error return.
//
//nolint:paralleltest // asserts against the process-wide gate's occupancy.
func TestKey_ReleasesItsSlotOnPanic(t *testing.T) {
	before := len(derivationSlots)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected a zero lane count to panic inside the derivation")
			}
		}()
		Key([]byte("secret"), []byte("saltsaltsaltsalt"),
			gateTestIterations, gateTestMemory, 0, gateTestKeyLength)
	}()

	if after := len(derivationSlots); after != before {
		t.Fatalf("slot leaked through a panicking derivation: occupancy %d -> %d", before, after)
	}
}

// TestKey_DerivesTheSameKeyAsTheUngatedCall proves the gate is
// transparent. It is the one property that would silently invalidate
// every stored hash in every deployment, so it is worth asserting
// against the underlying library rather than against a golden value
// this package produced itself.
//
//nolint:paralleltest // shares the process-wide gate with the tests above.
func TestKey_DerivesTheSameKeyAsTheUngatedCall(t *testing.T) {
	password := []byte("correct horse battery staple")
	salt := []byte("saltsaltsaltsalt")

	gated := Key(password, salt, gateTestIterations, gateTestMemory, gateTestParallelism, gateTestKeyLength)
	ungated := argon2.IDKey(password, salt, gateTestIterations, gateTestMemory, gateTestParallelism, gateTestKeyLength)

	if !bytes.Equal(gated, ungated) {
		t.Fatalf("gated derivation differs from the underlying one:\n gated %x\ndirect %x", gated, ungated)
	}
}

// TestMaxConcurrentDerivations_IsPositiveAndMatchesTheGate guards the
// two ways the capacity could be wrong at start-up. A zero capacity is
// the dangerous one: the channel would admit nobody and the first
// client authentication would hang forever, which is a worse outcome
// than the unbounded memory the gate exists to prevent.
//
//nolint:paralleltest // reads the process-wide gate.
func TestMaxConcurrentDerivations_IsPositiveAndMatchesTheGate(t *testing.T) {
	if got := MaxConcurrentDerivations(); got < 1 {
		t.Fatalf("MaxConcurrentDerivations() = %d; a gate that admits nobody deadlocks every verify", got)
	}
	if got, want := MaxConcurrentDerivations(), cap(derivationSlots); got != want {
		t.Fatalf("MaxConcurrentDerivations() = %d, gate capacity = %d; operators sizing a memory limit would read the wrong number", got, want)
	}
	if got, want := MaxConcurrentDerivations(), runtime.GOMAXPROCS(0); got != want && want > 1 {
		t.Fatalf("MaxConcurrentDerivations() = %d, GOMAXPROCS = %d; capacity no longer tracks the schedulable threads", got, want)
	}
}
