//nolint:testpackage // Exercises the package-private allocator boundary directly.
package inmem

import (
	"math"
	"testing"
)

func TestMFAVersionAllocatorRejectsSignedMaximum(t *testing.T) {
	t.Parallel()
	allocator := newMFAVersionAllocator()
	allocator.nextValue.Store(uint64(math.MaxInt64) - 2)
	if got, err := allocator.next(); err != nil || got != uint64(math.MaxInt64)-1 {
		t.Fatalf("allocator.next() = (%d, %v), want MaxInt64-1", got, err)
	}
	if got, err := allocator.next(); err == nil || got != 0 {
		t.Fatalf("allocator.next() at signed maximum = (%d, %v), want exhaustion", got, err)
	}
}
