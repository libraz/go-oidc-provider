//nolint:testpackage // Exercises the package-private randomness seam directly.
package keys

import (
	"math"
	"testing"
)

func TestRandomUint63Except_ReturnsUsableDistinctToken(t *testing.T) {
	t.Parallel()

	const excluded = uint64(42)
	for range 16 {
		got, err := RandomUint63Except(excluded)
		if err != nil {
			t.Fatalf("RandomUint63Except: %v", err)
		}
		if got == 0 || got >= math.MaxInt64 {
			t.Fatalf("token=%d outside usable signed-63-bit range", got)
		}
		if got == excluded {
			t.Fatalf("token=%d equals excluded value", got)
		}
	}
}

func TestRandomInt63Except_ReturnsUsableDistinctToken(t *testing.T) {
	t.Parallel()

	const excluded int64 = 42
	for range 16 {
		got, err := RandomInt63Except(excluded)
		if err != nil {
			t.Fatalf("RandomInt63Except: %v", err)
		}
		if got <= 0 || got == math.MaxInt64 {
			t.Fatalf("token=%d outside usable signed-63-bit range", got)
		}
		if got == excluded {
			t.Fatalf("token=%d equals excluded value", got)
		}
	}
}
