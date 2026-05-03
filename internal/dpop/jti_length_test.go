package dpop //nolint:testpackage // exercises the package-private decodeProofClaims and maxJTILen.

import (
	"errors"
	"strings"
	"testing"
)

// TestDecodeProofClaims_RejectsOversizedJTI pins H-G2: jti is capped
// at 256 bytes before the verifier touches the replay store. RFC 9449
// sets no upper bound; the cap closes an unbounded-allocation surface
// at the verifier boundary.
func TestDecodeProofClaims_RejectsOversizedJTI(t *testing.T) {
	t.Parallel()

	// Build a minimal valid claim envelope but with an oversized jti.
	oversized := strings.Repeat("a", maxJTILen+1)
	payload := []byte(`{"jti":"` + oversized + `","htm":"POST","htu":"https://op/token","iat":1700000000}`)
	_, err := decodeProofClaims(payload)
	if err == nil {
		t.Fatal("expected error for oversized jti, got nil")
	}
	if !errors.Is(err, ErrProofMalformed) {
		t.Errorf("err=%v want ErrProofMalformed", err)
	}
}

// TestDecodeProofClaims_AcceptsJTIAtCap confirms the boundary value
// (exactly maxJTILen bytes) is admitted.
func TestDecodeProofClaims_AcceptsJTIAtCap(t *testing.T) {
	t.Parallel()

	exact := strings.Repeat("a", maxJTILen)
	payload := []byte(`{"jti":"` + exact + `","htm":"POST","htu":"https://op/token","iat":1700000000}`)
	c, err := decodeProofClaims(payload)
	if err != nil {
		t.Fatalf("decodeProofClaims: %v", err)
	}
	if c.JTI != exact {
		t.Errorf("c.JTI length = %d, want %d", len(c.JTI), maxJTILen)
	}
}
