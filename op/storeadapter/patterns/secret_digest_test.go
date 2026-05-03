package patterns_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// TestDigest_MatchesSHA256Hex pins the wire shape of the digest the
// adapter corpus persists into authorization-code / refresh-token /
// PAR-uri columns: SHA-256 of the UTF-8 bytes of the bearer secret,
// hex-encoded as 64 ASCII characters. A future swap to HMAC-with-
// pepper will fail this test loudly so any change to the on-disk
// layout surfaces in review.
func TestDigest_MatchesSHA256Hex(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"a",
		"the quick brown fox jumps over the lazy dog",
		"urn:ietf:params:oauth:request_uri:abc",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			sum := sha256.Sum256([]byte(raw))
			want := hex.EncodeToString(sum[:])
			got := patterns.Digest(raw)
			if got != want {
				t.Fatalf("Digest(%q)=%q, want %q", raw, got, want)
			}
			if len(got) != 64 {
				t.Fatalf("Digest(%q) len=%d, want 64", raw, len(got))
			}
		})
	}
}

// TestDigestBytes_MatchesSHA256 pins the byte-form companion: the
// adapter that prefers BYTEA / BLOB columns over hex TEXT must
// observe the same digest as [Digest] when both are computed against
// the same input.
func TestDigestBytes_MatchesSHA256(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "a", "rt_secret"} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			gotBytes := patterns.DigestBytes(raw)
			wantBytes := sha256.Sum256([]byte(raw))
			if gotBytes != wantBytes {
				t.Fatalf("DigestBytes(%q)=%x, want %x", raw, gotBytes, wantBytes)
			}
			if hex.EncodeToString(gotBytes[:]) != patterns.Digest(raw) {
				t.Fatalf("DigestBytes(%q) and Digest(%q) disagree", raw, raw)
			}
		})
	}
}

// TestConstantTimeKeyMatch covers the comparison primitive used by
// the inmem and SQL adapters once a row has been located by digest:
// equal inputs report true, every other shape (different content,
// different lengths, empty operands) reports false.
func TestConstantTimeKeyMatch(t *testing.T) {
	t.Parallel()
	digestA := patterns.Digest("a")
	digestB := patterns.Digest("b")
	cases := []struct {
		name      string
		stored    string
		presented string
		want      bool
	}{
		{"equal digests", digestA, digestA, true},
		{"different digests", digestA, digestB, false},
		{"empty stored", "", digestA, false},
		{"empty presented", digestA, "", false},
		{"both empty", "", "", true},
		{"length mismatch", digestA, digestA[:32], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := patterns.ConstantTimeKeyMatch(tc.stored, tc.presented)
			if got != tc.want {
				t.Fatalf("ConstantTimeKeyMatch(%q, %q)=%v, want %v",
					tc.stored, tc.presented, got, tc.want)
			}
		})
	}
}
