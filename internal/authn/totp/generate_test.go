package totp_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
)

// rfc6238SHA1Secret is the 20-byte ASCII test secret from RFC 6238
// Appendix B. The library implements the SHA-1 profile only; the
// 32-byte SHA-256 and 64-byte SHA-512 vectors in the RFC do not apply.
var rfc6238SHA1Secret = []byte("12345678901234567890")

func TestCode_RFC6238AppendixB(t *testing.T) {
	t.Parallel()

	// The RFC publishes 8-digit codes; the 6-digit form the library
	// emits is the rightmost six characters. The wantTruncated column
	// is the 6-digit suffix verified against the SHA-1 column of the
	// table in Appendix B.
	cases := []struct {
		name          string
		unix          int64
		wantTruncated string
	}{
		{"T=59", 59, "287082"},
		{"T=1111111109", 1111111109, "081804"},
		{"T=1111111111", 1111111111, "050471"},
		{"T=1234567890", 1234567890, "005924"},
		{"T=2000000000", 2000000000, "279037"},
		{"T=20000000000", 20000000000, "353130"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			at := time.Unix(tc.unix, 0).UTC()
			got := totp.Code(rfc6238SHA1Secret, at)
			if got != tc.wantTruncated {
				t.Errorf("Code(%d) = %s, want %s", tc.unix, got, tc.wantTruncated)
			}
		})
	}
}

func TestCode_AlwaysSixDigits(t *testing.T) {
	t.Parallel()

	// Sweep a few seconds to make sure the formatter pads short codes
	// with leading zeros instead of producing 1..5-digit strings.
	for i := int64(0); i < 600; i += 7 {
		at := time.Unix(i, 0).UTC()
		got := totp.Code(rfc6238SHA1Secret, at)
		if len(got) != 6 {
			t.Fatalf("len(Code at t=%d) = %d (%q), want 6", i, len(got), got)
		}
		for _, r := range got {
			if r < '0' || r > '9' {
				t.Fatalf("Code at t=%d = %q contains non-digit", i, got)
			}
		}
	}
}

func TestCode_StableWithinStep(t *testing.T) {
	t.Parallel()

	// Two times within the same 30-second step MUST produce the same
	// code; two times in adjacent steps SHOULD differ for at least
	// one secret (we use the RFC fixture).
	a := totp.Code(rfc6238SHA1Secret, time.Unix(60, 0).UTC())
	b := totp.Code(rfc6238SHA1Secret, time.Unix(89, 0).UTC())
	if a != b {
		t.Errorf("codes within step disagree: %s vs %s", a, b)
	}
	c := totp.Code(rfc6238SHA1Secret, time.Unix(90, 0).UTC())
	if a == c {
		t.Errorf("adjacent steps produced identical code %s; expected different", a)
	}
}
