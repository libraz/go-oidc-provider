package jarm_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jarm"
)

// FuzzParseResponseMode exercises [jarm.Parse] with arbitrary strings.
// JARM response_mode values arrive on the wire from the client, so the
// parser is an untrusted-byte boundary even though the function looks
// trivial. Two structural invariants are checked:
//
//  1. Parse never panics, regardless of input.
//  2. The (mode, ok) pair is internally consistent. When ok is true the
//     returned mode MUST be exactly one of the four canonical JARM
//     constants AND its string form MUST equal the input verbatim — a
//     partial / case-folded match would be a silent acceptance bug.
//     When ok is false the returned mode MUST be the empty string so a
//     caller that ignores ok cannot accidentally use a stale value.
//
// Seed rationale:
//   - empty: the "no response_mode" path; ok must be false.
//   - "query" / "fragment" / "form_post": non-JARM modes; ok must be false.
//   - "query.jwt" / "fragment.jwt" / "form_post.jwt" / "jwt": the four
//     accepted JARM modes; ok must be true.
//   - "QUERY.JWT": case-mutated JARM mode; ok must be false (the spec is
//     case-sensitive on the wire).
//   - "query.jwt.extra": superstring of a valid mode; ok must be false.
//   - " query.jwt" (leading space): tolerant-decoder probe; ok must be
//     false (no whitespace trimming).
//   - "query.jwt\x00": NUL injection probe; ok must be false.
//   - 4 KiB string: oversize input; must not allocate-and-crash.
func FuzzParseResponseMode(f *testing.F) {
	big := make([]byte, 4*1024)
	for i := range big {
		big[i] = 'a'
	}

	f.Add("")
	f.Add("query")
	f.Add("fragment")
	f.Add("form_post")
	f.Add("query.jwt")
	f.Add("fragment.jwt")
	f.Add("form_post.jwt")
	f.Add("jwt")
	f.Add("QUERY.JWT")
	f.Add("query.jwt.extra")
	f.Add(" query.jwt")
	f.Add("query.jwt\x00")
	f.Add(string(big))

	f.Fuzz(func(t *testing.T, s string) {
		mode, ok := jarm.Parse(s)
		if !ok {
			if mode != "" {
				t.Fatalf("Parse(%q) returned ok=false with non-empty mode %q", s, mode)
			}
			// IsJARM and Parse must agree.
			if jarm.IsJARM(s) {
				t.Fatalf("IsJARM(%q)=true but Parse(...) returned ok=false", s)
			}
			return
		}

		// ok=true. The returned mode must be one of the four canonical
		// constants and its string form must equal the input exactly.
		switch mode {
		case jarm.ResponseModeQueryJWT,
			jarm.ResponseModeFragmentJWT,
			jarm.ResponseModeFormPostJWT,
			jarm.ResponseModeJWT:
			// allowed
		default:
			t.Fatalf("Parse(%q) accepted with unrecognised mode %q", s, mode)
		}
		if string(mode) != s {
			t.Fatalf("Parse(%q) returned mode=%q (must equal input verbatim)", s, mode)
		}
		if !jarm.IsJARM(s) {
			t.Fatalf("Parse(%q) returned ok=true but IsJARM(...) returned false", s)
		}
	})
}
