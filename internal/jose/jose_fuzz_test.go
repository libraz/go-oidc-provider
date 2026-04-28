package jose_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// FuzzJOSEParse exercises [jose.ParseSigned] with arbitrary byte sequences
// to verify three structural properties:
//
//  1. ParseSigned never panics, regardless of input.
//  2. ParseSigned never accepts a "none" or HMAC algorithm — these are
//     rejected at the type boundary before signature material is touched.
//  3. ParseSigned only returns nil error for inputs whose "alg" header is
//     in the allow-list (RS256/PS256/ES256/EdDSA).
//
// The seed corpus contains three known-bad inputs and one well-formed
// malformed-signature value. Real signed tokens are exercised in unit
// tests where the keyset is in scope.
func FuzzJOSEParse(f *testing.F) {
	// Seed: alg=none compact JWS — historically devastating to JWT
	// libs. Tracks CVE-2015-2951 (jose4j) and the broader 2015
	// "alg=none" disclosure (Auth0 advisory).
	f.Add(`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.`)
	// Seed: alg=HS256 — symmetric algorithm must be rejected. Tracks
	// CVE-2015-9235 (jsonwebtoken) and CVE-2016-10555 (jwt-simple).
	f.Add(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.invalid`)
	// Seed: bogus base64 in header.
	f.Add(`!!!.???.***`)
	// Seed: well-formed compact JWS with ES256 header but bogus signature.
	f.Add(`eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature_placeholder`)
	// Seed: case-variant alg=NONE. Tracks CVE-2026-22817 cluster
	// (Hono JWT middleware, 2026) — case-insensitive deny-list bypass.
	f.Add(`eyJhbGciOiJOT05FIn0.eyJzdWIiOiJhbGljZSJ9.`)
	f.Add(`eyJhbGciOiJOb25lIn0.eyJzdWIiOiJhbGljZSJ9.`)
	f.Add(`eyJhbGciOiJub05FIn0.eyJzdWIiOiJhbGljZSJ9.`)
	// Seed: JSON-serialised JWS form (RFC 7515 §7.2). The library's
	// contract is compact-only; this seed pins the rejection.
	f.Add(`{"payload":"eyJzdWIiOiJhbGljZSJ9","signatures":[{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"AA"}]}`)
	// Seed: header carrying jku — RFC 8725 §3.1 / CVE-2018-0114 class.
	// The verifier MUST NOT fetch the URL or trust the value.
	f.Add(`eyJhbGciOiJFUzI1NiIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuZXhhbXBsZS9qd2tzLmpzb24ifQ.eyJzdWIiOiJhbGljZSJ9.x`)
	// Seed: oversize compact JWS (1 MiB). Pins that ParseSigned does
	// not allocate or recurse unboundedly. RFC 8725 §3.11 / CVE-2024-29371
	// (jose4j DoS) is the threat model. Truncated to a manageable seed
	// size; the fuzzer will explore the neighbourhood.
	f.Add(strings.Repeat("a", 1<<16))

	f.Fuzz(func(t *testing.T, raw string) {
		jws, alg, err := jose.ParseSigned(raw)
		if err != nil {
			// Errors are fine; they MUST wrap one of our sentinel values.
			if !errors.Is(err, jose.ErrAlgorithmNotAllowed) && !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("ParseSigned returned unrecognised error class: %v", err)
			}
			if jws != nil {
				t.Fatalf("ParseSigned returned non-nil JWS alongside error: %v", err)
			}
			if alg != jose.AlgUnspecified {
				t.Fatalf("ParseSigned returned non-zero alg %q alongside error", alg)
			}
			return
		}

		// Success path. The library's contract is that the parsed alg is
		// in the allow-list and that "none"/HS* never reach this branch.
		if !alg.IsAllowed() {
			t.Fatalf("ParseSigned succeeded but returned disallowed alg %q for input %q",
				alg, truncate(raw, 64))
		}
		if jws == nil {
			t.Fatalf("ParseSigned returned ok with nil JWS for input %q", truncate(raw, 64))
		}
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(" + lengthLabel(len(s)) + ")"
}

func lengthLabel(n int) string {
	var b strings.Builder
	b.WriteString("len=")
	switch {
	case n < 1024:
		b.WriteString(itoa(n))
	default:
		b.WriteString(itoa(n))
	}
	return b.String()
}

// itoa is a tiny allocation-free int-to-string used only to keep failure
// messages predictable; the standard library's [strconv.Itoa] is fine but
// we avoid introducing it just for fuzz diagnostics.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
