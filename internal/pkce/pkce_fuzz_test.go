// Package pkce_test contains fuzz harnesses for the RFC 7636 PKCE
// validation and verification helpers exposed by [pkce].
//
// The fuzzers establish three classes of structural invariants:
//
//  1. The functions never panic on arbitrary input.
//  2. Errors are always one of the documented sentinels — no naked or new
//     error classes leak across the API boundary.
//  3. Success paths satisfy the format and cryptographic identities
//     mandated by RFC 7636 §4.1 / §4.6, re-checked independently in the
//     test using crypto/sha256 + encoding/base64.RawURLEncoding.
//
// Real round-trip vectors are exercised by the unit tests in pkce_test.go;
// the fuzz harness exists to catch regressions where a malformed or
// adversarial input produces an unexpected result class.
package pkce_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/pkce"
)

// FuzzValidateChallenge exercises [pkce.ValidateChallenge] with arbitrary
// (challenge, method) pairs.
//
// Invariants:
//
//  1. Never panics.
//  2. On error, the result MUST wrap one of [pkce.ErrChallengeRequired],
//     [pkce.ErrChallengeMethodUnsupported], or [pkce.ErrChallengeFormat].
//     Any other error class is a contract violation.
//  3. On nil error, the inputs MUST satisfy the public format guarantee:
//     method == [pkce.Method] ("S256"), len(challenge) == 43, and every
//     byte of challenge is in the base64url-no-pad alphabet (RFC 4648 §5).
//     SHA-256 → base64url-no-pad is the only success-shape RFC 7636 admits.
//
// Seed rationale:
//   - empty/empty and empty/S256 cover [ErrChallengeRequired] on each side.
//   - "abc"/S256 covers the short-length [ErrChallengeFormat] branch.
//   - 43 char valid base64url + S256 covers the success path.
//   - 43 char with "+" / "/" + S256 covers the wrong-alphabet branch
//     ("+/" are standard base64, NOT base64url, so must be rejected).
//   - valid challenge + "plain" covers [ErrChallengeMethodUnsupported]
//     (OAuth 2.1 forbids plain).
//   - valid challenge + "s256" (lowercase) covers method case-sensitivity.
func FuzzValidateChallenge(f *testing.F) {
	const validChallenge = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" // 43 base64url chars
	const wrongAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO+/"  // 43 chars but "+/" invalid

	f.Add("", "")
	f.Add("", pkce.Method)
	f.Add("abc", pkce.Method)
	f.Add(validChallenge, pkce.Method)
	f.Add(wrongAlphabet, pkce.Method)
	f.Add(validChallenge, "plain")
	f.Add(validChallenge, "s256")

	f.Fuzz(func(t *testing.T, challenge, method string) {
		err := pkce.ValidateChallenge(challenge, method)
		if err != nil {
			// Errors are fine; they MUST wrap one of the documented sentinels.
			switch {
			case errors.Is(err, pkce.ErrChallengeRequired):
			case errors.Is(err, pkce.ErrChallengeMethodUnsupported):
			case errors.Is(err, pkce.ErrChallengeFormat):
			default:
				t.Fatalf("ValidateChallenge returned unrecognised error class: %v", err)
			}
			return
		}

		// Success path. Recheck the public format guarantees independently.
		if method != pkce.Method {
			t.Fatalf("ValidateChallenge accepted method %q but only %q is allowed", method, pkce.Method)
		}
		if len(challenge) != 43 {
			t.Fatalf("ValidateChallenge accepted challenge of length %d (want 43)", len(challenge))
		}
		for i := range len(challenge) {
			c := challenge[i]
			ok := (c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '-' || c == '_'
			if !ok {
				t.Fatalf("ValidateChallenge accepted challenge with non base64url-no-pad byte %q at offset %d", c, i)
			}
		}
	})
}

// FuzzVerify exercises [pkce.Verify] with arbitrary
// (challenge, method, verifier) triples.
//
// Invariants:
//
//  1. Never panics.
//  2. On error, the result MUST wrap one of
//     [pkce.ErrChallengeMethodUnsupported], [pkce.ErrVerifierFormat], or
//     [pkce.ErrVerifierMismatch]. Any other class is a contract violation.
//  3. On nil error, the inputs MUST satisfy RFC 7636:
//     method == [pkce.Method], len(verifier) ∈ [43, 128], every byte of
//     verifier is RFC 3986 unreserved, and the cryptographic identity
//     challenge == base64url(sha256(verifier)) holds. The expected
//     challenge is recomputed in-test from the fuzzer-provided verifier;
//     since the fuzzer feeds challenge independently, this is a genuine
//     property check rather than a tautology.
//
// Seed rationale:
//   - Matched pair: a 43-char unreserved verifier with its true S256
//     challenge — exercises the success path.
//   - Mismatched pair: same verifier but a different (still-valid)
//     challenge — must hit [ErrVerifierMismatch] without timing leak.
//   - Too-short verifier — [ErrVerifierFormat] length branch.
//   - Verifier containing "+" — [ErrVerifierFormat] alphabet branch
//     ("+" is base64 but NOT in the RFC 3986 unreserved set).
//   - method="plain" — [ErrChallengeMethodUnsupported] (OAuth 2.1 / FAPI
//     forbid plain regardless of client config).
func FuzzVerify(f *testing.F) {
	// Verifier composed exclusively of RFC 3986 unreserved bytes.
	const goodVerifier = "0123456789abcdefghijklmnopqrstuvwxyz0123456" // 43 chars
	goodChallenge := s256(goodVerifier)

	// A different valid challenge that is NOT s256(goodVerifier).
	otherChallenge := s256("different-verifier-value-with-43-chars-XYZab")

	f.Add(goodChallenge, pkce.Method, goodVerifier)                                   // matches
	f.Add(otherChallenge, pkce.Method, goodVerifier)                                  // mismatch
	f.Add(goodChallenge, pkce.Method, "abc")                                          // too short
	f.Add(goodChallenge, pkce.Method, "0123456789abcdef+ghijklmnopqrstuvwxyz0123456") // contains "+"
	f.Add(goodChallenge, "plain", goodVerifier)                                       // unsupported method

	f.Fuzz(func(t *testing.T, challenge, method, verifier string) {
		err := pkce.Verify(challenge, method, verifier)
		if err != nil {
			// Errors are fine; they MUST wrap one of the documented sentinels.
			switch {
			case errors.Is(err, pkce.ErrChallengeMethodUnsupported):
			case errors.Is(err, pkce.ErrVerifierFormat):
			case errors.Is(err, pkce.ErrVerifierMismatch):
			default:
				t.Fatalf("Verify returned unrecognised error class: %v", err)
			}
			return
		}

		// Success path. Re-check every clause of the contract.
		if method != pkce.Method {
			t.Fatalf("Verify accepted method %q but only %q is allowed", method, pkce.Method)
		}
		if n := len(verifier); n < pkce.VerifierMinLength || n > pkce.VerifierMaxLength {
			t.Fatalf("Verify accepted verifier of length %d (want [%d,%d])",
				n, pkce.VerifierMinLength, pkce.VerifierMaxLength)
		}
		for i := range len(verifier) {
			c := verifier[i]
			ok := (c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '-' || c == '.' || c == '_' || c == '~'
			if !ok {
				t.Fatalf("Verify accepted verifier with non-unreserved byte %q at offset %d", c, i)
			}
		}
		// Independent recomputation of the S256 transformation. If this
		// disagrees with the fuzzer-supplied challenge, Verify produced a
		// false positive — the most dangerous failure mode for PKCE.
		want := s256(verifier)
		if want != challenge {
			t.Fatalf("Verify accepted challenge %q but base64url(sha256(verifier)) = %q",
				challenge, want)
		}
	})
}

// s256 is the canonical PKCE S256 transformation defined in RFC 7636 §4.6.
// It is a test-only helper, kept minimal so that it cannot drift from the
// spec: any deviation here would mask bugs in the production path.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
