// Package pkce implements RFC 7636 (Proof Key for Code Exchange) verification
// for the authorization_code grant.
//
// The OP only accepts the S256 transformation. The "plain" method is rejected
// by policy regardless of client configuration: §A.12.3 requires it and OAuth
// 2.1 / FAPI 2.0 forbid plain. Callers therefore never need to thread a
// method choice through the API; this package validates the challenge format
// at issuance and the verifier at exchange.
package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// Method is the wire form of code_challenge_method. The package exports it
// so callers can compare against the constant rather than hard-coding the
// string.
const Method = "S256"

// VerifierMinLength and VerifierMaxLength are the inclusive bounds on
// code_verifier length, per RFC 7636 §4.1.
const (
	VerifierMinLength = 43
	VerifierMaxLength = 128
)

// Sentinel errors. Callers translate these to wire-level OAuth codes
// (invalid_request at the authorization endpoint, invalid_grant at the token
// endpoint).
var (
	// ErrChallengeRequired indicates the client omitted code_challenge at
	// the authorization endpoint. Maps to invalid_request.
	ErrChallengeRequired = errors.New("pkce: code_challenge is required")

	// ErrChallengeMethodUnsupported indicates the client supplied a
	// code_challenge_method other than S256. Maps to invalid_request.
	ErrChallengeMethodUnsupported = errors.New("pkce: only S256 is supported")

	// ErrChallengeFormat indicates code_challenge is not a 43-character
	// base64url-without-padding string of the correct length. Maps to
	// invalid_request.
	ErrChallengeFormat = errors.New("pkce: code_challenge has invalid format")

	// ErrVerifierFormat indicates code_verifier violates the RFC 7636 §4.1
	// ABNF (length or character set). Maps to invalid_grant.
	ErrVerifierFormat = errors.New("pkce: code_verifier has invalid format")

	// ErrVerifierMismatch indicates the SHA-256 of code_verifier does not
	// match the stored code_challenge. Maps to invalid_grant.
	ErrVerifierMismatch = errors.New("pkce: code_verifier does not match challenge")
)

// ValidateChallenge checks that a code_challenge / code_challenge_method
// pair received at the authorization endpoint is acceptable: method must be
// S256, challenge must be a 43-character base64url-without-padding string
// (the only valid output of SHA-256 → base64url-no-pad).
//
// Empty challenge or empty method returns [ErrChallengeRequired]; it is the
// caller's responsibility to enforce LegacyNoPKCE exemptions before calling
// this function.
func ValidateChallenge(challenge, method string) error {
	if challenge == "" {
		return ErrChallengeRequired
	}
	if method == "" {
		return ErrChallengeRequired
	}
	if method != Method {
		return ErrChallengeMethodUnsupported
	}
	if !isValidChallenge(challenge) {
		return ErrChallengeFormat
	}
	return nil
}

// Verify checks that code_verifier matches the stored code_challenge under
// the S256 transformation defined in RFC 7636 §4.6:
//
//	code_challenge == base64url(sha256(code_verifier))
//
// The comparison runs in constant time to avoid leaking information about
// the stored challenge through timing.
//
// challengeMethod is the parsed code_challenge_method the caller persisted
// alongside the authorization request. It is threaded through the
// signature so the token endpoint commits to a single invariant — "the
// method the request used MUST still be acceptable at exchange time" —
// rather than re-parsing the request a second time. The only accepted
// value is [Method] ("S256"); any other value (notably the legacy
// "plain") returns [ErrChallengeMethodUnsupported]. Passing "plain"
// here is structurally rejected even though "plain" would map to a
// no-op transform: OAuth 2.1 / FAPI 2.0 forbid "plain", and the
// rejection lives next to the transform so a future audit finds the
// rule at a single site.
func Verify(challenge, challengeMethod, verifier string) error {
	// invariant: caller passes the parsed code_challenge_method the
	// authorization endpoint persisted; "plain" is rejected here even
	// though it would map to the identity transform.
	if challengeMethod != Method {
		return ErrChallengeMethodUnsupported
	}
	if !isValidVerifier(verifier) {
		return ErrVerifierFormat
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) != 1 {
		return ErrVerifierMismatch
	}
	return nil
}

// isValidChallenge reports whether s is exactly 43 base64url-no-pad
// characters. SHA-256 produces 32 bytes which encode to exactly 43 such
// characters, so any other length is malformed regardless of content.
func isValidChallenge(s string) bool {
	if len(s) != 43 {
		return false
	}
	return isBase64URLNoPad(s)
}

// isValidVerifier reports whether s satisfies RFC 7636 §4.1:
//
//	code-verifier = 43*128unreserved
//	unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
func isValidVerifier(s string) bool {
	if len(s) < VerifierMinLength || len(s) > VerifierMaxLength {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !isUnreserved(c) {
			return false
		}
	}
	return true
}

// isUnreserved reports whether c is in the RFC 3986 §2.3 unreserved set.
func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	default:
		return false
	}
}

// isBase64URLNoPad reports whether s is composed entirely of base64url
// characters (RFC 4648 §5) without padding.
func isBase64URLNoPad(s string) bool {
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
