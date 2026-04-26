// Package csrf implements the CSRF defences described in
// docs/plans/002-product-design.md §F.3.1: HMAC-bound double-submit tokens
// plus Origin / Referer allowlist checking. The package emits no HTML, sets
// no cookies, and reads no request bodies; higher layers wire it into the
// interaction and account handlers.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// keyLen is the byte length required for the HMAC key. SHA-256's block size
// is 64 bytes; using a 32-byte key keeps the operation in a single block and
// matches the established posture of the cookie codec.
const keyLen = 32

// nonceLen is the random nonce length encoded into every token. 16 bytes is
// well above the birthday bound for the lifetime of a single OP session.
const nonceLen = 16

// ErrInvalidKey is returned when [NewSigner] receives a key of the wrong
// length. CSRF protection collapses if the key is too short, so the package
// rejects the misconfiguration at startup.
var ErrInvalidKey = errors.New("csrf: HMAC key must be 32 bytes")

// ErrTokenInvalid is the only verification error surfaced to callers. It
// covers parse failures, HMAC mismatch, expiry, and session binding mismatch
// so the verification path cannot be used as an oracle.
var ErrTokenInvalid = errors.New("csrf: token failed verification")

// Signer issues and verifies CSRF tokens bound to a session identifier. A
// Signer is immutable and safe for concurrent use.
type Signer struct {
	key []byte
}

// NewSigner builds a [Signer] from a 32-byte HMAC key. The key should come
// from a KMS / Vault and be rotated by deploying a new build; the CSRF
// surface is small enough that we don't bother with multi-key acceptance.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) != keyLen {
		return nil, ErrInvalidKey
	}
	cp := make([]byte, keyLen)
	copy(cp, key)
	return &Signer{key: cp}, nil
}

// Issue mints a fresh token bound to sessionID and stamped at issuedAt. The
// returned string is suitable both as the [__Host-oidc_csrf] cookie value
// and as the [X-CSRF] header — the double-submit pattern relies on the two
// being literally identical.
//
// Format: "<nonce_b64>.<unix_seconds>.<hmac_b64>" where the HMAC covers the
// concatenation "sessionID|nonce|unix_seconds". The format is opaque to
// callers; treat it as a single token.
func (s *Signer) Issue(sessionID string, issuedAt time.Time) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("csrf: read nonce: %w", err)
	}
	iat := issuedAt.UTC().Unix()
	mac := s.compute(sessionID, nonce, iat)
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(nonce),
		strconv.FormatInt(iat, 10),
		base64.RawURLEncoding.EncodeToString(mac),
	}, "."), nil
}

// Verify validates that token was issued by this Signer for sessionID, that
// the HMAC tag is intact, and that issuedAt is within maxAge of now. A
// maxAge of zero disables the freshness check (used for session-lifetime
// tokens that must remain valid until logout).
func (s *Signer) Verify(token, sessionID string, now time.Time, maxAge time.Duration) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrTokenInvalid
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(nonce) != nonceLen {
		return ErrTokenInvalid
	}
	iat, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return ErrTokenInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrTokenInvalid
	}
	want := s.compute(sessionID, nonce, iat)
	if !hmac.Equal(got, want) {
		return ErrTokenInvalid
	}
	if maxAge > 0 {
		issued := time.Unix(iat, 0).UTC()
		if now.UTC().Sub(issued) > maxAge {
			return ErrTokenInvalid
		}
	}
	return nil
}

// compute returns the HMAC-SHA256 tag of "sessionID|nonce|iat".
//
// The pipe separator is needed because sessionID is variable-length; without
// a delimiter, an attacker could move bytes between fields and still hit the
// same MAC. Pipes never appear in our session IDs (UUIDs / opaque tokens) so
// the separator is unambiguous.
func (s *Signer) compute(sessionID string, nonce []byte, iat int64) []byte {
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write([]byte(sessionID))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write(nonce)
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(strconv.FormatInt(iat, 10)))
	return h.Sum(nil)
}

// ConstantTimeEqual reports whether the cookie value and the supplied header
// value are equal in constant time, matching the double-submit comparison
// required by §F.3.1. The function is exported so handlers can use it
// without re-importing crypto/subtle.
func ConstantTimeEqual(cookie, header string) bool {
	if len(cookie) != len(header) {
		return false
	}
	return hmac.Equal([]byte(cookie), []byte(header))
}
