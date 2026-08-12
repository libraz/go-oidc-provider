// Package csrf implements the CSRF defences the OP applies to its
// HTML-driven flows: HMAC-bound double-submit tokens plus
// Origin / Referer allowlist checking. The package emits no HTML, sets
// no cookies, and reads no request bodies; higher layers wire it into the
// interaction and account handlers.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

// randomTokenLen is the byte length of the opaque tokens [NewRandomToken]
// mints. 32 bytes matches the HMAC key length and is far beyond guessing
// range for the minutes-long window a double-submit token stays valid.
const randomTokenLen = 32

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
	// keys is ordered current first, then previous rotation keys. The
	// signer always issues with keys[0], while verification accepts the
	// whole overlap window.
	keys [][]byte
}

// NewSigner builds a [Signer] from a 32-byte current HMAC key and optional
// previous keys. The key ring is immutable after construction: issuance uses
// the current key only, while verification tries current then previous keys
// so a rolling deployment does not invalidate an in-flight interaction.
func NewSigner(current []byte, previous ...[]byte) (*Signer, error) {
	if len(current) != keyLen {
		return nil, ErrInvalidKey
	}
	keys := make([][]byte, 0, 1+len(previous))
	keys = append(keys, cloneKey(current))
	for _, key := range previous {
		if len(key) != keyLen {
			return nil, ErrInvalidKey
		}
		keys = append(keys, cloneKey(key))
	}
	return &Signer{keys: keys}, nil
}

// Issue mints a fresh token bound to sessionID and stamped at issuedAt. The
// returned string is suitable both as the [__Host-oidc_csrf] cookie value
// and as the X-CSRF-Token header — the double-submit pattern relies on the two
// being literally identical.
// Format: "<nonce_b64>.<unix_seconds>.<hmac_b64>" where the HMAC covers a
// length-prefixed canonicalisation of (sessionID, nonce, iat, ""). The
// format is opaque to callers; treat it as a single token.
func (s *Signer) Issue(sessionID string, issuedAt time.Time) (string, error) {
	return s.IssueScoped(sessionID, "", issuedAt)
}

// IssueScoped mints a token additionally bound to a per-request scope
// string (e.g. an interaction nonce or a form action ID). The scope is
// folded into the HMAC input so a token issued for one form cannot be
// replayed against another even when both share the session. An empty
// scope reduces to [Issue] semantics.
func (s *Signer) IssueScoped(sessionID, scope string, issuedAt time.Time) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("csrf: read nonce: %w", err)
	}
	iat := issuedAt.UTC().Unix()
	mac := s.compute(s.keys[0], sessionID, nonce, iat, scope)
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
	return s.VerifyScoped(token, sessionID, "", now, maxAge)
}

// VerifyScoped is the [IssueScoped] counterpart. The scope MUST equal the
// one supplied at issuance, otherwise the HMAC tag mismatches and the token
// is rejected. Pass an empty scope to verify a token minted by [Issue].
func (s *Signer) VerifyScoped(token, sessionID, scope string, now time.Time, maxAge time.Duration) error {
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
	valid := false
	for _, key := range s.keys {
		want := s.compute(key, sessionID, nonce, iat, scope)
		// Do not return on the first match. Keeping the verification pass
		// at a stable key-count avoids making the active key identifiable
		// through timing during the rotation overlap window.
		if hmac.Equal(got, want) {
			valid = true
		}
	}
	if !valid {
		return ErrTokenInvalid
	}
	issued := time.Unix(iat, 0).UTC()
	age := now.UTC().Sub(issued)
	if age < 0 {
		return ErrTokenInvalid
	}
	if maxAge > 0 {
		if age > maxAge {
			return ErrTokenInvalid
		}
	}
	return nil
}

// compute returns the HMAC-SHA256 tag of the canonical encoding
//
//	uint32be(len(sessionID)) || sessionID || uint32be(len(nonce)) || nonce || int64be(iat) || optional binding
//
// Length-prefixed framing eliminates the boundary-shifting collisions that
// any single-byte separator (the previous "|") would have permitted: a
// (sessionID, nonce) pair and a different (sessionID', nonce') with the same
// concatenation now produce different inputs because the two length prefixes
// disagree. Adding the optional [Issue]-time binding keeps a single MAC
// implementation across both APIs.
func (s *Signer) compute(key []byte, sessionID string, nonce []byte, iat int64, binding string) []byte {
	h := hmac.New(sha256.New, key)
	var lenBuf [4]byte
	sid := []byte(sessionID)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sid))) //nolint:gosec // len fits in uint32 by construction.
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(sid)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(nonce))) //nolint:gosec // 16 fits in uint32.
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(nonce)
	var iatBuf [8]byte
	binary.BigEndian.PutUint64(iatBuf[:], uint64(iat)) //nolint:gosec // signed↔unsigned reinterpret is intentional.
	_, _ = h.Write(iatBuf[:])
	bind := []byte(binding)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(bind))) //nolint:gosec // len fits in uint32 by construction.
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(bind)
	return h.Sum(nil)
}

func cloneKey(key []byte) []byte {
	cp := make([]byte, len(key))
	copy(cp, key)
	return cp
}

// NewRandomToken mints an opaque, cryptographically random double-submit
// token encoded as unpadded base64url. The encoding is URL-safe so the
// value round-trips through both a Set-Cookie header and an
// application/x-www-form-urlencoded field without escaping.
//
// The token carries no binding of its own — the cookie IS the state, and
// the only check is [ConstantTimeEqual] against the resubmitted copy. Use
// it for a gate whose flow has no server-side identifier to bind to; a
// flow that does (an interaction uid, a form step) should mint through
// [Signer.IssueScoped] instead so a token cannot be replayed across
// steps.
func NewRandomToken() (string, error) {
	buf := make([]byte, randomTokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("csrf: read token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ConstantTimeEqual reports whether the cookie value and the supplied header
// value are equal in constant time, matching the double-submit comparison
// the interaction endpoints require. The function is exported so handlers can use it
// without re-importing crypto/subtle.
func ConstantTimeEqual(cookie, header string) bool {
	if len(cookie) != len(header) {
		return false
	}
	return hmac.Equal([]byte(cookie), []byte(header))
}
