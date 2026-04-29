// Package cookie implements the OP's cookie layer. It owns AES-256-GCM
// encryption with key rotation, the [__Host-] profile policy, and the helpers
// that translate a logical "set this cookie" into an [http.Cookie] with the
// production-grade defaults the library requires (Secure, HttpOnly,
// SameSite=Lax, Path=/, no Domain attribute).
// The package is intentionally agnostic of the cookie payload format: callers
// supply raw bytes, the codec produces an opaque base64url string, and the
// caller decides whether the bytes are JSON, CBOR, or anything else. Higher
// layers (session, interaction) wrap the codec with their own typed payloads.
// [__Host-]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-13#section-4.1.3.2
package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// keyLen is the byte length required for AES-256 keys. Anything else is
// rejected at construction time so misconfiguration cannot weaken the cipher.
const keyLen = 32

// nonceLen is the GCM standard nonce length in bytes. The codec generates a
// fresh random nonce per encryption and prepends it to the ciphertext.
const nonceLen = 12

// ErrInvalidKey is returned when a key supplied to [NewCodec] is not exactly
// 32 bytes long. AES-256-GCM requires a 256-bit key.
var ErrInvalidKey = errors.New("cookie: AES-256-GCM key must be 32 bytes")

// ErrDecrypt is returned when [Codec.Open] cannot authenticate the supplied
// ciphertext under any configured key. The error is intentionally opaque so
// callers cannot use it to distinguish between rotation and tampering.
var ErrDecrypt = errors.New("cookie: ciphertext failed authentication")

// Codec encrypts and decrypts cookie payloads using AES-256-GCM. The first
// key is the encryption key; subsequent keys are tried in order during
// decryption to support graceful rotation.
// A Codec is immutable and safe for concurrent use.
type Codec struct {
	current cipher.AEAD
	prev    []cipher.AEAD
}

// NewCodec constructs a [Codec] from the supplied keys. The first key is used
// for new encryptions; remaining keys are accepted only on decryption to
// support rotation.
// Every key must be exactly 32 bytes; an empty list is rejected so that
// "WithCookieKey was forgotten" surfaces at startup rather than at runtime.
func NewCodec(current []byte, previous ...[]byte) (*Codec, error) {
	if len(current) != keyLen {
		return nil, ErrInvalidKey
	}
	cur, err := newAEAD(current)
	if err != nil {
		return nil, fmt.Errorf("cookie: build current AEAD: %w", err)
	}
	prev := make([]cipher.AEAD, 0, len(previous))
	for i, k := range previous {
		if len(k) != keyLen {
			return nil, fmt.Errorf("cookie: previous key %d: %w", i, ErrInvalidKey)
		}
		a, err := newAEAD(k)
		if err != nil {
			return nil, fmt.Errorf("cookie: build previous AEAD %d: %w", i, err)
		}
		prev = append(prev, a)
	}
	return &Codec{current: cur, prev: prev}, nil
}

// Seal encrypts plaintext with the current key and returns a URL-safe base64
// string suitable for an [http.Cookie] value. The aad argument is bound into
// the GCM tag so a payload encrypted for one cookie name (e.g. "session")
// fails to authenticate when copied into another cookie ("interaction").
func (c *Codec) Seal(plaintext, aad []byte) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("cookie: read nonce: %w", err)
	}
	ct := c.current.Seal(nonce, nonce, plaintext, aad)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// Open decrypts a value produced by [Codec.Seal]. It tries the current key
// first and falls back to the rotation history. The aad argument must match
// the value passed to [Codec.Seal] for the call to succeed.
func (c *Codec) Open(value string, aad []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(raw) < nonceLen {
		return nil, ErrDecrypt
	}
	nonce, ct := raw[:nonceLen], raw[nonceLen:]
	if pt, err := c.current.Open(nil, nonce, ct, aad); err == nil {
		return pt, nil
	}
	for _, prev := range c.prev {
		if pt, err := prev.Open(nil, nonce, ct, aad); err == nil {
			return pt, nil
		}
	}
	return nil, ErrDecrypt
}

// newAEAD wraps [cipher.NewGCM] over an AES-256 cipher. Errors here indicate
// a programming bug (we already validated the key length) but they are
// surfaced rather than panicked so the operator sees a clean start-up error.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
