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
	"encoding/base64"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

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
	ring *keys.AEADRing
}

// NewCodec constructs a [Codec] from the supplied keys. The first key is used
// for new encryptions; remaining keys are accepted only on decryption to
// support rotation.
// Every key must be exactly 32 bytes; an empty list is rejected so that
// "WithCookieKeys was forgotten" surfaces at startup rather than at runtime.
func NewCodec(current []byte, previous ...[]byte) (*Codec, error) {
	ring, err := keys.NewAEADRing(ErrInvalidKey, current, previous...)
	if err != nil {
		return nil, err
	}
	return &Codec{ring: ring}, nil
}

// Seal encrypts plaintext with the current key and returns a URL-safe base64
// string suitable for an [http.Cookie] value. The aad argument is bound into
// the GCM tag so a payload encrypted for one cookie name (e.g. "session")
// fails to authenticate when copied into another cookie ("interaction").
func (c *Codec) Seal(plaintext, aad []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(c.ring.Seal(plaintext, aad)), nil
}

// Open decrypts a value produced by [Codec.Seal]. It tries the current key
// first and falls back to the rotation history. The aad argument must match
// the value passed to [Codec.Seal] for the call to succeed.
func (c *Codec) Open(value string, aad []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, ok := c.ring.Open(raw, aad)
	if !ok {
		return nil, ErrDecrypt
	}
	return pt, nil
}
