package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// keyLen is the byte length required for AES-256 keys. The codec rejects
// any other length at construction time so a misconfigured rotation slot
// cannot silently weaken the cipher.
const keyLen = 32

// nonceLen is the GCM standard nonce length in bytes. The codec
// generates a fresh random nonce per Seal and prepends it to the
// returned blob.
const nonceLen = 12

// ErrInvalidKey is returned when a key supplied to [NewCodec] is not
// exactly 32 bytes long. AES-256-GCM requires a 256-bit key.
var ErrInvalidKey = errors.New("totp: AES-256-GCM key must be 32 bytes")

// ErrDecrypt is returned when [Codec.Open] cannot authenticate the
// supplied blob under any configured key. The error is intentionally
// opaque so callers cannot distinguish key rotation from tampering.
var ErrDecrypt = errors.New("totp: ciphertext failed authentication")

// Codec encrypts and decrypts TOTP shared secrets at rest using
// AES-256-GCM. The first key is used for new encryptions; subsequent
// keys are tried in order during decryption to support graceful
// rotation. Unlike internal/cookie.Codec,
// the rotation history MUST be retained until every TOTP record has
// been re-encrypted under the current key — an enrolled secret may
// outlive multiple cookie-key rotations because users do not log in
// every day.
//
// A Codec is immutable after construction and safe for concurrent use.
type Codec struct {
	current cipher.AEAD
	prev    []cipher.AEAD
}

// NewCodec constructs a [Codec] from the supplied keys. The first key is
// used for new encryptions; remaining keys are accepted only on
// decryption to support rotation.
//
// Every key must be exactly 32 bytes; passing a key of any other length
// returns [ErrInvalidKey] so misconfiguration surfaces at startup
// rather than at first verify.
func NewCodec(current []byte, previous ...[]byte) (*Codec, error) {
	if len(current) != keyLen {
		return nil, ErrInvalidKey
	}
	cur, err := newAEAD(current)
	if err != nil {
		return nil, fmt.Errorf("totp: build current AEAD: %w", err)
	}
	prev := make([]cipher.AEAD, 0, len(previous))
	for i, k := range previous {
		if len(k) != keyLen {
			return nil, fmt.Errorf("totp: previous key %d: %w", i, ErrInvalidKey)
		}
		a, err := newAEAD(k)
		if err != nil {
			return nil, fmt.Errorf("totp: build previous AEAD %d: %w", i, err)
		}
		prev = append(prev, a)
	}
	return &Codec{current: cur, prev: prev}, nil
}

// Seal encrypts secret under the current key and returns the raw blob
// nonce||ciphertext||tag. The function does NOT base64-encode the
// output: TOTP secrets are stored in a database column as a BLOB / bytea,
// not in an HTTP cookie.
//
// The aad argument is bound into the GCM tag and is expected to be the
// subject ID of the record. A blob exfiltrated from one user's row
// therefore fails to decrypt when replayed under a different subject —
// the GCM tag verification rejects the AAD mismatch.
func (c *Codec) Seal(secret, aad []byte) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("totp: read nonce: %w", err)
	}
	return c.current.Seal(nonce, nonce, secret, aad), nil
}

// Open decrypts a blob produced by [Codec.Seal]. It tries the current
// key first and falls back to the rotation history in order. The aad
// argument MUST match the value passed to Seal; mismatches return
// [ErrDecrypt].
func (c *Codec) Open(blob, aad []byte) ([]byte, error) {
	if len(blob) < nonceLen {
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:nonceLen], blob[nonceLen:]
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

// newAEAD wraps [cipher.NewGCM] over an AES-256 cipher. The function is
// only reachable after the key length has already been validated, so
// any error here indicates a programming bug in the standard library;
// it is surfaced rather than panicked so the operator sees a clean
// startup error.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
