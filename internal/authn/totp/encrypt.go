package totp

import (
	"errors"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

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
	ring *keys.AEADRing
}

// NewCodec constructs a [Codec] from the supplied keys. The first key is
// used for new encryptions; remaining keys are accepted only on
// decryption to support rotation.
//
// Every key must be exactly 32 bytes; passing a key of any other length
// returns [ErrInvalidKey] so misconfiguration surfaces at startup
// rather than at first verify.
func NewCodec(current []byte, previous ...[]byte) (*Codec, error) {
	ring, err := keys.NewAEADRing(ErrInvalidKey, current, previous...)
	if err != nil {
		return nil, err
	}
	return &Codec{ring: ring}, nil
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
	return c.ring.Seal(secret, aad), nil
}

// Open decrypts a blob produced by [Codec.Seal]. It tries the current
// key first and falls back to the rotation history in order. The aad
// argument MUST match the value passed to Seal; mismatches return
// [ErrDecrypt].
func (c *Codec) Open(blob, aad []byte) ([]byte, error) {
	pt, ok := c.ring.Open(blob, aad)
	if !ok {
		return nil, ErrDecrypt
	}
	return pt, nil
}
