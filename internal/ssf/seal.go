package ssf

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// sealKeyLen is the AES-256 key length.
const sealKeyLen = 32

// ErrSealKey reports a seal key that is not 32 bytes.
var ErrSealKey = errors.New("ssf: seal key must be 32 bytes")

// ErrUnseal reports a sealed value no key in the ring authenticates.
// Rotation and tampering are deliberately indistinguishable.
var ErrUnseal = errors.New("ssf: sealed value failed authentication")

// Sealer seals a push stream's authorization_header with AES-256-GCM.
// The blob is nonce(12)||ciphertext||tag with a fresh crypto/rand nonce
// per seal, and the stream ID is the AAD, so a blob copied onto another
// stream does not open. Seal uses the first key; Unseal tries every key
// in ring order. Immutable and safe for concurrent use.
type Sealer struct {
	ring []cipher.AEAD
}

// NewSealer builds a Sealer from the key ring, current key first.
func NewSealer(current []byte, previous ...[]byte) (*Sealer, error) {
	all := append([][]byte{current}, previous...)
	ring := make([]cipher.AEAD, 0, len(all))
	for i, k := range all {
		if len(k) != sealKeyLen {
			return nil, fmt.Errorf("ssf: seal key %d: %w", i, ErrSealKey)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("ssf: seal key %d: %w", i, err)
		}
		// The random-nonce mode draws a 12-byte nonce from crypto/rand
		// and prepends it, so this package never handles nonces itself.
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, fmt.Errorf("ssf: seal key %d: %w", i, err)
		}
		ring = append(ring, aead)
	}
	return &Sealer{ring: ring}, nil
}

// Seal encrypts header under the current key, bound to streamID.
func (s *Sealer) Seal(streamID, header string) []byte {
	// The nil nonce is required by the random-nonce AEAD, which draws its own.
	return s.ring[0].Seal(nil, nil, []byte(header), []byte(streamID)) //nolint:gosec // G407: NewGCMWithRandomNonce generates the nonce internally.
}

// Unseal opens a blob produced by [Sealer.Seal] for streamID.
func (s *Sealer) Unseal(streamID string, sealed []byte) (string, error) {
	for _, aead := range s.ring {
		if pt, err := aead.Open(nil, nil, sealed, []byte(streamID)); err == nil {
			return string(pt), nil
		}
	}
	return "", ErrUnseal
}
