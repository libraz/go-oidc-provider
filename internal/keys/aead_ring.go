package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AEADKeyLen is the AES-256 key length every [AEADRing] key must have.
const AEADKeyLen = 32

// AEADRing is an AES-256-GCM key ring. Seal uses the first key; Open tries
// every key in ring order so a rotated-out key keeps opening older blobs.
// The blob is nonce(12)||ciphertext||tag with a fresh crypto/rand nonce per
// seal. Immutable and safe for concurrent use.
type AEADRing struct {
	ring []cipher.AEAD
}

// NewAEADRing builds a ring from current followed by previous. A key that is
// not [AEADKeyLen] bytes yields badKey: bare for current, wrapped with its
// index for a previous key, so each caller keeps its own sentinel.
func NewAEADRing(badKey error, current []byte, previous ...[]byte) (*AEADRing, error) {
	ring := make([]cipher.AEAD, 0, 1+len(previous))
	for i, k := range append([][]byte{current}, previous...) {
		if len(k) != AEADKeyLen {
			if i == 0 {
				return nil, badKey
			}
			return nil, fmt.Errorf("previous key %d: %w", i-1, badKey)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		ring = append(ring, aead)
	}
	return &AEADRing{ring: ring}, nil
}

// Seal encrypts plaintext under the current key with aad bound into the tag.
func (r *AEADRing) Seal(plaintext, aad []byte) []byte {
	// The random-nonce AEAD draws and prepends its own nonce.
	return r.ring[0].Seal(nil, nil, plaintext, aad) //nolint:gosec // G407: NewGCMWithRandomNonce generates the nonce internally.
}

// Open decrypts a blob produced by [AEADRing.Seal] under any ring key. The
// boolean is false when no key authenticates it; rotation and tampering are
// deliberately indistinguishable.
func (r *AEADRing) Open(blob, aad []byte) ([]byte, bool) {
	for _, aead := range r.ring {
		if pt, err := aead.Open(nil, nil, blob, aad); err == nil {
			return pt, true
		}
	}
	return nil, false
}
