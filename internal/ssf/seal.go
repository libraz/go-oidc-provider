package ssf

import (
	"errors"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

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
	ring *keys.AEADRing
}

// NewSealer builds a Sealer from the key ring, current key first.
func NewSealer(current []byte, previous ...[]byte) (*Sealer, error) {
	ring, err := keys.NewAEADRing(ErrSealKey, current, previous...)
	if err != nil {
		return nil, err
	}
	return &Sealer{ring: ring}, nil
}

// Seal encrypts header under the current key, bound to streamID.
func (s *Sealer) Seal(streamID, header string) []byte {
	return s.ring.Seal([]byte(header), []byte(streamID))
}

// Unseal opens a blob produced by [Sealer.Seal] for streamID.
func (s *Sealer) Unseal(streamID string, sealed []byte) (string, error) {
	pt, ok := s.ring.Open(sealed, []byte(streamID))
	if !ok {
		return "", ErrUnseal
	}
	return string(pt), nil
}
