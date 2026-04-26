package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

// GenerateES256 returns a freshly generated ECDSA P-256 [Entry] with the
// supplied key ID. It is intended for tests and the testkit; production
// keys MUST be loaded from a KMS or trusted on-disk material.
//
// The key is generated with [crypto/rand.Reader]; a failure to read the
// entropy source is wrapped and returned. KeyID MUST be non-empty.
func GenerateES256(keyID string) (Entry, error) {
	if keyID == "" {
		return Entry{}, fmt.Errorf("%w: empty KeyID", ErrInvalidKey)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Entry{}, fmt.Errorf("keys: generate ES256: %w", err)
	}
	return Entry{KeyID: keyID, Signer: priv}, nil
}
