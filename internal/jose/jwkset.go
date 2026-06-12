package jose

import (
	"crypto"
	"encoding/json"

	josev4 "github.com/go-jose/go-jose/v4"
)

// JWK exposes the minimal inline-JWKS fields callers outside internal/jose
// need for key-shape validation without importing go-jose directly.
type JWK struct {
	Algorithm string
	Key       crypto.PublicKey
}

// ParseJWKSet parses a JWKS document and returns the valid keys it contains.
func ParseJWKSet(raw []byte) ([]JWK, error) {
	var set josev4.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	out := make([]JWK, 0, len(set.Keys))
	for _, key := range set.Keys {
		if !key.Valid() {
			return nil, ErrUnsupportedKeyShape
		}
		pub, ok := key.Key.(crypto.PublicKey)
		if !ok {
			return nil, ErrUnsupportedKeyShape
		}
		out = append(out, JWK{Algorithm: key.Algorithm, Key: pub})
	}
	return out, nil
}
