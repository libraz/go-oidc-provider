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
		// crypto.PublicKey is an alias for `any`, so the previous
		// `key.Key.(crypto.PublicKey)` assertion never failed and admitted
		// private (and symmetric) keys as if they were verification keys.
		// A JWKS advertised for signature verification MUST carry only
		// public asymmetric keys; reject anything else. IsPublic reports
		// false for private and symmetric (oct) keys.
		if !key.IsPublic() {
			return nil, ErrUnsupportedKeyShape
		}
		out = append(out, JWK{Algorithm: key.Algorithm, Key: key.Key})
	}
	return out, nil
}
