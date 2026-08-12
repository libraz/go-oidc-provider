package jose

import (
	"crypto"
	"encoding/json"
	"errors"

	josev4 "github.com/go-jose/go-jose/v4"
)

// ErrNoUsableJWK reports that a JWK Set was syntactically well-formed and
// declared at least one member, but none of them could be decoded into a
// key this build understands.
var ErrNoUsableJWK = errors.New("jose: JWK set contains no usable key")

// JWK exposes the minimal inline-JWKS fields callers outside internal/jose
// need for key-shape validation without importing go-jose directly.
type JWK struct {
	Algorithm string
	Use       string
	Key       crypto.PublicKey
}

// DecodeJWKSet decodes a JWK Set document member by member, dropping the
// members this build cannot represent. RFC 7517 §5 directs implementations
// to ignore JWKs whose "kty" they do not understand, that are missing
// required members, or whose values fall outside the supported ranges. The
// underlying JOSE library instead fails the whole document as soon as one
// member is unsupported, which would lock a relying party out of every
// JWKS-backed path the moment it published, say, an X25519 encryption key
// alongside its ES256 signing key.
//
// The second return value is the number of members the document declared,
// dropped ones included, so callers can bound cardinality on the wire shape
// rather than on the survivors. It is populated even when the function
// returns [ErrNoUsableJWK], so a caller that enforces a cardinality budget
// can apply it before inspecting the error.
//
// A document that declares no members decodes to an empty set without
// error; callers that require at least one key check the length themselves.
func DecodeJWKSet(raw []byte) (*josev4.JSONWebKeySet, int, error) {
	var envelope struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, 0, err
	}
	set := &josev4.JSONWebKeySet{Keys: make([]josev4.JSONWebKey, 0, len(envelope.Keys))}
	for _, member := range envelope.Keys {
		var key josev4.JSONWebKey
		if err := key.UnmarshalJSON(member); err != nil {
			continue
		}
		set.Keys = append(set.Keys, key)
	}
	if len(set.Keys) == 0 && len(envelope.Keys) > 0 {
		return nil, len(envelope.Keys), ErrNoUsableJWK
	}
	return set, len(envelope.Keys), nil
}

// ParseJWKSet parses a JWKS document and returns the valid keys it contains.
// Members the JOSE layer cannot decode are ignored (see [DecodeJWKSet]); a
// member that decodes but is not a public asymmetric key is a hard error,
// because admitting it would store a private or symmetric key as if it were
// a verification key.
func ParseJWKSet(raw []byte) ([]JWK, error) {
	set, _, err := DecodeJWKSet(raw)
	if err != nil {
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
		out = append(out, JWK{Algorithm: key.Algorithm, Use: key.Use, Key: key.Key})
	}
	return out, nil
}
