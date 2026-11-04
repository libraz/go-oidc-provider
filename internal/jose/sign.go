package jose

import (
	"crypto"
	"encoding/json"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// SignCompact signs claims as a compact JWS under alg with key, naming kid
// in the protected header. alg must be on the allow-list and match the key
// shape; a mismatch wraps [ErrUnsupportedKeyShape].
func SignCompact(key crypto.Signer, alg Algorithm, kid string, claims any) (string, error) {
	if !alg.IsAllowed() {
		return "", fmt.Errorf("jose: sign: alg %q is not allowed", alg)
	}
	if err := AssertAlgKeyShape(string(alg), key.Public()); err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jose: sign: marshal claims: %w", err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{
		Algorithm: josev4.SignatureAlgorithm(alg),
		Key:       josev4.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(alg), Use: "sig"},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("jose: sign: build signer: %w", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("jose: sign: %w", err)
	}
	return obj.CompactSerialize()
}
