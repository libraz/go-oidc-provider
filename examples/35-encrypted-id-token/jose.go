//go:build example

// jose.go — JWE-of-JWS decrypt + verify dance for example
// 35-encrypted-id-token.
//
// This is the wire shape the example exists to demonstrate. The OP
// emits a five-part JWE (RSA-OAEP-256 wrap + A256GCM content) whose
// payload is the inner signed id_token (ES256 JWS). The RP must:
//
//  1. Parse the compact JWE with the alg / enc allowlist.
//  2. Decrypt the JWE with its private RSA encryption key, recovering
//     the inner JWS bytes.
//  3. Parse the inner compact JWS with the sig-alg allowlist.
//  4. Look up the OP's signing key by `kid`, verify the JWS, and
//     unmarshal the claim set.
//  5. Confirm the `iss` matches the OP the RP was configured to talk
//     to.
//
// The dance lives in its own file so readers can find it without
// scrolling past HTTP handler boilerplate.

package main

import (
	"encoding/json"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// decryptAndVerify splits the JWE-of-JWS shape: it decrypts the JWE
// with the RP's private encryption key, recovers the inner JWS,
// verifies the JWS against the OP's signing JWKS, and returns the
// claim map.
func (r *rp) decryptAndVerify(rawJWE string) (map[string]any, error) {
	jwe, err := josev4.ParseEncrypted(rawJWE,
		[]josev4.KeyAlgorithm{josev4.RSA_OAEP_256},
		[]josev4.ContentEncryption{josev4.A256GCM},
	)
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}
	innerJWS, err := jwe.Decrypt(r.opts.EncPrivate)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	jws, err := josev4.ParseSigned(string(innerJWS),
		[]josev4.SignatureAlgorithm{josev4.ES256},
	)
	if err != nil {
		return nil, fmt.Errorf("parse inner JWS: %w", err)
	}
	if len(jws.Signatures) == 0 {
		return nil, errors.New("inner JWS has no signatures")
	}

	kid := jws.Signatures[0].Header.KeyID
	matches := r.opSigJWKS.Key(kid)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no OP signing key for kid %q", kid)
	}
	payload, err := jws.Verify(matches[0].Key)
	if err != nil {
		return nil, fmt.Errorf("verify inner JWS: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	if iss, _ := claims["iss"].(string); iss != r.opts.Issuer {
		return nil, fmt.Errorf("iss mismatch: got %q want %q", iss, r.opts.Issuer)
	}
	return claims, nil
}
