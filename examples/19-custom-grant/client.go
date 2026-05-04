//go:build example

// client.go — embedder service-side wiring for example 19-custom-grant.
//
// This file simulates the backend service that mints the inbound
// service_token JWS the OP's custom-grant handler verifies. In a real
// deployment this code lives inside the embedder's service binary, the
// signing key is held by a KMS, and the JWS travels over a mutually
// authenticated channel to the OP's /token endpoint. Here it runs in
// the same process as the OP so the example is self-contained.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// newServiceKey generates the ephemeral ES256 keypair the demo uses to
// sign and verify service tokens. The pair is unrelated to the OP's
// own signing keyset — the whole point of the example is that the
// embedder's trust anchor is independent of the OP's.
func newServiceKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// signServiceToken builds and signs a compact-serialised JWS with
// alg=ES256 over a minimal claim set (iss/sub/aud/iat/exp/nbf/jti).
// The demo backend service would normally sign through its KMS; here
// the keypair is held in-process so the example stays single-binary.
func signServiceToken(priv *ecdsa.PrivateKey, now time.Time) (string, error) {
	header := map[string]string{"alg": "ES256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": "service-issuer",
		"sub": serviceSubject,
		"aud": serviceTokenAudience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(serviceTokenTTL).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	// RFC 7518 §3.4: ES256 signatures are the fixed-width
	// concatenation of R and S, each padded to 32 bytes.
	const coordLen = 32
	sig := make([]byte, 2*coordLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[coordLen-len(rBytes):coordLen], rBytes)
	copy(sig[2*coordLen-len(sBytes):], sBytes)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
