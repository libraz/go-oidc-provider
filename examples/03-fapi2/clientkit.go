//go:build example

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
)

// This file isolates the helpers that materialise client-side
// artefacts (a JWK Set the OP can inline on the client record, and a
// PKCS#8 PEM the operator hands to whatever JWT signer drives the
// private_key_jwt assertions). The OP wiring in main.go calls these
// once at startup; keeping them on a sibling file lets the OP
// configuration stay readable as a single screen.

// publicJWKSetJSON encodes pub as the inline JWK Set JSON the OIDC
// Dynamic Client Registration 1.0 §2 "jwks" field accepts. The set
// carries a single entry whose "kid" matches [demoClientKID] so the
// JAR / private_key_jwt verifiers can discriminate when a client
// rotates keys later.
func publicJWKSetJSON(pub *ecdsa.PublicKey) ([]byte, error) {
	type jwk struct {
		KTY string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Use string `json:"use"`
		KID string `json:"kid"`
		Alg string `json:"alg"`
	}
	type jwkSet struct {
		Keys []jwk `json:"keys"`
	}
	return json.Marshal(jwkSet{Keys: []jwk{{
		KTY: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		Use: "sig",
		KID: demoClientKID,
		Alg: "ES256",
	}}})
}

// encodeECPrivateKeyPEM marshals priv as a PKCS#8-shaped PEM block so
// the user can save it and feed it to a JWT signer of their choice.
// The example does not pin a specific JWT library; any ECDSA P-256
// signer reading PKCS#8 will produce assertions the OP accepts.
func encodeECPrivateKeyPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
