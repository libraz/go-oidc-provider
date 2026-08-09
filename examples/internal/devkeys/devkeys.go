//go:build example

// Package devkeys generates ephemeral cryptographic material for the
// example/* main.go files so each example does not duplicate the
// crypto/ecdsa + crypto/rand boilerplate. Every value is generated
// fresh at process start; restarting the example invalidates every
// session, code, and token in flight.
//
// Production embedders MUST NOT use this package. Real deployments
// load signing keys from a vault / KMS, persist the cookie key in a
// secret manager, and rotate the TOTP encryption key out-of-band.
// The package is gated behind the "example" build tag so it cannot
// be imported into production binaries by accident.
package devkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/libraz/go-oidc-provider/op"
)

// Material holds the cryptographic values typical example main.go
// files need at boot. Fields are populated by [MustEphemeral]; an
// example reads only the fields it actually needs.
type Material struct {
	// SigningKey is an ECDSA P-256 private key. Pair with KeyID to
	// build an [op.Keyset] entry; see [Material.Keyset].
	SigningKey *ecdsa.PrivateKey
	// KeyID is the JWS "kid" header value paired with SigningKey.
	KeyID string
	// CookieKey is a 32-byte AES-256-GCM key for the OP's session
	// cookie codec. Pass to [op.WithCookieKeys].
	CookieKey []byte
	// TOTPKey is a 32-byte AES-256-GCM key for at-rest encryption of
	// stored TOTP secrets. Pass to [op.StepTOTP.EncryptionKey] when
	// the example wires a TOTP factor.
	TOTPKey []byte
}

// MustEphemeral returns ephemeral cryptographic material with the
// supplied JWS kid. The function panics on any RNG failure because
// example main.go files cannot meaningfully recover from one.
//
//nolint:forbidigo // dev-only key material behind the example build tag: the Must* contract keeps example wiring free of branches for a failure that leaves nothing safe to boot with.
func MustEphemeral(keyID string) *Material {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("devkeys: generate signing key: %v", err))
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		panic(fmt.Sprintf("devkeys: generate cookie key: %v", err))
	}
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		panic(fmt.Sprintf("devkeys: generate TOTP key: %v", err))
	}
	return &Material{
		SigningKey: priv,
		KeyID:      keyID,
		CookieKey:  cookieKey,
		TOTPKey:    totpKey,
	}
}

// Keyset returns a one-entry [op.Keyset] over the SigningKey / KeyID
// pair. Most examples want exactly this shape; embedders that need
// rotation pass an additional previous key explicitly.
func (m *Material) Keyset() op.Keyset {
	return op.Keyset{{KeyID: m.KeyID, Signer: m.SigningKey}}
}
