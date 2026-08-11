package jarm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// fakeSigner is a stand-in [crypto.Signer] whose Public() returns a
// type the algorithm-derivation helper does not understand. The signer
// methods are unreachable because [jarm.NewSigner] rejects the key
// before any sign call.
type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey                                  { return struct{}{} }
func (fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

// TestNewSigner_RejectsUnsupportedKey closes the H-FAPI-2 vector by
// surfacing the misconfiguration at construction time. The OP signs
// with ECDSA P-256 only (see internal/keys.NewSet); other key shapes
// MUST fail [NewSigner] rather than reach Sign and emit a JWS with
// the wrong "alg" header.
func TestNewSigner_RejectsUnsupportedKey(t *testing.T) {
	t.Parallel()

	key := tokens.SigningKey{KeyID: "k1", Signer: fakeSigner{}}
	_, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    key,
		Issuer: "https://op.example.com",
	})
	if !errors.Is(err, jarm.ErrEncode) {
		t.Fatalf("err=%v want ErrEncode for unsupported key type", err)
	}
}

// TestNewSigner_RejectsNonP256ECDSA pins the project ES256-only stance
// for ECDSA keys: P-384 / P-521 keys must surface as a structured
// error at construction time rather than minting JWS with mismatched
// algorithm headers.
func TestNewSigner_RejectsNonP256ECDSA(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	_, err = jarm.NewSigner(jarm.SignerConfig{
		Key:    tokens.SigningKey{KeyID: "k1", Signer: priv},
		Issuer: "https://op.example.com",
	})
	if !errors.Is(err, jarm.ErrEncode) {
		t.Fatalf("err=%v want ErrEncode for P-384 ECDSA", err)
	}
}
