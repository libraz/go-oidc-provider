package jarm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// fakeSigner is a stand-in [crypto.Signer] whose Public() returns a
// type the algorithm-derivation helper does not understand. The signer
// methods are unreachable because [jarm.NewSigner] rejects the key
// before any sign call.
type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey                                  { return struct{}{} }
func (fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

// TestNewSigner_RejectsUnsupportedKey surfaces the misconfiguration at
// construction time: a key shape the OP does not sign with MUST fail
// [NewSigner] rather than reach Sign and emit a JWS with the wrong "alg"
// header.
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

// TestNewSigner_RejectsNonP256ECDSA pins that ECDSA keys other than
// P-256 surface as a structured error at construction time rather than
// minting JWS with mismatched algorithm headers.
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

// TestSigner_RS256Key pins that an RSA signing key yields an RS256 JARM
// response that verifies against the key's public half.
func TestSigner_RS256Key(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateRS256("jarm-rsa-kid")
	if err != nil {
		t.Fatalf("GenerateRS256: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    tokens.SigningKey{KeyID: entry.KeyID, Signer: entry.Signer},
		Issuer: "https://op.example.com",
		Clock:  fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	raw, err := signer.SignDefault(jarm.Payload{Audience: "client-1", Code: "code-1"})
	if err != nil {
		t.Fatalf("SignDefault: %v", err)
	}
	parsed, err := josev4.ParseSignedCompact(raw, []josev4.SignatureAlgorithm{josev4.RS256, josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSignedCompact: %v", err)
	}
	hdr := parsed.Signatures[0].Header
	if hdr.Algorithm != "RS256" {
		t.Errorf("alg=%q want RS256", hdr.Algorithm)
	}
	if hdr.KeyID != entry.KeyID {
		t.Errorf("kid=%q want %q", hdr.KeyID, entry.KeyID)
	}
	if _, err := parsed.Verify(entry.Signer.Public()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
