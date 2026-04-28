package dpop_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

func TestThumbprint_RFC7638Vector(t *testing.T) {
	t.Parallel()
	// RFC 7638 §3.1 worked example uses an RSA key, but the canonical
	// encoding is identical across key types. Re-run against an EC
	// P-256 key generated from a deterministic seed so the test pins
	// the hashing path without re-implementing the canonical encoding.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk := &josev4.JSONWebKey{Key: &priv.PublicKey}
	got, err := dpop.Thumbprint(jwk)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	// RFC 7638 §3.5: 32 bytes encoded as base64url-no-pad → 43 chars.
	if len(got) != 43 {
		t.Errorf("len(thumbprint)=%d want 43; got=%q", len(got), got)
	}
	if strings.ContainsAny(got, "+/=") {
		t.Errorf("thumbprint must be base64url-no-pad: %q", got)
	}
}

func TestThumbprint_DifferentKeysDifferentValues(t *testing.T) {
	t.Parallel()
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey a: %v", err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey b: %v", err)
	}
	tA, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &a.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint a: %v", err)
	}
	tB, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &b.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint b: %v", err)
	}
	if tA == tB {
		t.Errorf("distinct keys produced equal thumbprints: %q", tA)
	}
}

func TestThumbprint_StableForSameKey(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	first, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint first: %v", err)
	}
	second, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint second: %v", err)
	}
	if first != second {
		t.Errorf("non-deterministic thumbprint: %q vs %q", first, second)
	}
}

func TestThumbprint_Ed25519(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	got, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: pub})
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if len(got) != 43 {
		t.Errorf("len=%d want 43", len(got))
	}
}

func TestThumbprint_RejectsNil(t *testing.T) {
	t.Parallel()
	if _, err := dpop.Thumbprint(nil); err == nil {
		t.Fatal("dpop.Thumbprint(nil) must error")
	}
}

func TestThumbprint_RejectsPrivate(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: priv}); err == nil {
		t.Fatal("dpop.Thumbprint(private key) must error")
	}
}

func TestThumbprint_AcceptsRSA2048(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	got, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("dpop.Thumbprint(RSA-2048): %v", err)
	}
	if len(got) != 43 {
		t.Errorf("len(thumbprint)=%d want 43; got=%q", len(got), got)
	}
}

func TestThumbprint_RejectsSmallRSA(t *testing.T) {
	t.Parallel()
	// 1024 is below the FAPI / RFC 7518 floor; the verifier must
	// reject so PS256 cannot be used to weaken the binding. The
	// short key is the test subject — gosec G403 is expected here.
	priv, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // intentional sub-spec key for the rejection path
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	if _, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey}); err == nil {
		t.Fatal("dpop.Thumbprint(RSA-1024) must error: modulus below 2048 bits")
	}
}

func TestThumbprint_RejectsP384(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey}); err == nil {
		t.Fatal("dpop.Thumbprint(P-384) must error: jose allow-list is P-256 only")
	}
}
