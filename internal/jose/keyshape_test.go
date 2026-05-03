package jose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// mustECDSA returns a freshly-generated ECDSA private key on curve. The
// helper exists so the table-driven test below stays focused on the
// matrix rather than key-generation noise.
func mustECDSA(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(%s): %v", curve.Params().Name, err)
	}
	return priv
}

// mustRSA returns a freshly-generated RSA key of the given modulus
// size. Used for both the ≥2048 accepted path and the <2048 rejected
// path; gosec does not fire here because the size is a non-literal
// parameter (gosec G403 only inspects integer literals).
func mustRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	return priv
}

// TestKeyShape_Table is the canonical alg/kty/crv mapping pinned in one
// place. The accepted rows mirror RFC 7518 §3.1 (RS256, ES256, ES384,
// ES512) and RFC 8037 §3.1 (EdDSA); the rejected rows guard against the
// drift bug the consolidation is fixing — silently admitting Ed448 or a
// 1024-bit RSA key would let one verifier accept what another rejects.
func TestKeyShape_Table(t *testing.T) {
	t.Parallel()

	rsa2048 := mustRSA(t, 2048)
	rsa1024 := mustRSA(t, 1024)
	ec256 := mustECDSA(t, elliptic.P256())
	ec384 := mustECDSA(t, elliptic.P384())
	ec521 := mustECDSA(t, elliptic.P521())
	ec224 := mustECDSA(t, elliptic.P224())
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	cases := []struct {
		name    string
		key     crypto.PublicKey
		wantOK  bool
		wantAlg string
		wantKty string
		wantCrv string
	}{
		{name: "RSA 2048", key: &rsa2048.PublicKey, wantOK: true, wantAlg: "RS256", wantKty: "RSA"},
		{name: "ECDSA P-256", key: &ec256.PublicKey, wantOK: true, wantAlg: "ES256", wantKty: "EC", wantCrv: "P-256"},
		{name: "ECDSA P-384", key: &ec384.PublicKey, wantOK: true, wantAlg: "ES384", wantKty: "EC", wantCrv: "P-384"},
		{name: "ECDSA P-521", key: &ec521.PublicKey, wantOK: true, wantAlg: "ES512", wantKty: "EC", wantCrv: "P-521"},
		{name: "Ed25519", key: edPub, wantOK: true, wantAlg: "EdDSA", wantKty: "OKP", wantCrv: "Ed25519"},

		{name: "RSA 1024 rejected", key: &rsa1024.PublicKey, wantOK: false},
		{name: "ECDSA P-224 rejected", key: &ec224.PublicKey, wantOK: false},
		{name: "nil rejected", key: nil, wantOK: false},
		{name: "garbage struct rejected", key: struct{}{}, wantOK: false},
		{name: "ed25519 wrong length rejected", key: ed25519.PublicKey(make([]byte, 16)), wantOK: false},
		{name: "nil rsa pointer rejected", key: (*rsa.PublicKey)(nil), wantOK: false},
		{name: "nil ecdsa pointer rejected", key: (*ecdsa.PublicKey)(nil), wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			alg, kty, crv, ok := jose.KeyShape(tc.key)
			if ok != tc.wantOK {
				t.Fatalf("KeyShape ok=%v, want %v (alg=%q kty=%q crv=%q)", ok, tc.wantOK, alg, kty, crv)
			}
			if !tc.wantOK {
				return
			}
			if alg != tc.wantAlg {
				t.Errorf("alg=%q want %q", alg, tc.wantAlg)
			}
			if kty != tc.wantKty {
				t.Errorf("kty=%q want %q", kty, tc.wantKty)
			}
			if crv != tc.wantCrv {
				t.Errorf("crv=%q want %q", crv, tc.wantCrv)
			}
		})
	}
}

// TestAssertAlgKeyShape_RejectsMismatch pins the alg/key pairing gate.
// RS256 and PS256 share the *rsa.PublicKey shape; the EC and Ed25519
// algorithms each pair to exactly one shape. A garbage alg or a nil key
// must surface [jose.ErrUnsupportedKeyShape] so callers branch on it
// via [errors.Is].
func TestAssertAlgKeyShape_RejectsMismatch(t *testing.T) {
	t.Parallel()

	rsaKey := &mustRSA(t, 2048).PublicKey
	ec256Key := &mustECDSA(t, elliptic.P256()).PublicKey
	ec384Key := &mustECDSA(t, elliptic.P384()).PublicKey
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	type row struct {
		name    string
		alg     string
		key     crypto.PublicKey
		wantErr bool
	}
	cases := []row{
		{name: "RS256+RSA accepted", alg: "RS256", key: rsaKey, wantErr: false},
		{name: "PS256+RSA accepted", alg: "PS256", key: rsaKey, wantErr: false},
		{name: "ES256+P256 accepted", alg: "ES256", key: ec256Key, wantErr: false},
		{name: "ES384+P384 accepted", alg: "ES384", key: ec384Key, wantErr: false},
		{name: "EdDSA+ed25519 accepted", alg: "EdDSA", key: edPub, wantErr: false},

		{name: "RS256+EC rejected", alg: "RS256", key: ec256Key, wantErr: true},
		{name: "PS256+ed25519 rejected", alg: "PS256", key: edPub, wantErr: true},
		{name: "ES256+RSA rejected", alg: "ES256", key: rsaKey, wantErr: true},
		{name: "ES256+P384 rejected", alg: "ES256", key: ec384Key, wantErr: true},
		{name: "EdDSA+RSA rejected", alg: "EdDSA", key: rsaKey, wantErr: true},

		{name: "empty alg rejected", alg: "", key: ec256Key, wantErr: true},
		{name: "unknown alg rejected", alg: "HS256", key: ec256Key, wantErr: true},
		{name: "nil key rejected", alg: "ES256", key: nil, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := jose.AssertAlgKeyShape(tc.alg, tc.key)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("AssertAlgKeyShape(%q, %T) returned nil; want error", tc.alg, tc.key)
				}
				if !errors.Is(err, jose.ErrUnsupportedKeyShape) {
					t.Errorf("err=%v; want errors.Is(ErrUnsupportedKeyShape)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("AssertAlgKeyShape(%q, %T) err=%v; want nil", tc.alg, tc.key, err)
			}
		})
	}
}
