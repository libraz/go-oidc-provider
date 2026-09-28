package op_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrimaryPasskey_AAGUIDAllowlistRequiresAttestationRoots pins that
// op.New refuses an authenticator-model allowlist with no trust anchors
// to verify attestation chains against, and a nil anchor.
func TestPrimaryPasskey_AAGUIDAllowlistRequiresAttestationRoots(t *testing.T) {
	t.Parallel()

	root := selfSignedRoot(t)
	step := func(st *inmem.Store, roots []*x509.Certificate) op.PrimaryPasskey {
		return op.PrimaryPasskey{
			Store:            st.Passkeys(),
			RPID:             "id.example.com",
			RPDisplayName:    "Example",
			RPOrigins:        []string{"https://id.example.com"},
			AAGUIDAllowlist:  []string{"fbfc3007-154e-4ecc-8c0b-6e020557d7bd"},
			AttestationRoots: roots,
		}
	}

	cases := []struct {
		name       string
		roots      []*x509.Certificate
		wantSubstr string
	}{
		{name: "no roots", wantSubstr: "PrimaryPasskey.AAGUIDAllowlist requires AttestationRoots"},
		{name: "nil root", roots: []*x509.Certificate{root, nil}, wantSubstr: "PrimaryPasskey.AttestationRoots[1] is nil"},
		{name: "configured root", roots: []*x509.Certificate{root}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := inmem.New()
			opts := append(validBaseOptsWithStoreNoAuthn(t, st), op.WithLoginFlow(op.LoginFlow{Primary: step(st, tc.roots)}))
			_, err := op.New(opts...)
			if tc.wantSubstr == "" {
				if err != nil {
					t.Fatalf("op.New: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("op.New: accepted, want an error containing %q", tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("op.New: error %q does not contain %q", err.Error(), tc.wantSubstr)
			}
			var typed *op.Error
			if !errors.As(err, &typed) {
				t.Fatalf("op.New: error %T is not *op.Error", err)
			}
		})
	}
}

// selfSignedRoot mints a CA certificate to stand in for a vendor
// attestation root.
func selfSignedRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Vendor Attestation Root"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	return cert
}
