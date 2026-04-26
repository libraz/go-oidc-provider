package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// generateLeaf produces a self-signed leaf cert suitable for thumbprint
// tests. The key material is fresh ECDSA P-256 because the rest of the
// library (and FAPI 2.0) anchors on that curve.
//
// The function does NOT call time.Now: the NotBefore / NotAfter values
// are pinned to literal timestamps so the cert bytes are deterministic
// across runs of the test.
func generateLeaf(tb testing.TB) *x509.Certificate {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.testkit.invalid"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// TestThumbprint_MatchesRFC8705 pins the encoding to the §3.1 wire
// shape: base64url of SHA-256 over the DER bytes, no padding.
func TestThumbprint_MatchesRFC8705(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	got := mtls.Thumbprint(cert)
	if got == "" {
		t.Fatalf("Thumbprint must not be empty for a valid cert")
	}

	sum := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != want {
		t.Errorf("Thumbprint=%q want %q", got, want)
	}

	// base64url-no-pad has no "=" padding and uses "-" / "_" instead
	// of "+" / "/".
	for _, c := range got {
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			t.Errorf("Thumbprint character %q outside base64url alphabet", c)
		}
	}
}

// TestThumbprint_DistinctCertsProduceDistinctValues verifies the
// trivial collision-resistance expectation: two freshly generated
// certs hash to different values.
func TestThumbprint_DistinctCertsProduceDistinctValues(t *testing.T) {
	t.Parallel()

	a := mtls.Thumbprint(generateLeaf(t))
	b := mtls.Thumbprint(generateLeaf(t))
	if a == b {
		t.Errorf("Thumbprints collided across distinct certs: %q", a)
	}
}

// TestThumbprint_NilOrEmpty returns the empty string so the caller can
// guard the cnf assignment with a non-empty check rather than an
// explicit nil compare.
func TestThumbprint_NilOrEmpty(t *testing.T) {
	t.Parallel()

	if got := mtls.Thumbprint(nil); got != "" {
		t.Errorf("Thumbprint(nil)=%q want \"\"", got)
	}
	if got := mtls.Thumbprint(&x509.Certificate{}); got != "" {
		t.Errorf("Thumbprint(empty)=%q want \"\"", got)
	}
}
