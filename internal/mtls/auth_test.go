package mtls_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// generateLeafWith customises the cert template before issuance. The
// helper exists so tests can populate SAN fields without re-implementing
// the boilerplate.
func generateLeafWith(tb testing.TB, fn func(*x509.Certificate)) *x509.Certificate {
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
	if fn != nil {
		fn(tmpl)
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

// TestVerifyTLSClientAuth_SubjectDN_HappyPath matches the cert's
// subject string against the registered DN.
func TestVerifyTLSClientAuth_SubjectDN_HappyPath(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, func(c *x509.Certificate) {
		c.Subject = pkix.Name{
			CommonName:   "rp.example",
			Organization: []string{"Example Org"},
		}
	})
	if err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{
		SubjectDN: cert.Subject.String(),
	}); err != nil {
		t.Errorf("VerifyTLSClientAuth: %v", err)
	}
}

// TestVerifyTLSClientAuth_SubjectDN_Mismatch returns ErrSubjectMismatch
// when the configured DN does not equal the cert's.
func TestVerifyTLSClientAuth_SubjectDN_Mismatch(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "real.example"}
	})
	err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{
		SubjectDN: "CN=not-the-cert",
	})
	if !errors.Is(err, mtls.ErrSubjectMismatch) {
		t.Errorf("err=%v want ErrSubjectMismatch", err)
	}
}

// TestVerifyTLSClientAuth_SANDNS matches a registered DNS SAN (case-
// insensitive).
func TestVerifyTLSClientAuth_SANDNS(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"rp.example", "alt.example"}
	})
	if err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{
		SANDNS: "RP.EXAMPLE",
	}); err != nil {
		t.Errorf("VerifyTLSClientAuth: %v", err)
	}
}

// TestVerifyTLSClientAuth_SANURI matches a registered URI SAN.
func TestVerifyTLSClientAuth_SANURI(t *testing.T) {
	t.Parallel()

	expected := "spiffe://example.org/rp/1"
	parsed, err := url.Parse(expected)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	cert := generateLeafWith(t, func(c *x509.Certificate) {
		c.URIs = []*url.URL{parsed}
	})
	if err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{
		SANURI: expected,
	}); err != nil {
		t.Errorf("VerifyTLSClientAuth: %v", err)
	}
}

// TestVerifyTLSClientAuth_SANIP matches a registered IP SAN.
func TestVerifyTLSClientAuth_SANIP(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, func(c *x509.Certificate) {
		c.IPAddresses = []net.IP{net.ParseIP("203.0.113.5")}
	})
	if err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{
		SANIP: "203.0.113.5",
	}); err != nil {
		t.Errorf("VerifyTLSClientAuth: %v", err)
	}
}

// TestVerifyTLSClientAuth_SANEmail matches a registered email SAN.
func TestVerifyTLSClientAuth_SANEmail(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, func(c *x509.Certificate) {
		c.EmailAddresses = []string{"client@example.org"}
	})
	if err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{
		SANEmail: "Client@Example.Org",
	}); err != nil {
		t.Errorf("VerifyTLSClientAuth: %v", err)
	}
}

// TestVerifyTLSClientAuth_SubjectFallsThroughToSAN proves that a
// non-matching subject does not short-circuit the SAN attempts: the
// matcher considers any non-empty field a viable hit.
func TestVerifyTLSClientAuth_SubjectFallsThroughToSAN(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "literal"}
		c.DNSNames = []string{"rp.example"}
	})
	err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{
		SubjectDN: "CN=does-not-match",
		SANDNS:    "rp.example",
	})
	if err != nil {
		t.Errorf("VerifyTLSClientAuth: %v want nil (SAN fallback)", err)
	}
}

// TestVerifyTLSClientAuth_NoMatcher fails closed when the client
// metadata lacks every field.
func TestVerifyTLSClientAuth_NoMatcher(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, nil)
	err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{})
	if !errors.Is(err, mtls.ErrNoMatcherConfigured) {
		t.Errorf("err=%v want ErrNoMatcherConfigured", err)
	}
}

// TestVerifyTLSClientAuth_NilCert fails closed.
func TestVerifyTLSClientAuth_NilCert(t *testing.T) {
	t.Parallel()

	err := mtls.VerifyTLSClientAuth(nil, mtls.ClientMatcher{SubjectDN: "CN=any"})
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert", err)
	}
}

// jwksFromKeys serialises a JWK set containing each public key in keys.
func jwksFromKeys(tb testing.TB, keys ...crypto.PublicKey) []byte {
	tb.Helper()
	out := josev4.JSONWebKeySet{}
	for i, k := range keys {
		out.Keys = append(out.Keys, josev4.JSONWebKey{
			Key:   k,
			KeyID: keyIDFor(i),
			Use:   "sig",
		})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		tb.Fatalf("json.Marshal: %v", err)
	}
	return raw
}

func keyIDFor(i int) string {
	switch i {
	case 0:
		return "kid-0"
	case 1:
		return "kid-1"
	default:
		return "kid-n"
	}
}

// TestVerifySelfSigned_HappyPath matches a cert whose key is registered
// in the JWKS.
func TestVerifySelfSigned_HappyPath(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "self-signed"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	jwks := jwksFromKeys(t, &priv.PublicKey)
	if err := mtls.VerifySelfSignedTLSClientAuth(cert, jwks); err != nil {
		t.Errorf("VerifySelfSignedTLSClientAuth: %v", err)
	}
}

// TestVerifySelfSigned_NoMatchingKey rejects when the JWKS does not
// contain the cert's public key.
func TestVerifySelfSigned_NoMatchingKey(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, nil)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwks := jwksFromKeys(t, &other.PublicKey)
	err = mtls.VerifySelfSignedTLSClientAuth(cert, jwks)
	if !errors.Is(err, mtls.ErrNoMatchingJWK) {
		t.Errorf("err=%v want ErrNoMatchingJWK", err)
	}
}

// TestVerifySelfSigned_RSAKey accepts an RSA cert when the JWKS
// carries the matching RSA public key. The §2.2.2 path is alg-
// agnostic at the binding layer because the trust anchor is the JWK
// thumbprint, not the cert signature.
func TestVerifySelfSigned_RSAKey(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "rsa-self-signed"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	jwks := jwksFromKeys(t, &priv.PublicKey)
	if err := mtls.VerifySelfSignedTLSClientAuth(cert, jwks); err != nil {
		t.Errorf("VerifySelfSignedTLSClientAuth(RSA): %v", err)
	}
}

// TestVerifySelfSigned_MalformedJWKS surfaces a typed sentinel for
// unparseable JWKS bytes.
func TestVerifySelfSigned_MalformedJWKS(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, nil)
	err := mtls.VerifySelfSignedTLSClientAuth(cert, []byte("not json"))
	if !errors.Is(err, mtls.ErrJWKSMalformed) {
		t.Errorf("err=%v want ErrJWKSMalformed", err)
	}
}

// TestVerifySelfSigned_EmptyJWKS treats an empty payload as malformed
// (no keys can possibly match).
func TestVerifySelfSigned_EmptyJWKS(t *testing.T) {
	t.Parallel()

	cert := generateLeafWith(t, nil)
	err := mtls.VerifySelfSignedTLSClientAuth(cert, nil)
	if !errors.Is(err, mtls.ErrJWKSMalformed) {
		t.Errorf("err=%v want ErrJWKSMalformed", err)
	}
}

// TestVerifySelfSigned_NilCert fails closed.
func TestVerifySelfSigned_NilCert(t *testing.T) {
	t.Parallel()

	err := mtls.VerifySelfSignedTLSClientAuth(nil, []byte(`{"keys":[]}`))
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert", err)
	}
}
