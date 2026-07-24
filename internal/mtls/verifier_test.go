package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// TestVerifier_ThumbprintFromRequest_TLSPath returns the thumbprint
// of the leaf cert presented at the TLS handshake.
func TestVerifier_ThumbprintFromRequest_TLSPath(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got, err := v.ThumbprintFromRequest(req)
	if err != nil {
		t.Fatalf("ThumbprintFromRequest: %v", err)
	}
	if got != mtls.Thumbprint(cert) {
		t.Errorf("thumbprint mismatch")
	}
}

func TestVerifier_CertificateFromRequest_RootCAsRejectsUntrustedLeaf(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	roots := x509.NewCertPool()
	v, err := mtls.NewVerifier(mtls.VerifierConfig{RootCAs: roots})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	_, err = v.CertificateFromRequest(req)
	if !errors.Is(err, mtls.ErrCertUntrusted) {
		t.Fatalf("err=%v want ErrCertUntrusted", err)
	}
}

func TestVerifier_CertificateFromRequest_RootCAsAcceptsTrustedLeaf(t *testing.T) {
	t.Parallel()

	ca, leaf := generateCATrustedLeaf(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{RootCAs: roots})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

	got, err := v.CertificateFromRequest(req)
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if got != leaf {
		t.Fatal("CertificateFromRequest returned a different certificate pointer")
	}
}

// TestVerifier_TrustedProxyValidatesForwardedClientNotTransport proves
// RootCAs applies to the selected OAuth client identity, not to the
// unrelated certificate that authenticated the proxy-to-OP transport.
func TestVerifier_TrustedProxyValidatesForwardedClientNotTransport(t *testing.T) {
	t.Parallel()

	clientCA, clientLeaf := generateCATrustedLeaf(t)
	proxyLeaf := generateLeaf(t)
	roots := x509.NewCertPool()
	roots.AddCert(clientCA)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{
		Proxy: mtls.ProxyConfig{
			HeaderName:     "X-Client-Cert",
			TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24"),
		},
		RootCAs: roots,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{proxyLeaf}}
	req.Header.Set("X-Client-Cert", pemEncode(t, clientLeaf))
	got, err := v.CertificateFromRequest(req)
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(clientLeaf) {
		t.Fatal("verifier returned the proxy transport certificate")
	}
}

// TestVerifier_TrustedProxyCannotSubstituteTrustedTransportForUntrustedClient
// closes the inverse case: trusting the proxy's TLS certificate does not
// make a tampered or otherwise untrusted forwarded client leaf acceptable.
func TestVerifier_TrustedProxyCannotSubstituteTrustedTransportForUntrustedClient(t *testing.T) {
	t.Parallel()

	proxyCA, proxyLeaf := generateCATrustedLeaf(t)
	untrustedClientLeaf := generateLeaf(t)
	roots := x509.NewCertPool()
	roots.AddCert(proxyCA)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{
		Proxy: mtls.ProxyConfig{
			HeaderName:     "X-Client-Cert",
			TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24"),
		},
		RootCAs: roots,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{proxyLeaf}}
	req.Header.Set("X-Client-Cert", pemEncode(t, untrustedClientLeaf))
	_, err = v.CertificateFromRequest(req)
	if !errors.Is(err, mtls.ErrCertUntrusted) {
		t.Fatalf("err=%v want ErrCertUntrusted", err)
	}
}

// TestVerifier_ThumbprintFromRequest_NoCert returns ErrNoClientCert
// when neither source produces a cert.
func TestVerifier_ThumbprintFromRequest_NoCert(t *testing.T) {
	t.Parallel()

	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	_, err = v.ThumbprintFromRequest(req)
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert", err)
	}
}

// TestVerifier_VerifyBoundRequest_HappyPath accepts a request whose
// presented cert hashes to the bound thumbprint.
func TestVerifier_VerifyBoundRequest_HappyPath(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	if err := v.VerifyBoundRequest(req, mtls.Thumbprint(cert)); err != nil {
		t.Errorf("VerifyBoundRequest: %v", err)
	}
}

// TestVerifier_VerifyBoundRequest_Mismatch rejects a request whose
// presented cert is not the bound one.
func TestVerifier_VerifyBoundRequest_Mismatch(t *testing.T) {
	t.Parallel()

	bound := generateLeaf(t)
	other := generateLeaf(t)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}}

	err = v.VerifyBoundRequest(req, mtls.Thumbprint(bound))
	if !errors.Is(err, mtls.ErrThumbprintMismatch) {
		t.Errorf("err=%v want ErrThumbprintMismatch", err)
	}
}

// TestVerifier_VerifyBoundRequest_NoCert surfaces ErrNoClientCert
// when the request did not present any cert at all but the token
// claims a binding.
func TestVerifier_VerifyBoundRequest_NoCert(t *testing.T) {
	t.Parallel()

	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	err = v.VerifyBoundRequest(req, "abc")
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert", err)
	}
}

// TestVerifier_VerifyBoundRequest_EmptyBoundFailsClosed defends
// against accidentally calling the helper when no binding exists.
func TestVerifier_VerifyBoundRequest_EmptyBoundFailsClosed(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/userinfo", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	err = v.VerifyBoundRequest(req, "")
	if !errors.Is(err, mtls.ErrThumbprintMismatch) {
		t.Errorf("err=%v want ErrThumbprintMismatch (empty bound thumbprint)", err)
	}
}

func generateCATrustedLeaf(tb testing.TB) (*x509.Certificate, *x509.Certificate) {
	tb.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("Generate CA key: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("Generate leaf key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("Create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatalf("Parse CA: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("Create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		tb.Fatalf("Parse leaf: %v", err)
	}
	return ca, leaf
}
