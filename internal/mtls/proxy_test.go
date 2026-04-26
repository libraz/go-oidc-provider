package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// pemEncode wraps cert.Raw in a PEM "CERTIFICATE" block. Tests use it
// to fabricate the header payload a reverse proxy would forward.
func pemEncode(tb testing.TB, cert *x509.Certificate) string {
	tb.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return string(pem.EncodeToMemory(block))
}

// TestCertificateFromRequest_TLSHandshake takes the leaf out of
// [http.Request.TLS] when one is present.
func TestCertificateFromRequest_TLSHandshake(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{})
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(cert) {
		t.Errorf("returned cert thumbprint differs from input")
	}
}

// TestCertificateFromRequest_LeafOnly confirms the function returns
// the *first* peer certificate when the proxy presents a chain.
func TestCertificateFromRequest_LeafOnly(t *testing.T) {
	t.Parallel()

	leaf := generateLeaf(t)
	intermediate := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, intermediate},
	}

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{})
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(leaf) {
		t.Errorf("expected leaf, got intermediate")
	}
}

// TestCertificateFromRequest_HeaderPath consumes the cert from the
// configured proxy header when no TLS handshake cert is present.
func TestCertificateFromRequest_HeaderPath(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert"})
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(cert) {
		t.Errorf("returned cert thumbprint differs from input")
	}
}

// TestCertificateFromRequest_HeaderURLEncoded accepts a percent-
// encoded payload (the shape nginx ssl_client_escaped_cert emits).
func TestCertificateFromRequest_HeaderURLEncoded(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.Header.Set("X-Client-Cert", url.QueryEscape(pemEncode(t, cert)))

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert"})
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(cert) {
		t.Errorf("returned cert thumbprint differs from input")
	}
}

// TestCertificateFromRequest_NoCert returns ErrNoClientCert when
// neither source yields a cert.
func TestCertificateFromRequest_NoCert(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert"})
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert", err)
	}
}

// TestCertificateFromRequest_HeaderDisabled refuses to consult any
// header when ProxyConfig.HeaderName is empty: an inbound request
// would otherwise spoof a cert by setting an arbitrary header.
func TestCertificateFromRequest_HeaderDisabled(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{})
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert (header path disabled)", err)
	}
}

// TestCertificateFromRequest_MalformedHeader returns ErrCertMalformed
// when the header is present but does not contain a parseable cert.
func TestCertificateFromRequest_MalformedHeader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.Header.Set("X-Client-Cert", "not a pem block")

	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert"})
	if !errors.Is(err, mtls.ErrCertMalformed) {
		t.Errorf("err=%v want ErrCertMalformed", err)
	}
}

// TestCertificateFromRequest_WrongPEMType refuses payloads whose PEM
// block is something other than CERTIFICATE (e.g. a private key).
func TestCertificateFromRequest_WrongPEMType(t *testing.T) {
	t.Parallel()

	bogus := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.Header.Set("X-Client-Cert", string(bogus))

	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert"})
	if !errors.Is(err, mtls.ErrCertMalformed) {
		t.Errorf("err=%v want ErrCertMalformed", err)
	}
}

// TestCertificateFromRequest_PrefersHandshake confirms that when both
// a TLS handshake cert AND a header cert are present, the handshake
// wins. This protects against an attacker who controls only the
// header (e.g. by sneaking it past a misconfigured proxy).
func TestCertificateFromRequest_PrefersHandshake(t *testing.T) {
	t.Parallel()

	handshake := generateLeaf(t)
	header := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{handshake}}
	req.Header.Set("X-Client-Cert", pemEncode(t, header))

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert"})
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(handshake) {
		t.Errorf("expected handshake cert to win over header cert")
	}
}

// TestCertificateFromRequest_NilRequest fails closed.
func TestCertificateFromRequest_NilRequest(t *testing.T) {
	t.Parallel()

	_, err := mtls.CertificateFromRequest(nil, mtls.ProxyConfig{})
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert for nil request", err)
	}
}
