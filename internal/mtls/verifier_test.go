package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
