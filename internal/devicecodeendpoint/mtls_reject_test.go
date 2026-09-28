// Package devicecodeendpoint_test (this file): a device-authorization
// request that presents an unusable mTLS client certificate must fail
// closed the same way the token endpoint does, instead of silently
// falling back to the unbound (bearer) path.
package devicecodeendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/devicecodeendpoint"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// generateLeaf returns a self-signed, client-auth-capable leaf
// certificate. It is never added to a trust pool, so a [mtls.Verifier]
// configured with any [mtls.VerifierConfig.RootCAs] rejects it as
// untrusted.
func generateLeaf(tb testing.TB) *x509.Certificate {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestHandlerRejectsUntrustedMTLSCertificate pins the fail-closed
// behaviour: a certificate that fails chain validation must surface as
// invalid_client, not be silently dropped into the unbound path. On
// the old code, extractMTLSThumbprint mapped ErrCertUntrusted to an
// empty thumbprint and the request would have succeeded with 200.
func TestHandlerRejectsUntrustedMTLSCertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_, deps := newFixture(t, now, store.Client{
		ID:                      "device-client",
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid"},
	})

	verifier, err := mtls.NewVerifier(mtls.VerifierConfig{RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatalf("mtls.NewVerifier: %v", err)
	}
	deps.MTLS = verifier

	form := url.Values{"client_id": {"device-client"}, "scope": {"openid"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{generateLeaf(t)}}

	rec := httptest.NewRecorder()
	devicecodeendpoint.Handler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s, want %d (invalid_client)", rec.Code, rec.Body.String(), http.StatusUnauthorized)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	if body.Error != "invalid_client" {
		t.Fatalf("error = %q, want invalid_client", body.Error)
	}
}

// TestHandlerRejectsMalformedMTLSCertificateHeader mirrors the
// [TestHandlerRejectsUntrustedMTLSCertificate] guard for the
// present-but-unparseable case: a trusted proxy forwarded a header
// that does not decode to a certificate at all. The old code
// collapsed this into the unbound path too.
func TestHandlerRejectsMalformedMTLSCertificateHeader(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_, deps := newFixture(t, now, store.Client{
		ID:                      "device-client",
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid"},
	})

	proxies, err := mtls.ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	verifier, err := mtls.NewVerifier(mtls.VerifierConfig{
		Proxy: mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: proxies},
	})
	if err != nil {
		t.Fatalf("mtls.NewVerifier: %v", err)
	}
	deps.MTLS = verifier

	form := url.Values{"client_id": {"device-client"}, "scope": {"openid"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Client-Cert", "not a certificate")
	req.RemoteAddr = "10.1.2.3:12345"

	rec := httptest.NewRecorder()
	devicecodeendpoint.Handler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want %d (invalid_request)", rec.Code, rec.Body.String(), http.StatusBadRequest)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	if body.Error != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", body.Error)
	}
}
