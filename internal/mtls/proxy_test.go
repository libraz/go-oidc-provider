package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// mustParsePrefixes is the test-side wrapper around
// [mtls.ParseTrustedProxies]. It funnels the legacy "any source"
// posture (used by the existing proxy tests) onto the new explicit
// allow-list shape — every existing test pins a wide-open
// 0.0.0.0/0 + ::/0 prefix because those tests target the cert-
// parsing logic, not the proxy gating; the dedicated proxy-gating
// tests in proxy_trust_test.go cover the negative path.
func mustParsePrefixes(t testing.TB, cidrs ...string) []netip.Prefix {
	t.Helper()
	out, err := mtls.ParseTrustedProxies(cidrs)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v): %v", cidrs, err)
	}
	return out
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

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
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

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
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
	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
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

	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
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

	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
	if !errors.Is(err, mtls.ErrCertMalformed) {
		t.Errorf("err=%v want ErrCertMalformed", err)
	}
}

// TestCertificateFromRequest_ConflictOnTrustedProxy confirms that when a
// forwarding header is configured, the request arrives from a trusted
// proxy, AND both a handshake leaf and a header cert are present but
// DISAGREE, the function refuses with [mtls.ErrCertSourceConflict]
// instead of silently binding to one source. On a dual-mTLS / mesh hop
// the handshake leaf is the proxy's own client cert; binding to it would
// collapse the sender-constraint to the proxy.
func TestCertificateFromRequest_ConflictOnTrustedProxy(t *testing.T) {
	t.Parallel()

	handshake := generateLeaf(t)
	header := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{handshake}}
	req.Header.Set("X-Client-Cert", pemEncode(t, header))

	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
	if !errors.Is(err, mtls.ErrCertSourceConflict) {
		t.Errorf("err=%v want ErrCertSourceConflict (proxy handshake cert MUST NOT silently win over the forwarded cert)", err)
	}
}

// TestCertificateFromRequest_OnlyConfiguredHeaderHonoured pins the
// "exact-name match" property on the proxy header path: when the
// embedder configures [ProxyConfig.HeaderName], NO other header is
// ever consulted, even widely-deployed alternatives like
// "X-Forwarded-Client-Cert" (Envoy XFCC), "Ssl-Client-Cert" (nginx
// stream), or "X-SSL-Client-Cert" (haproxy). The package's contract
// is that ONE header name is trusted at a time, configured per
// deployment; admitting "well-known" alternatives "for convenience"
// is exactly the misconfiguration class that turns a reverse proxy
// into a cert-spoofing surface.
//
// Threat model (no single CVE; documented as a class in RFC 8705 §3
// and recurring in deployment guides for Envoy, nginx, haproxy,
// AWS ELB, Cloudflare):
//
//   - The OP runs behind a reverse proxy that strips and replaces
//     "X-Client-Cert" before passing the request to the OP. The
//     attacker cannot set "X-Client-Cert" because the proxy clobbers
//     it. But if the OP ALSO consulted "X-Forwarded-Client-Cert"
//     (which the proxy did NOT strip because it is not the chosen
//     name), an attacker could set XFCC on the inbound request and
//     spoof a client cert.
//   - Symmetric variant: an OP that adds case-insensitive matching
//     would let an attacker bypass a strict proxy strip rule by
//     setting "x-client-cert" (lowercase) — though Go's net/http
//     canonicalises header names so this is structurally closed,
//     the test pins the byte-equal expectation regardless.
//
// Defence: [CertificateFromRequest] consults exactly the header
// named in [ProxyConfig.HeaderName] via [http.Header.Get], which is
// canonicalised but does NOT alias to other names. Any deviation
// from "exact name, single header" surfaces here.
func TestCertificateFromRequest_OnlyConfiguredHeaderHonoured(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	pemBody := pemEncode(t, cert)

	// Deployment configures "X-Client-Cert". Every probe sets a
	// DIFFERENT header name to a valid PEM payload; the package MUST
	// return ErrNoClientCert on every one because none of them are
	// the configured name.
	probes := []string{
		"X-Forwarded-Client-Cert", // Envoy XFCC
		"Ssl-Client-Cert",         // nginx stream
		"X-SSL-Client-Cert",       // haproxy
		"X-ARR-ClientCert",        // IIS / Azure App Service
		"X-Client-Certificate",    // pluralised typo
		"Client-Cert",             // unprefixed
		"X-Forwarded-Cert",        // truncated
		"X-Client-Cert-Chain",     // chain variant
	}
	for _, headerName := range probes {
		t.Run(headerName, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
			req.Header.Set(headerName, pemBody)
			_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
			if !errors.Is(err, mtls.ErrNoClientCert) {
				t.Errorf("header %q: err=%v want ErrNoClientCert (only configured name MUST be honoured)",
					headerName, err)
			}
		})
	}
}

// TestCertificateFromRequest_NoTLSNoHeader_StillFailsClosed pins the
// belt-and-braces property: a request with neither TLS handshake nor
// the configured header MUST yield ErrNoClientCert, regardless of how
// many DECOY headers the attacker piles on. The test is structurally
// redundant with [TestCertificateFromRequest_OnlyConfiguredHeaderHonoured]
// but exists separately so a failure here pinpoints "no source at all"
// vs "wrong source consulted".
func TestCertificateFromRequest_NoTLSNoHeader_StillFailsClosed(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	pemBody := pemEncode(t, cert)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	// Pile on every plausible attacker header.
	for _, name := range []string{
		"X-Forwarded-Client-Cert",
		"Ssl-Client-Cert",
		"X-SSL-Client-Cert",
		"X-ARR-ClientCert",
		"X-Client-Cert", // even the canonical name — but config is empty.
	} {
		req.Header.Set(name, pemBody)
	}

	// Empty ProxyConfig: no header is trusted. TLS source is also
	// absent. MUST fail closed.
	_, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{})
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert; an unconfigured deployment must NOT trust any header", err)
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
