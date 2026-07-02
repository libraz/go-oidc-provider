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

// TestParseTrustedProxies_RejectsMalformed pins the construction-time
// guard: a malformed CIDR / IP literal MUST fail [ParseTrustedProxies]
// so the embedder cannot drop a bad entry into [ProxyConfig.TrustedProxies]
// and silently widen the allow-list to "no source at all".
func TestParseTrustedProxies_RejectsMalformed(t *testing.T) {
	t.Parallel()

	cases := []string{
		"not-a-cidr",
		"10.0.0.0/33",      // mask too large for IPv4
		"::1/200",          // mask too large for IPv6
		"10.0.0.0/8/extra", // double-slash garbage
		"",                 // empty string
		"300.300.300.300",  // each octet out of range
		"fe80::zz",         // bad IPv6 hex
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := mtls.ParseTrustedProxies([]string{raw}); err == nil {
				t.Errorf("ParseTrustedProxies(%q) accepted; want error", raw)
			}
		})
	}
}

// TestParseTrustedProxies_AcceptsCIDRandBareIP confirms both the
// "10.0.0.0/8" and the convenience "10.0.0.1" (no mask) shapes parse.
// Embedders pinning a single proxy IP often forget the /32; the helper
// promotes the bare form to the host-mask prefix.
func TestParseTrustedProxies_AcceptsCIDRandBareIP(t *testing.T) {
	t.Parallel()

	prefixes, err := mtls.ParseTrustedProxies([]string{"10.0.0.0/8", "192.168.1.1", "::1", "fd00::/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if len(prefixes) != 4 {
		t.Fatalf("len(prefixes)=%d want 4", len(prefixes))
	}
	if prefixes[1].Bits() != 32 {
		t.Errorf("bare IPv4 prefix bits=%d want 32", prefixes[1].Bits())
	}
	if prefixes[2].Bits() != 128 {
		t.Errorf("bare IPv6 prefix bits=%d want 128", prefixes[2].Bits())
	}
}

// TestCertificateFromRequest_TrustedProxyHonoured covers the happy
// path: a request whose RemoteAddr lies inside a configured prefix
// MUST consume the cert from the header.
func TestCertificateFromRequest_TrustedProxyHonoured(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "10.0.0.0/8"),
	}
	got, err := mtls.CertificateFromRequest(req, cfg)
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(cert) {
		t.Errorf("returned cert thumbprint differs from input")
	}
}

// TestCertificateFromRequest_UntrustedSourceIgnoresHeader closes the
// H-FAPI-1 vector: an attacker who reaches the OP directly (bypassing
// the reverse proxy) MUST NOT be able to forge a client cert by setting
// the proxy header. The function returns [ErrNoClientCert] — the same
// sentinel as the "no header" path — so the wire response is
// indistinguishable from a missing source.
func TestCertificateFromRequest_UntrustedSourceIgnoresHeader(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	// Attacker reaches the OP from the public internet; the proxy
	// would have terminated upstream and rewritten the header, but
	// the attacker bypasses the proxy entirely.
	req.RemoteAddr = "203.0.113.7:55555"
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "10.0.0.0/8"),
	}
	_, err := mtls.CertificateFromRequest(req, cfg)
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert (untrusted source MUST NOT spoof cert)", err)
	}
}

// TestCertificateFromRequest_HeaderWithoutTrustedProxiesRejects pins
// the configuration-time guard: an embedder who sets HeaderName but
// forgets to populate TrustedProxies MUST get the safe-by-default
// behaviour of "header path disabled", not "header path open to every
// source".
func TestCertificateFromRequest_HeaderWithoutTrustedProxiesRejects(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	cfg := mtls.ProxyConfig{HeaderName: "X-Client-Cert"} // empty TrustedProxies
	_, err := mtls.CertificateFromRequest(req, cfg)
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert (HeaderName without TrustedProxies MUST fail closed)", err)
	}
}

// TestCertificateFromRequest_HeaderPrecedenceOverProxyHandshake pins the
// dual-mTLS / mesh fix: when the forwarding header is configured and the
// request arrives from a trusted proxy, a handshake leaf that DISAGREES
// with the forwarded cert MUST NOT be silently bound. The internal
// handshake carries the proxy's OWN client cert; binding to it would
// collapse the sender-constraint to the proxy's thumbprint. The function
// refuses with [ErrCertSourceConflict] instead of picking a source.
func TestCertificateFromRequest_HeaderPrecedenceOverProxyHandshake(t *testing.T) {
	t.Parallel()

	proxyCert := generateLeaf(t)  // proxy's own client cert on the internal hop
	clientCert := generateLeaf(t) // the real client cert forwarded in the header
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "10.0.0.5:54321"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{proxyCert}}
	req.Header.Set("X-Client-Cert", pemEncode(t, clientCert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "10.0.0.0/8"),
	}
	_, err := mtls.CertificateFromRequest(req, cfg)
	if !errors.Is(err, mtls.ErrCertSourceConflict) {
		t.Fatalf("err=%v want ErrCertSourceConflict (proxy handshake cert MUST NOT silently win)", err)
	}
}

// TestCertificateFromRequest_HeaderCertBindsWhenHandshakeAbsent proves the
// forwarded cert is what the binding uses on the trusted-proxy path when
// the internal hop presents no client cert of its own.
func TestCertificateFromRequest_HeaderCertBindsWhenHandshakeAbsent(t *testing.T) {
	t.Parallel()

	clientCert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Header.Set("X-Client-Cert", pemEncode(t, clientCert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "10.0.0.0/8"),
	}
	got, err := mtls.CertificateFromRequest(req, cfg)
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(clientCert) {
		t.Errorf("bound cert is not the forwarded header cert")
	}
}

// TestCertificateFromRequest_HeaderMatchingHandshakeAccepted covers the
// benign case where the proxy re-presents the same cert on both channels:
// the thumbprints agree, so there is no conflict and the forwarded cert is
// returned.
func TestCertificateFromRequest_HeaderMatchingHandshakeAccepted(t *testing.T) {
	t.Parallel()

	clientCert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "10.0.0.5:54321"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
	req.Header.Set("X-Client-Cert", pemEncode(t, clientCert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "10.0.0.0/8"),
	}
	got, err := mtls.CertificateFromRequest(req, cfg)
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(clientCert) {
		t.Errorf("bound cert differs from the presented cert")
	}
}

// TestCertificateFromRequest_NoHeaderConfiguredHandshakeUnchanged is the
// regression guard for the default OFCS / op-demo config: with no
// forwarding header configured, the handshake leaf is returned verbatim
// even if the request happens to carry a (non-configured) cert header.
// This is the byte-identical direct-TLS path.
func TestCertificateFromRequest_NoHeaderConfiguredHandshakeUnchanged(t *testing.T) {
	t.Parallel()

	handshakeCert := generateLeaf(t)
	strayCert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "10.0.0.5:54321"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{handshakeCert}}
	// A stray header MUST be ignored because cfg.HeaderName is unset.
	req.Header.Set("X-Client-Cert", pemEncode(t, strayCert))

	cfg := mtls.ProxyConfig{} // default: direct-TLS only
	got, err := mtls.CertificateFromRequest(req, cfg)
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(handshakeCert) {
		t.Errorf("default path did not return the handshake cert")
	}
}

// TestCertificateFromRequest_UntrustedSourceHandshakeStillWins confirms
// that when a header is configured but the request did NOT arrive from a
// trusted proxy, the header is ignored and the direct handshake leaf is
// returned unchanged (a direct client cannot spoof, and a legitimate
// direct-TLS client is still honoured).
func TestCertificateFromRequest_UntrustedSourceHandshakeStillWins(t *testing.T) {
	t.Parallel()

	handshakeCert := generateLeaf(t)
	strayCert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "203.0.113.7:55555" // outside the allow-list
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{handshakeCert}}
	req.Header.Set("X-Client-Cert", pemEncode(t, strayCert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "10.0.0.0/8"),
	}
	got, err := mtls.CertificateFromRequest(req, cfg)
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(handshakeCert) {
		t.Errorf("untrusted-source path did not return the handshake cert")
	}
}

// TestCertificateFromRequest_IPv6TrustedProxyHonoured exercises the
// IPv6 branch of [remoteIsTrusted]. The fixture uses a bracketed IPv6
// "host:port" form because that is what [http.Server] writes into
// [http.Request.RemoteAddr] for IPv6 connections.
func TestCertificateFromRequest_IPv6TrustedProxyHonoured(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "[fd00::1]:55555"
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "fd00::/8"),
	}
	got, err := mtls.CertificateFromRequest(req, cfg)
	if err != nil {
		t.Fatalf("CertificateFromRequest (IPv6 trusted): %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(cert) {
		t.Errorf("returned cert thumbprint differs from input")
	}
}

// TestCertificateFromRequest_IPv6UntrustedRejects mirrors the IPv4
// negative case for IPv6 sources.
func TestCertificateFromRequest_IPv6UntrustedRejects(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "[2001:db8::1]:55555"
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "fd00::/8"),
	}
	_, err := mtls.CertificateFromRequest(req, cfg)
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err=%v want ErrNoClientCert (untrusted IPv6 source MUST NOT spoof cert)", err)
	}
}

// TestCertificateFromRequest_BareIPRemoteAddrTolerated covers the
// edge case where the std library writes a bare IP literal into
// RemoteAddr (no port). The helper [parseRemoteAddr] tolerates the
// shape so a non-conformant transport does not collapse to "always
// untrusted".
func TestCertificateFromRequest_BareIPRemoteAddrTolerated(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.RemoteAddr = "10.0.0.5"
	req.Header.Set("X-Client-Cert", pemEncode(t, cert))

	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "10.0.0.0/8"),
	}
	got, err := mtls.CertificateFromRequest(req, cfg)
	if err != nil {
		t.Fatalf("CertificateFromRequest (bare IP): %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(cert) {
		t.Errorf("returned cert thumbprint differs from input")
	}
}
