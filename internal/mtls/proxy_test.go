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
	"strings"
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

// parsePEMCert is the inverse of [pemEncode], used by the tests that
// pin behaviour against certificates embedded verbatim in the source
// rather than generated per run.
func parsePEMCert(tb testing.TB, body string) *x509.Certificate {
	tb.Helper()
	block, _ := pem.Decode([]byte(body))
	if block == nil {
		tb.Fatalf("embedded PEM does not decode")
		return nil // Fatalf stops the goroutine; the return is for static analysis.
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		tb.Fatalf("ParseCertificate: %v", err)
	}
	return cert
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

// TestCertificateFromRequest_HeaderURLEncoded accepts an encoded
// payload under both conventions a proxy may use. nginx
// ssl_client_escaped_cert percent-escapes everything including the
// delimiter-line spaces, while a form-encoding hop writes those spaces
// as "+" and the base64 body's own "+" as "%2B". The two differ only
// in how "+" is read, and the certificate MUST come back unchanged
// either way — a decoder that resolved "+" the wrong way would hand
// back different bytes than the proxy verified.
func TestCertificateFromRequest_HeaderURLEncoded(t *testing.T) {
	t.Parallel()

	// The embedded leaf carries "+" inside its base64 body, which is
	// what makes the two conventions distinguishable at all.
	cert := parsePEMCert(t, smugglingLeadPEM)
	encodings := map[string]string{
		"percent encoded": url.PathEscape(smugglingLeadPEM),
		"form encoded":    url.QueryEscape(smugglingLeadPEM),
	}
	for name, payload := range encodings {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
			req.Header.Set("X-Client-Cert", payload)

			got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
			if err != nil {
				t.Fatalf("CertificateFromRequest: %v", err)
			}
			if mtls.Thumbprint(got) != mtls.Thumbprint(cert) {
				t.Errorf("returned cert thumbprint differs from input")
			}
		})
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

// TestCertificateFromRequest_SeparatesProxyAndClientIdentities confirms
// the normal TLS-termination topology: the handshake cert authenticates
// the proxy transport while the forwarded cert identifies the OAuth
// client. Their thumbprints are expected to differ; RFC 8705 binding
// MUST use the forwarded client cert.
func TestCertificateFromRequest_SeparatesProxyAndClientIdentities(t *testing.T) {
	t.Parallel()

	proxyCert := generateLeaf(t)
	clientCert := generateLeaf(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{proxyCert}}
	req.Header.Set("X-Client-Cert", pemEncode(t, clientCert))

	got, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "0.0.0.0/0", "::/0")})
	if err != nil {
		t.Fatalf("CertificateFromRequest: %v", err)
	}
	if mtls.Thumbprint(got) != mtls.Thumbprint(clientCert) {
		t.Errorf("bound cert is not the forwarded OAuth client cert")
	}
}

// TestCertificateFromRequest_TrustedHeaderRejectsAmbiguity ensures a
// trusted source still cannot smuggle multiple possible client leaves
// through the forwarding channel. The proxy contract is one header
// field containing one certificate PEM block.
func TestCertificateFromRequest_TrustedHeaderRejectsAmbiguity(t *testing.T) {
	t.Parallel()

	leaf := generateLeaf(t)
	other := generateLeaf(t)
	leafPEM := pemEncode(t, leaf)
	otherPEM := pemEncode(t, other)
	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24"),
	}

	tests := []struct {
		name   string
		values []string
	}{
		{
			name:   "duplicate header fields",
			values: []string{leafPEM, otherPEM},
		},
		{
			name:   "forwarded PEM chain",
			values: []string{leafPEM + otherPEM},
		},
		{
			name:   "percent-encoded PEM chain",
			values: []string{url.QueryEscape(leafPEM + otherPEM)},
		},
		{
			name:   "trailing non-whitespace",
			values: []string{leafPEM + "attacker-controlled-suffix"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
			req.Header[http.CanonicalHeaderKey("X-Client-Cert")] = tc.values
			_, err := mtls.CertificateFromRequest(req, cfg)
			if !errors.Is(err, mtls.ErrCertMalformed) {
				t.Errorf("err=%v want ErrCertMalformed", err)
			}
		})
	}
}

// smugglingLeadPEM and smugglingTrailPEM are a fixed pair of
// self-signed leaves that reproduce a chain-selection defect the
// randomly generated pair in
// [TestCertificateFromRequest_TrustedHeaderRejectsAmbiguity] only hits
// by chance. The pair is embedded verbatim because the property depends
// on the exact base64 bodies:
//
//   - the lead certificate's body contains "+" characters in a count
//     that is not a multiple of four, so rewriting them to spaces (what
//     form-decoding does) leaves a base64 body whose length is no
//     longer a multiple of four and therefore fails to decode;
//   - the trailing certificate's body contains no "+" at all, so the
//     same rewrite leaves it byte-identical and perfectly decodable.
//
// Both carry a validity window that ends far beyond any maintenance
// horizon, so the fixture cannot become a scheduled failure the way a
// conventionally dated test certificate would.
//
// Concatenated, the two put the decoder in the state that matters: the
// leading block is unparseable and the trailing one is not. A decoder
// that skips undecodable blocks resolves that payload to the SECOND
// certificate and reports no remaining data, which would let whoever
// composed the header choose which leaf the OP binds — the exact
// ambiguity the forwarding contract exists to deny.
const (
	smugglingLeadPEM = `-----BEGIN CERTIFICATE-----
MIIBPDCB46ADAgECAgEBMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMTEnJwLnRlc3Rr
aXQuaW52YWxpZDAgFw0yNDAxMDEwMDAwMDBaGA8yMTI1MDEwMTAwMDAwMFowHTEb
MBkGA1UEAxMScnAudGVzdGtpdC5pbnZhbGlkMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEC5cZw6h6Gvch6qZXUwauCqGQfj4pPS6tnRI4nMW16w/Mm+uI6wbmllde
K3aLokph82d0apCDEN3cbmbCQqt2TqMSMBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqG
SM49BAMCA0gAMEUCIEfW2fpiMYXIn/EDO6AfyB3pmmLwhVyOfklu5AQPDsjkAiEA
04oFVEtqrwt9Tn6RT55iO7zSZaIu0RyJevpkbRjPoDo=
-----END CERTIFICATE-----
`
	smugglingTrailPEM = `-----BEGIN CERTIFICATE-----
MIIBPDCB46ADAgECAgEBMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMTEnJwLnRlc3Rr
aXQuaW52YWxpZDAgFw0yNDAxMDEwMDAwMDBaGA8yMTI1MDEwMTAwMDAwMFowHTEb
MBkGA1UEAxMScnAudGVzdGtpdC5pbnZhbGlkMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE8Q8V26Zx7FwJZ//nd/pQ0qD8iDrwve7ne20WNhUxeE2FMKAqFQCyXxV9
bVqLvSFRgw8p530QeAoIsB1OHVU4PKMSMBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqG
SM49BAMCA0gAMEUCICCah34frH1kJFsroUp9MdWJ2XFcqhuQvHtcrX4IV2tTAiEA
g9BkZoORTrwN3lYrnxTVfO6FNlypLEO71Zrht03c1QI=
-----END CERTIFICATE-----
`
)

// TestCertificateFromRequest_ChainNeverSelectsTrailingCert pins the
// property against the fixed pair described above: a two-certificate
// payload is malformed, and in particular the trailing certificate is
// never what comes back. Both assertions are made because they fail
// differently — a returned error says the payload was rejected, while
// the thumbprint check says WHICH leaf a regression would have handed
// to RFC 8705 binding.
func TestCertificateFromRequest_ChainNeverSelectsTrailingCert(t *testing.T) {
	t.Parallel()

	trail := parsePEMCert(t, smugglingTrailPEM)
	cfg := mtls.ProxyConfig{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24"),
	}

	// Every encoding a proxy might have applied to the same chain. The
	// payload is malformed under all of them; none may resolve to the
	// trailing leaf.
	chain := smugglingLeadPEM + smugglingTrailPEM
	payloads := map[string]string{
		"raw":              chain,
		"percent encoded":  url.PathEscape(chain),
		"form encoded":     url.QueryEscape(chain),
		"plus as space":    strings.ReplaceAll(chain, "+", " "),
		"trailing newline": chain + "\n",
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://op.example/token", http.NoBody)
			req.Header[http.CanonicalHeaderKey("X-Client-Cert")] = []string{payload}
			got, err := mtls.CertificateFromRequest(req, cfg)
			if !errors.Is(err, mtls.ErrCertMalformed) {
				t.Errorf("err=%v want ErrCertMalformed", err)
			}
			if got != nil && mtls.Thumbprint(got) == mtls.Thumbprint(trail) {
				t.Errorf("returned the trailing certificate of a forwarded chain")
			}
		})
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
