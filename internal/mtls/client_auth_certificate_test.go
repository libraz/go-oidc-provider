package mtls_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// TestVerifier_ClientAuthCertificate_ChainVerdict pins when a certificate
// counts as chain-verified for RFC 8705 §2.1: the handshake's verified
// chains or RootCAs on direct TLS, RootCAs alone on the forwarded path.
func TestVerifier_ClientAuthCertificate_ChainVerdict(t *testing.T) {
	t.Parallel()

	ca, leaf := generateCATrustedLeaf(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	proxy := mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24")}

	direct := func(chains bool) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/token", http.NoBody)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		if chains {
			r.TLS.VerifiedChains = [][]*x509.Certificate{{leaf, ca}}
		}
		return r
	}
	forwarded := func() *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/token", http.NoBody)
		r.Header.Set("X-Client-Cert", pemEncode(t, leaf))
		return r
	}
	cases := []struct {
		name string
		cfg  mtls.VerifierConfig
		req  *http.Request
		want bool
	}{
		{"direct verified chains", mtls.VerifierConfig{}, direct(true), true},
		{"direct no verified chains", mtls.VerifierConfig{}, direct(false), false},
		{"direct root CAs", mtls.VerifierConfig{RootCAs: roots}, direct(false), true},
		{"forwarded without root CAs", mtls.VerifierConfig{Proxy: proxy}, forwarded(), false},
		{"forwarded root CAs", mtls.VerifierConfig{Proxy: proxy, RootCAs: roots}, forwarded(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := mtls.NewVerifier(tc.cfg)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			got, verified, err := v.ClientAuthCertificate(tc.req, mtls.MethodTLSClientAuth)
			if err != nil {
				t.Fatalf("ClientAuthCertificate: %v", err)
			}
			if mtls.Thumbprint(got) != mtls.Thumbprint(leaf) {
				t.Fatal("returned a different certificate")
			}
			if verified != tc.want {
				t.Fatalf("chain verified = %v, want %v", verified, tc.want)
			}
		})
	}
}

// TestVerifier_ClientAuthCertificate_SameLeafAsBinding pins that client
// authentication and cnf.x5t#S256 binding read one certificate: on the
// forwarded path the proxy's handshake leaf is never the client's.
func TestVerifier_ClientAuthCertificate_SameLeafAsBinding(t *testing.T) {
	t.Parallel()

	_, clientLeaf := generateCATrustedLeaf(t)
	proxyLeaf := generateLeaf(t)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{
		Proxy: mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24")},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/token", http.NoBody)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{proxyLeaf}}
	r.Header.Set("X-Client-Cert", pemEncode(t, clientLeaf))
	authCert, _, err := v.ClientAuthCertificate(r, mtls.MethodTLSClientAuth)
	if err != nil {
		t.Fatalf("ClientAuthCertificate: %v", err)
	}
	bound, err := v.ThumbprintFromRequest(r)
	if err != nil {
		t.Fatalf("ThumbprintFromRequest: %v", err)
	}
	if mtls.Thumbprint(authCert) != bound || bound != mtls.Thumbprint(clientLeaf) {
		t.Fatal("authentication and binding read different certificates")
	}
}

// TestVerifier_ClientAuthCertificate_UntrustedProxyIgnoresHeader pins that
// a forwarded header from outside the trusted CIDRs yields no certificate.
func TestVerifier_ClientAuthCertificate_UntrustedProxyIgnoresHeader(t *testing.T) {
	t.Parallel()

	_, leaf := generateCATrustedLeaf(t)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{
		Proxy: mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "198.51.100.0/24")},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/token", http.NoBody)
	r.Header.Set("X-Client-Cert", pemEncode(t, leaf))
	if _, _, err := v.ClientAuthCertificate(r, mtls.MethodTLSClientAuth); !errors.Is(err, mtls.ErrNoClientCert) {
		t.Fatalf("err = %v, want ErrNoClientCert", err)
	}
}

// TestClientMatcher_Validate pins the RFC 8705 §2.1.2 exactly-one rule.
func TestClientMatcher_Validate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		m    mtls.ClientMatcher
		want error
	}{
		{"subject_dn", mtls.ClientMatcher{SubjectDN: "CN=c"}, nil},
		{"san_dns", mtls.ClientMatcher{SANDNS: "c.example"}, nil},
		{"san_uri", mtls.ClientMatcher{SANURI: "spiffe://example/c"}, nil},
		{"san_ip", mtls.ClientMatcher{SANIP: "192.0.2.1"}, nil},
		{"san_email", mtls.ClientMatcher{SANEmail: "c@example.com"}, nil},
		{"none", mtls.ClientMatcher{}, mtls.ErrNoMatcherConfigured},
		{"two", mtls.ClientMatcher{SubjectDN: "CN=c", SANDNS: "c.example"}, mtls.ErrAmbiguousMatcher},
		{"bad ip", mtls.ClientMatcher{SANIP: "c.example"}, mtls.ErrMatcherMalformed},
	} {
		if err := tc.m.Validate(); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: Validate = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestVerifySelfSignedTLSClientAuthKeySet matches a decoded key set by
// public-key thumbprint and fails closed on a nil set.
func TestVerifySelfSignedTLSClientAuthKeySet(t *testing.T) {
	t.Parallel()

	cert := generateLeaf(t)
	other := generateLeaf(t)
	set := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{Key: other.PublicKey}, {Key: cert.PublicKey}}}
	if err := mtls.VerifySelfSignedTLSClientAuthKeySet(cert, set); err != nil {
		t.Fatalf("matching key: %v", err)
	}
	only := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{Key: other.PublicKey}}}
	if err := mtls.VerifySelfSignedTLSClientAuthKeySet(cert, only); !errors.Is(err, mtls.ErrNoMatchingJWK) {
		t.Fatalf("absent key: err = %v, want ErrNoMatchingJWK", err)
	}
	if err := mtls.VerifySelfSignedTLSClientAuthKeySet(cert, nil); !errors.Is(err, mtls.ErrNoMatchingJWK) {
		t.Fatalf("nil set: err = %v, want ErrNoMatchingJWK", err)
	}
}

// TestVerifySelfSignedTLSClientAuthKeySet_KeyTypes pins that RFC 8705
// §2.2 matching accepts certificates over RSA, EC P-256 / P-384 / P-521
// and Ed25519 keys: the thumbprint is the key's, whatever its type.
func TestVerifySelfSignedTLSClientAuthKeySet_KeyTypes(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	keys := map[string]crypto.Signer{"RSA": rsaKey}
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		keys[name] = k
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	keys["Ed25519"] = edKey

	for name, key := range keys {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatalf("%s: CreateCertificate: %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%s: ParseCertificate: %v", name, err)
		}
		set := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{Key: key.Public()}}}
		if err := mtls.VerifySelfSignedTLSClientAuthKeySet(cert, set); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestVerifier_ForClient pins the per-client trust rule: under RootCAs a
// self_signed_tls_client_auth client's view reads and binds a self-signed
// certificate, every other method's view still rejects it, and the
// trusted-proxy rule survives the exemption.
func TestVerifier_ForClient(t *testing.T) {
	t.Parallel()

	ca, _ := generateCATrustedLeaf(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	selfSigned := generateLeaf(t)
	v, err := mtls.NewVerifier(mtls.VerifierConfig{
		Proxy:   mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24")},
		RootCAs: roots,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	forwarded := func(remote string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/token", http.NoBody)
		r.RemoteAddr = remote
		r.Header.Set("X-Client-Cert", pemEncode(t, selfSigned))
		return r
	}

	exempt := v.ForClient(mtls.MethodSelfSignedTLSClientAuth)
	if exempt.VerifiesChains() {
		t.Fatal("self_signed_tls_client_auth view still verifies chains")
	}
	if err := exempt.VerifyBoundRequest(forwarded("192.0.2.1:443"), mtls.Thumbprint(selfSigned)); err != nil {
		t.Fatalf("self-signed view: VerifyBoundRequest: %v", err)
	}
	if _, err := exempt.CertificateFromRequest(forwarded("198.51.100.1:443")); !errors.Is(err, mtls.ErrNoClientCert) {
		t.Fatalf("self-signed view, untrusted source: err = %v, want ErrNoClientCert", err)
	}
	for _, method := range []string{mtls.MethodTLSClientAuth, "private_key_jwt", "client_secret_basic", ""} {
		if got := v.ForClient(method); got != v {
			t.Fatalf("ForClient(%q) changed the verifier", method)
		}
		if _, err := v.ForClient(method).ThumbprintFromRequest(forwarded("192.0.2.1:443")); !errors.Is(err, mtls.ErrCertUntrusted) {
			t.Fatalf("ForClient(%q): err = %v, want ErrCertUntrusted", method, err)
		}
	}
	if (*mtls.Verifier)(nil).ForClient(mtls.MethodSelfSignedTLSClientAuth) != nil {
		t.Fatal("ForClient on a nil verifier is not nil")
	}
}
