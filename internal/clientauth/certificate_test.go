package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/op/store"
)

// stubCertificates is a [clientauth.CertificateSource] returning a fixed
// certificate and chain verdict.
type stubCertificates struct {
	cert     *x509.Certificate
	verified bool
	err      error
}

func (s stubCertificates) ClientAuthCertificate(*http.Request, string) (*x509.Certificate, bool, error) {
	return s.cert, s.verified, s.err
}

// testClientCert issues a self-signed leaf carrying the SANs the matcher
// cases compare against.
func testClientCert(tb testing.TB) *x509.Certificate {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(7),
		Subject:        pkix.Name{CommonName: "rp", Organization: []string{"Example"}},
		NotBefore:      time.Unix(0, 0),
		NotAfter:       time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:       []string{"rp.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
		EmailAddresses: []string{"rp@example.com"},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func certRequest() *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/token", http.NoBody)
}

// TestMTLSVerifier_TLSClientAuth pins RFC 8705 §2.1: a chain-verified
// certificate matching the one registered matcher authenticates, and an
// unverified chain, a mismatch, or a record with several matchers is
// invalid_client.
func TestMTLSVerifier_TLSClientAuth(t *testing.T) {
	t.Parallel()

	cert := testClientCert(t)
	for _, tc := range []struct {
		name     string
		verified bool
		client   store.Client
		want     error
	}{
		{"subject_dn", true, store.Client{TLSClientAuthSubjectDN: "CN=rp,O=Example"}, nil},
		{"san_dns", true, store.Client{TLSClientAuthSANDNS: "RP.example.com"}, nil},
		{"san_ip", true, store.Client{TLSClientAuthSANIP: "192.0.2.10"}, nil},
		{"san_email", true, store.Client{TLSClientAuthSANEmail: "rp@example.com"}, nil},
		{"unverified chain", false, store.Client{TLSClientAuthSANDNS: "rp.example.com"}, mtls.ErrCertChainUnverified},
		{"wrong san", true, store.Client{TLSClientAuthSANDNS: "other.example.com"}, mtls.ErrSANMismatch},
		{"wrong subject", true, store.Client{TLSClientAuthSubjectDN: "CN=other"}, mtls.ErrSubjectMismatch},
		{"several matchers", true, store.Client{TLSClientAuthSubjectDN: "CN=rp,O=Example", TLSClientAuthSANDNS: "rp.example.com"}, mtls.ErrAmbiguousMatcher},
		{"no matcher", true, store.Client{}, mtls.ErrNoMatcherConfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := &clientauth.MTLSVerifier{Certificates: stubCertificates{cert: cert, verified: tc.verified}}
			client := tc.client
			client.ID = "rp"
			err := v.VerifyCertificate(context.Background(), certRequest(), clientauth.MethodTLSClientAuth, &client)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("VerifyCertificate: %v", err)
				}
				return
			}
			if !errors.Is(err, clientauth.ErrCredentialsInvalid) || !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want ErrCredentialsInvalid wrapping %v", err, tc.want)
			}
		})
	}
}

// TestMTLSVerifier_NoCertificate maps a request without a certificate to
// invalid_client on both methods.
func TestMTLSVerifier_NoCertificate(t *testing.T) {
	t.Parallel()

	v := &clientauth.MTLSVerifier{
		Certificates: stubCertificates{err: mtls.ErrNoClientCert},
		Resolver:     staticResolver{},
	}
	for _, m := range []clientauth.Method{clientauth.MethodTLSClientAuth, clientauth.MethodSelfSignedTLSClientAuth} {
		err := v.VerifyCertificate(context.Background(), certRequest(), m, &store.Client{ID: "rp", TLSClientAuthSANDNS: "rp.example.com"})
		if !errors.Is(err, clientauth.ErrCredentialsInvalid) || !errors.Is(err, mtls.ErrNoClientCert) {
			t.Fatalf("%s: err = %v, want ErrCredentialsInvalid wrapping ErrNoClientCert", m, err)
		}
	}
}

// TestMTLSVerifier_SelfSigned pins RFC 8705 §2.2: the certificate key must
// be in the client's keys, no chain is required, and a jwks_uri miss
// refetches once so a rotated-in key authenticates.
func TestMTLSVerifier_SelfSigned(t *testing.T) {
	t.Parallel()

	cert := testClientCert(t)
	other := testClientCert(t)
	withCert := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{Key: cert.PublicKey}}}
	withoutCert := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{Key: other.PublicKey}}}
	client := &store.Client{ID: "rp"}

	v := &clientauth.MTLSVerifier{Certificates: stubCertificates{cert: cert}, Resolver: staticResolver{keys: withCert}}
	if err := v.VerifyCertificate(context.Background(), certRequest(), clientauth.MethodSelfSignedTLSClientAuth, client); err != nil {
		t.Fatalf("registered key: %v", err)
	}

	v.Resolver = staticResolver{keys: withoutCert}
	err := v.VerifyCertificate(context.Background(), certRequest(), clientauth.MethodSelfSignedTLSClientAuth, client)
	if !errors.Is(err, clientauth.ErrCredentialsInvalid) || !errors.Is(err, mtls.ErrNoMatchingJWK) {
		t.Fatalf("absent key: err = %v, want ErrCredentialsInvalid wrapping ErrNoMatchingJWK", err)
	}

	refetches := 0
	v.Resolver = rotatingResolver{stale: withoutCert, fresh: withCert, refetch: &refetches}
	if err := v.VerifyCertificate(context.Background(), certRequest(), clientauth.MethodSelfSignedTLSClientAuth, client); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if refetches != 1 {
		t.Fatalf("refetches = %d, want 1", refetches)
	}
}

// TestVerifyClient_CertificateMethod pins that a body-credential-free
// request from a client registered for an mTLS method is judged under that
// method, and fails closed without a certificate verifier.
func TestVerifyClient_CertificateMethod(t *testing.T) {
	t.Parallel()

	cert := testClientCert(t)
	client := &store.Client{ID: "rp", TokenEndpointAuthMethod: "tls_client_auth", TLSClientAuthSANDNS: "rp.example.com"} //nolint:gosec // G101 false positive: "tls_client_auth" is an auth-method name, not a credential.
	creds := &clientauth.Credentials{ClientID: "rp", Method: clientauth.MethodNone}
	if got := clientauth.EffectiveMethod(creds, client); got != clientauth.MethodTLSClientAuth {
		t.Fatalf("EffectiveMethod = %q, want tls_client_auth", got)
	}

	opts := clientauth.VerifyOpts{
		CertificateVerifier: &clientauth.MTLSVerifier{Certificates: stubCertificates{cert: cert, verified: true}},
		Request:             certRequest(),
	}
	verified, err := clientauth.VerifyClient(context.Background(), creds, client, opts)
	if err != nil {
		t.Fatalf("VerifyClient: %v", err)
	}
	if verified.Method != clientauth.MethodTLSClientAuth {
		t.Fatalf("Verified.Method = %q, want tls_client_auth", verified.Method)
	}

	if _, err := clientauth.VerifyClient(context.Background(), creds, client, clientauth.VerifyOpts{}); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("no certificate verifier: err = %v, want ErrCredentialsInvalid", err)
	}

	opts.AllowedMethods = []clientauth.Method{clientauth.MethodPrivateKeyJWT}
	if _, err := clientauth.VerifyClient(context.Background(), creds, client, opts); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("policy excludes tls_client_auth: err = %v, want ErrCredentialsInvalid", err)
	}

	public := &store.Client{ID: "rp", TokenEndpointAuthMethod: "tls_client_auth", PublicClient: true} //nolint:gosec // G101 false positive: "tls_client_auth" is an auth-method name, not a credential.
	if got := clientauth.EffectiveMethod(creds, public); got != clientauth.MethodNone {
		t.Fatalf("public client: EffectiveMethod = %q, want none", got)
	}
	secret := &clientauth.Credentials{ClientID: "rp", Method: clientauth.MethodSecretBasic}
	if got := clientauth.EffectiveMethod(secret, client); got != clientauth.MethodSecretBasic {
		t.Fatalf("secret credentials: EffectiveMethod = %q, want client_secret_basic", got)
	}
}
