package op_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	rootCAsClientID = "rp-mtls-rootcas"
	//nolint:gosec // opaque test fixture secret, not a credential.
	rootCAsSecret = "rp-mtls-rootcas-secret"
)

// newRootCAsProvider builds an mTLS-enabled provider with one
// confidential client that may run the client_credentials grant. That
// grant is the shortest path through /token that still reaches the
// certificate-binding step, so it isolates the trust-anchor decision
// from the rest of the code exchange.
func newRootCAsProvider(tb testing.TB, opts ...op.Option) *testkit.Provider {
	tb.Helper()
	all := append([]op.Option{op.WithFeature(feature.MTLS)}, opts...)
	tk := testkit.NewProvider(tb, testkit.WithOptions(all...))
	hash, err := op.HashClientSecret(rootCAsSecret)
	if err != nil {
		tb.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(tb, testkit.ClientFixture{
		ID:                      rootCAsClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile"},
		GrantTypes:              []string{"authorization_code", "client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return tk
}

// rootCAsTokenPost drives a client_credentials request through the
// provider's handler with cert presented as the TLS handshake leaf. The
// testkit server does not negotiate client certificates, so the request
// is dispatched straight at the [http.Handler] with a fabricated
// [tls.ConnectionState] — the same shape the std-library server would
// have produced.
func rootCAsTokenPost(tb testing.TB, tk *testkit.Provider, cert *x509.Certificate) *http.Response {
	tb.Helper()
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"profile"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Issuer+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rootCAsClientID, rootCAsSecret)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	tk.OP.ServeHTTP(rec, req)
	return rec.Result()
}

// rootCAsErrorCode reads the OAuth error code out of a response body.
// An empty or non-JSON body yields "" so callers report the status code
// alongside it rather than failing on the decode.
func rootCAsErrorCode(tb testing.TB, resp *http.Response) string {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	return body.Error
}

// rootCAsSelfSignedLeaf returns a self-signed client leaf. It chains to
// nothing, so any non-empty trust anchor set rejects it.
func rootCAsSelfSignedLeaf(tb testing.TB) *x509.Certificate {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2001),
		Subject:      pkix.Name{CommonName: "untrusted.rp.invalid"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

// rootCAsIssuedLeaf returns a CA and a client leaf issued by it. The
// validity window is pinned to literal timestamps wide enough that the
// chain-building clock (which is the real one — x509 verification does
// not take an injected clock) never decides the outcome.
func rootCAsIssuedLeaf(tb testing.TB) (ca, leaf *x509.Certificate) {
	tb.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey CA: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey leaf: %v", err)
	}
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2002),
		Subject:               pkix.Name{CommonName: "mtls rootcas test ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("CreateCertificate CA: %v", err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatalf("ParseCertificate CA: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2003),
		Subject:      pkix.Name{CommonName: "trusted.rp.invalid"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("CreateCertificate leaf: %v", err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		tb.Fatalf("ParseCertificate leaf: %v", err)
	}
	return ca, leaf
}

// TestWithMTLSRootCAs_RejectsNilPool pins the construction-time guard:
// a nil pool is ambiguous between "trust nothing" and "do not validate",
// and silently choosing the latter would be the opposite of what a
// caller reaching for the option intends.
func TestWithMTLSRootCAs_RejectsNilPool(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithFeature(feature.MTLS),
		op.WithMTLSRootCAs(nil),
	)...)
	if err == nil {
		t.Fatal("expected configuration error for a nil CertPool, got nil")
	}
	if !strings.Contains(err.Error(), "WithMTLSRootCAs") {
		t.Errorf("err = %v, want it to name WithMTLSRootCAs", err)
	}
}

// TestWithMTLSRootCAs_RejectsUntrustedClientLeaf proves the option is
// wired all the way to the certificate the OP would otherwise have
// bound a token to: the same self-signed leaf is accepted when no trust
// anchors are configured and refused with invalid_client once they are.
// Running both halves is what distinguishes "the pool took effect" from
// "the request failed for an unrelated reason".
func TestWithMTLSRootCAs_RejectsUntrustedClientLeaf(t *testing.T) {
	t.Parallel()

	leaf := rootCAsSelfSignedLeaf(t)

	t.Run("without-root-cas", func(t *testing.T) {
		t.Parallel()

		tk := newRootCAsProvider(t)
		resp := rootCAsTokenPost(t, tk, leaf)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d want 200 (error=%q); without trust anchors the OP binds whatever cert the transport gave it",
				resp.StatusCode, rootCAsErrorCode(t, resp))
		}
	})

	t.Run("with-root-cas", func(t *testing.T) {
		t.Parallel()

		tk := newRootCAsProvider(t, op.WithMTLSRootCAs(x509.NewCertPool()))
		resp := rootCAsTokenPost(t, tk, leaf)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d want 401 for a leaf that chains to no configured anchor", resp.StatusCode)
		}
		if got := rootCAsErrorCode(t, resp); got != "invalid_client" {
			t.Errorf("error=%q want invalid_client (RFC 8705 §3)", got)
		}
	})
}

// TestWithMTLSRootCAs_AcceptsTrustedClientLeaf is the positive half:
// a leaf issued by a CA in the configured pool passes chain validation
// and the token is issued as usual.
func TestWithMTLSRootCAs_AcceptsTrustedClientLeaf(t *testing.T) {
	t.Parallel()

	ca, leaf := rootCAsIssuedLeaf(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	tk := newRootCAsProvider(t, op.WithMTLSRootCAs(pool))
	resp := rootCAsTokenPost(t, tk, leaf)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (error=%q) for a leaf issued by a trusted CA",
			resp.StatusCode, rootCAsErrorCode(t, resp))
	}
}
