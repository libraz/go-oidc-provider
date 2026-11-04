//go:build example

// Example 55-mtls-proxy demonstrates RFC 8705 mutual-TLS client
// authentication and certificate-bound access tokens for an OP that sits
// behind a TLS-terminating reverse proxy. The proxy owns the TLS handshake
// with the client, so the OP never sees the certificate on its own
// connection: the proxy forwards the leaf in a header, and the OP honours
// that header only from the proxy addresses it was told to trust.
//
// Run with the example build tag:
//
//	(cd examples/55-mtls-proxy && GOWORK=off go run -tags example .)
//
// Two listeners come up in the same process, plus a self-check:
//
//   - 127.0.0.1:8080 — the OP, plain HTTP, the way it runs behind an ingress.
//     It registers one tls_client_auth client (op.TLSClientAuthClient)
//     matched on the certificate subject DN, enables feature.MTLS, trusts
//     the proxy's address (op.WithTrustedProxies), reads the client
//     certificate from the X-Client-Cert header (op.WithMTLSProxy) and
//     re-verifies its chain against the demo CA (op.WithMTLSRootCAs).
//   - 127.0.0.1:8443 — the proxy, an httputil.ReverseProxy terminating TLS.
//     It asks for a client certificate, strips any inbound X-Client-Cert,
//     and sets it from the certificate the handshake actually produced.
//     The issuer is this public HTTPS origin.
//
// The CA, the proxy's server certificate and the client certificate are
// generated in process at every start. The client certificate and key are
// also written to a temporary directory so the curl line below works.
//
// Manual verification:
//
//  1. Start the example. The log prints a "try: curl ..." line naming the
//     client certificate, key and CA files.
//  2. Run that line: the token response carries an access_token and
//     "token_type":"Bearer"; the JWT access token's cnf claim holds
//     "x5t#S256", the SHA-256 thumbprint of the client certificate (the
//     example logs the expected value).
//  3. Repeat the request without --cert/--key: the OP answers 401
//     invalid_client, because no certificate reached it.
//  4. The log also shows "✓ self-verify" once the example has done the same
//     two requests itself.
//
// Wiring details:
//
//   - The proxy only requests a client certificate (tls.RequestClientCert) so
//     public endpoints such as discovery stay reachable without one. It does
//     not verify the chain; WithMTLSRootCAs makes the OP do that, which is
//     also what tls_client_auth requires of a forwarded certificate.
//   - The proxy MUST delete the inbound header before setting its own. The
//     OP additionally ignores the header from any source outside the trusted
//     CIDRs, so a client that reaches the OP directly cannot forge a
//     certificate.
//   - WithMTLSProxy leaves TrustedProxies empty here, so the OP reuses the
//     WithTrustedProxies list for the forwarded certificate as well.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Certificates: the demo CA and leaves are generated per run and the client key is written to a temp directory; production certificates come from the operator's PKI and keys never touch a shared directory.
//   - Proxy: an in-process reverse proxy stands in for nginx / Envoy / an ingress; production proxies set the header from the verified handshake ($ssl_client_escaped_cert in nginx) and are the only hosts inside the trusted CIDRs.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr    = "127.0.0.1:8080"
	proxyAddr = "127.0.0.1:8443"
	issuer    = "https://" + proxyAddr

	clientID  = "mtls-service"
	scope     = "api:read"
	certField = "X-Client-Cert"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	pki, err := newPKI()
	if err != nil {
		return err
	}
	keys := devkeys.MustEphemeral("mtls-proxy-1")

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithGrants(grant.ClientCredentials),
		// feature.MTLS switches on tls_client_auth and the cnf.x5t#S256
		// binding of every token issued to a certificate-presenting client.
		op.WithFeature(feature.MTLS),
		// The proxy connects from loopback; only that source may supply
		// the certificate header.
		op.WithTrustedProxies("127.0.0.1/32", "::1/128"),
		op.WithMTLSProxy(op.MTLSProxy{HeaderName: certField}),
		// The proxy does not verify the chain, so the OP does, against the
		// CA that issued the client certificate.
		op.WithMTLSRootCAs(pki.pool),
		op.WithStaticClients(op.TLSClientAuthClient{
			ID:         clientID,
			SubjectDN:  pki.clientSubjectDN,
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{scope},
		}),
		op.WithScope(op.PublicScope(scope, "Read your API resources")),
	)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)
	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (plain HTTP behind the proxy; issuer %s)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux, provider)
	}()

	proxySrv, err := newProxy(pki)
	if err != nil {
		return err
	}
	proxyErrCh := make(chan error, 1)
	go func() {
		log.Printf("TLS proxy listening on %s", proxyAddr)
		proxyErrCh <- proxySrv.ListenAndServeTLS("", "")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := pki.clientHTTP(&pki.client)
	if err := waitForIssuer(ctx, client); err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "mtls-proxy-example-")
	if err != nil {
		return err
	}
	files, err := pki.writeClientFiles(dir)
	if err != nil {
		return err
	}
	log.Printf("client certificate thumbprint (cnf x5t#S256): %s", pki.clientThumbprint)
	log.Printf("try: curl --cacert %s --cert %s --key %s \\", files.ca, files.cert, files.key)
	log.Printf("         -d 'grant_type=client_credentials&client_id=%s&scope=%s' \\", clientID, scope)
	log.Printf("         %s/oidc/token", issuer)

	if err := selfVerify(ctx, pki); err != nil {
		fmt.Println("✗ self-verify: " + err.Error())
		return err
	}
	fmt.Println("✓ self-verify: certificate-bound token issued through the TLS proxy")

	select {
	case err := <-opErrCh:
		return err
	case err := <-proxyErrCh:
		return err
	}
}

// newProxy builds the TLS-terminating reverse proxy in front of the OP. It is
// the only component that sees the client's handshake certificate.
func newProxy(pki *pki) (*http.Server, error) {
	target, err := url.Parse("http://" + opAddr)
	if err != nil {
		return nil, err
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// Keep the public Host: the OP builds URLs from its issuer, and
			// the forwarded host must agree with it.
			r.Out.Host = r.In.Host
			r.SetXForwarded()
			// Never relay a header the client supplied; set it only from the
			// certificate this handshake produced.
			r.Out.Header.Del(certField)
			if tlsState := r.In.TLS; tlsState != nil && len(tlsState.PeerCertificates) > 0 {
				r.Out.Header.Set(certField, forwardedCert(tlsState.PeerCertificates[0]))
			}
		},
	}
	return &http.Server{
		Addr:              proxyAddr,
		Handler:           rp,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pki.server},
			// Ask for a certificate without rejecting its absence or its
			// chain: the OP decides per endpoint, and verifies the chain.
			ClientAuth: tls.RequestClientCert,
		},
	}, nil
}

// forwardedCert renders the leaf as one percent-encoded PEM block, the shape
// nginx's $ssl_client_escaped_cert produces and the OP accepts.
func forwardedCert(leaf *x509.Certificate) string {
	return url.PathEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})))
}

// selfVerify requests a token with and without the client certificate and
// checks that only the first succeeds, bound to that certificate.
func selfVerify(ctx context.Context, pki *pki) error {
	status, body, err := postToken(ctx, pki.clientHTTP(&pki.client))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("token request with certificate: status %d: %s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return fmt.Errorf("token response without access_token: %s", body)
	}
	thumb, err := accessTokenThumbprint(tok.AccessToken)
	if err != nil {
		return err
	}
	if thumb != pki.clientThumbprint {
		return fmt.Errorf("cnf x5t#S256 = %q, want %q", thumb, pki.clientThumbprint)
	}
	log.Printf("access token bound to the client certificate (cnf x5t#S256 %s)", thumb)

	status, body, err = postToken(ctx, pki.clientHTTP(nil))
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		return fmt.Errorf("token request without certificate: status %d, want a client-authentication failure: %s", status, body)
	}
	if !bytes.Contains(body, []byte("invalid_client")) {
		return fmt.Errorf("token request without certificate: want invalid_client, got %s", body)
	}
	return nil
}

func postToken(ctx context.Context, client *http.Client) (int, []byte, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "scope": {scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// accessTokenThumbprint reads cnf.x5t#S256 from the access token's payload.
// The signature is not checked: the client is not the token's audience and
// the value only feeds this comparison.
func accessTokenThumbprint(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("access token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode access token payload: %w", err)
	}
	var claims struct {
		Cnf map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("parse access token payload: %w", err)
	}
	if claims.Cnf["x5t#S256"] == "" {
		return "", errors.New("access token carries no cnf.x5t#S256")
	}
	return claims.Cnf["x5t#S256"], nil
}

func waitForIssuer(ctx context.Context, client *http.Client) error {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
		if err != nil {
			return err
		}
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("timeout waiting for the OP behind the TLS proxy")
		case <-tick.C:
		}
	}
}

// pki is the demo CA with the proxy's server certificate and the client's
// certificate it issued.
type pki struct {
	caDER            []byte
	pool             *x509.CertPool
	server           tls.Certificate
	client           tls.Certificate
	clientSubjectDN  string
	clientThumbprint string
}

func newPKI() (*pki, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now() //nolint:forbidigo // demo certificates are minted against the wall clock; not OP business logic.
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mtls-proxy-demo-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	clientName := pkix.Name{CommonName: "mtls-service", Organization: []string{"Example"}}
	server, err := issueLeaf(ca, caKey, 2, pkix.Name{CommonName: "mtls-proxy"}, x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1"))
	if err != nil {
		return nil, err
	}
	client, err := issueLeaf(ca, caKey, 3, clientName, x509.ExtKeyUsageClientAuth, nil)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(client.Certificate[0])
	return &pki{
		caDER:            caDER,
		pool:             pool,
		server:           server,
		client:           client,
		clientSubjectDN:  clientName.String(),
		clientThumbprint: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

func issueLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, subject pkix.Name, usage x509.ExtKeyUsage, ip net.IP) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now() //nolint:forbidigo // demo certificates are minted against the wall clock; not OP business logic.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// clientHTTP returns an HTTP client that trusts the demo CA and presents cert
// when it is non-nil.
func (p *pki) clientHTTP(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.pool}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

type clientFiles struct{ ca, cert, key string }

// writeClientFiles saves the CA and the client's certificate and key as PEM
// so the curl line in the log can use them.
func (p *pki) writeClientFiles(dir string) (clientFiles, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.client.PrivateKey)
	if err != nil {
		return clientFiles{}, err
	}
	files := clientFiles{
		ca:   filepath.Join(dir, "ca.pem"),
		cert: filepath.Join(dir, "client.pem"),
		key:  filepath.Join(dir, "client.key"),
	}
	for path, block := range map[string]*pem.Block{
		files.ca:   {Type: "CERTIFICATE", Bytes: p.caDER},
		files.cert: {Type: "CERTIFICATE", Bytes: p.client.Certificate[0]},
		files.key:  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			return clientFiles{}, err
		}
	}
	return files, nil
}
