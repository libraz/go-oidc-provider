package scenarios_test

import (
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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// mtlsAuthHeader is the forwarded-certificate header the proxy topology
// configures through op.WithMTLSProxy.
const mtlsAuthHeader = "X-Client-Cert"

// mtlsMatcherKinds are the RFC 8705 §2.1.2 matcher kinds; each has its own
// tls_client_auth client registering only that kind.
var mtlsMatcherKinds = []string{"subject_dn", "san_dns", "san_uri", "san_ip", "san_email"}

// mtlsCertValidity names how the presented certificate relates to the
// client it claims.
const (
	mtlsValid          = "valid"           // matches the client's matcher or key
	mtlsMismatch       = "mismatch"        // wrong SAN / subject, or key not in the JWKS
	mtlsUnverified     = "unverified"      // chain not verified (PKI) / plain self-signed
	mtlsNoCert         = "nocert"          // no certificate at all
	mtlsUntrustedProxy = "untrusted_proxy" // header from a source outside the trusted CIDRs
)

// mtlsPKI is a throwaway CA with the leaves the scenarios present.
type mtlsPKI struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	pool  *x509.CertPool
}

func newMTLSPKI(tb testing.TB, name string) *mtlsPKI {
	tb.Helper()
	key := mtlsKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &mtlsPKI{ca: ca, caKey: key, pool: pool}
}

func mtlsKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// leafFor returns a CA-issued client certificate whose subject and SANs
// all carry identity's values (see [mtlsMatcherValue]).
func (p *mtlsPKI) leafFor(tb testing.TB, identity string) tls.Certificate {
	tb.Helper()
	return mtlsIssue(tb, p.ca, p.caKey, identity)
}

// mtlsSelfSigned returns a self-signed client certificate for identity.
func mtlsSelfSigned(tb testing.TB, identity string) tls.Certificate {
	tb.Helper()
	return mtlsIssue(tb, nil, nil, identity)
}

func mtlsIssue(tb testing.TB, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, identity string) tls.Certificate {
	tb.Helper()
	key := mtlsKey(tb)
	uri, err := url.Parse(mtlsMatcherValue("san_uri", identity))
	if err != nil {
		tb.Fatalf("parse SAN URI: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		tb.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: identity, Organization: []string{"Example"}},
		NotBefore:      time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:       time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:       []string{mtlsMatcherValue("san_dns", identity)},
		URIs:           []*url.URL{uri},
		IPAddresses:    []net.IP{net.ParseIP(mtlsMatcherValue("san_ip", identity))},
		EmailAddresses: []string{mtlsMatcherValue("san_email", identity)},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		tb.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// mtlsMatcherValue is the value of one matcher kind for identity, both on
// the certificate and in the client's registration.
func mtlsMatcherValue(kind, identity string) string {
	switch kind {
	case "subject_dn":
		return "CN=" + identity + ",O=Example"
	case "san_dns":
		return identity + ".example.com"
	case "san_uri":
		return "spiffe://example.com/" + identity
	case "san_ip":
		sum := sha256.Sum256([]byte(identity))
		return fmt.Sprintf("10.%d.%d.%d", sum[0], sum[1], sum[2])
	case "san_email":
		return identity + "@example.com"
	default:
		panic("unknown matcher kind " + kind)
	}
}

// mtlsTLSClientSeed is the static tls_client_auth client registering the
// single matcher kind for identity.
func mtlsTLSClientSeed(identity, kind string) op.TLSClientAuthClient {
	c := op.TLSClientAuthClient{
		ID:           identity,
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "api"},
		GrantTypes:   mtlsClientGrants(),
	}
	v := mtlsMatcherValue(kind, identity)
	switch kind {
	case "subject_dn":
		c.SubjectDN = v
	case "san_dns":
		c.SANDNS = v
	case "san_uri":
		c.SANURI = v
	case "san_ip":
		c.SANIP = v
	case "san_email":
		c.SANEmail = v
	}
	return c
}

// mtlsSelfSignedSeed is the static self_signed_tls_client_auth client whose
// JWKS holds cert's public key.
func mtlsSelfSignedSeed(tb testing.TB, id string, cert tls.Certificate) op.SelfSignedTLSClientAuthClient {
	tb.Helper()
	raw, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{Key: cert.Leaf.PublicKey, KeyID: "cert"}}})
	if err != nil {
		tb.Fatalf("marshal JWKS: %v", err)
	}
	return op.SelfSignedTLSClientAuthClient{
		ID:           id,
		JWKS:         raw,
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "api"},
		GrantTypes:   mtlsClientGrants(),
	}
}

func mtlsClientGrants() []string {
	return []string{
		"authorization_code", "refresh_token", "client_credentials",
		"urn:ietf:params:oauth:grant-type:device_code", cibaURNGrant,
	}
}

// mtlsEndpointOptions enables every client-authenticating endpoint.
func mtlsEndpointOptions() []op.Option {
	return []op.Option{
		op.WithFeature(feature.MTLS),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.Introspect),
		op.WithFeature(feature.Revoke),
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials),
		op.WithDeviceCodeGrant(op.DeviceCodeGrant{}),
		op.WithCIBAGrant(op.CIBAGrant{HintResolver: cibaHintResolver{}}),
		op.WithGrantManagement(op.GrantManagement{Actions: []op.GrantManagementAction{op.GrantActionQuery, op.GrantActionRevoke}}),
	}
}

// mtlsTopology is one way certificates reach the OP: its own TLS
// handshake, or a header from a reverse proxy.
type mtlsTopology struct {
	// verifying requires chain-verified client certificates when given;
	// requesting accepts any client certificate. Both are nil on a proxy
	// topology, which serves plain HTTP from the loopback "proxy".
	verifying, requesting *httptest.Server
	proxy                 *httptest.Server
}

// mtlsDirect serves h over TLS twice: once verifying client chains
// against pki, once accepting any client certificate.
func mtlsDirect(tb testing.TB, h http.Handler, pki *mtlsPKI) mtlsTopology {
	tb.Helper()
	start := func(cfg *tls.Config) *httptest.Server {
		srv := httptest.NewUnstartedServer(h)
		srv.TLS = cfg
		srv.StartTLS()
		tb.Cleanup(srv.Close)
		return srv
	}
	return mtlsTopology{
		verifying:  start(&tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pki.pool, MinVersion: tls.VersionTLS12}),
		requesting: start(&tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}),
	}
}

// mtlsProxied serves h over plain HTTP; requests arrive from loopback.
func mtlsProxied(tb testing.TB, h http.Handler) mtlsTopology {
	tb.Helper()
	srv := httptest.NewServer(h)
	tb.Cleanup(srv.Close)
	return mtlsTopology{proxy: srv}
}

// mtlsEndpointRequest builds the request each endpoint authenticates.
// The client is named by client_id only; the certificate is the credential.
func mtlsEndpointRequest(tb testing.TB, endpoint, base, clientID string) *http.Request {
	tb.Helper()
	form := url.Values{"client_id": {clientID}}
	method, path := http.MethodPost, ""
	switch endpoint {
	case "token":
		path = "/oidc/token"
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "api")
	case "par":
		path = "/oidc/par"
		form.Set("response_type", "code")
		form.Set("redirect_uri", "https://rp.example.com/cb")
		form.Set("scope", "openid")
		form.Set("state", "state-mtls")
		form.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
		form.Set("code_challenge_method", "S256")
	case "introspect":
		path = "/oidc/introspect"
		form.Set("token", "not-a-token")
	case "revoke":
		path = "/oidc/revoke"
		form.Set("token", "not-a-token")
	case "ciba":
		path = "/oidc/bc-authorize"
		form.Set("scope", "openid")
		form.Set("login_hint", cibaKnownLoginHint)
	case "device":
		path = "/oidc/device_authorization"
		form.Set("scope", "openid")
	case "grantmgmt":
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			base+"/oidc/grant_management/unknown-grant?"+form.Encode(), http.NoBody)
		if err != nil {
			tb.Fatalf("NewRequest: %v", err)
		}
		return req
	default:
		tb.Fatalf("unknown endpoint %q", endpoint)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, base+path, strings.NewReader(form.Encode()))
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// mtlsAuthenticatedStatus is the status each endpoint answers once the
// client authenticated: the request bodies above are otherwise valid,
// except grant management's, which names a grant that does not exist.
var mtlsAuthenticatedStatus = map[string]int{
	"token":      http.StatusOK,
	"par":        http.StatusCreated,
	"introspect": http.StatusOK,
	"revoke":     http.StatusOK,
	"ciba":       http.StatusOK,
	"device":     http.StatusOK,
	"grantmgmt":  http.StatusNotFound,
}

// mtlsResult is one endpoint response.
type mtlsResult struct {
	status int
	body   map[string]any
	raw    string
}

// send issues req through topology t. On a direct topology cert (if any)
// is presented in the handshake to srv; on a proxy topology it is
// forwarded in [mtlsAuthHeader].
func (t mtlsTopology) send(tb testing.TB, req *http.Request, srv *httptest.Server, cert *tls.Certificate) mtlsResult {
	tb.Helper()
	var client *http.Client
	if t.proxy != nil {
		if cert != nil {
			// Percent-encoded, as nginx's ssl_client_escaped_cert forwards it.
			req.Header.Set(mtlsAuthHeader, url.PathEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))))
		}
		client = t.proxy.Client()
	} else {
		transport := srv.Client().Transport.(*http.Transport).Clone() //nolint:forcetypeassert // httptest always uses *http.Transport.
		if cert != nil {
			transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}
		client = &http.Client{Transport: transport}
	}
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	out := mtlsResult{status: resp.StatusCode, raw: string(raw)}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

// base returns the URL the request is sent to on t.
func (t mtlsTopology) base(srv *httptest.Server) string {
	if t.proxy != nil {
		return t.proxy.URL
	}
	return srv.URL
}

// mtlsAssertInvalidClient fails unless res is the RFC 6749 §5.2
// invalid_client rejection.
func mtlsAssertInvalidClient(tb testing.TB, res mtlsResult) {
	tb.Helper()
	if res.status != http.StatusUnauthorized || res.body["error"] != "invalid_client" {
		tb.Fatalf("status=%d body=%s, want 401 invalid_client", res.status, res.raw)
	}
}

// mtlsAssertAuthenticated fails unless endpoint answered as it does for an
// authenticated client, and, at the token endpoint, bound the access token
// to cert.
func mtlsAssertAuthenticated(tb testing.TB, endpoint string, res mtlsResult, cert *tls.Certificate) {
	tb.Helper()
	if want := mtlsAuthenticatedStatus[endpoint]; res.status != want {
		tb.Fatalf("%s: status=%d body=%s, want %d", endpoint, res.status, res.raw, want)
	}
	if endpoint != "token" {
		return
	}
	at, _ := res.body["access_token"].(string)
	parts := strings.Split(at, ".")
	if len(parts) != 3 {
		tb.Fatalf("access_token is not a JWT: %q", at)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("decode access_token payload: %v", err)
	}
	var claims struct {
		Cnf map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		tb.Fatalf("unmarshal access_token payload: %v", err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	if got, want := claims.Cnf["x5t#S256"], base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		tb.Fatalf("cnf.x5t#S256=%q, want the authenticating certificate's %q", got, want)
	}
}

// mtlsFixture holds the providers the matrix runs against and the
// certificates each validity case presents.
type mtlsFixture struct {
	pki, rogue *mtlsPKI
	selfCert   tls.Certificate
	otherSelf  tls.Certificate
	intruder   tls.Certificate
	pkjwt      *pkjwtKeypair

	direct, directRoots, proxyPKI, untrusted mtlsTopology
}

const (
	mtlsSelfClientID  = "self-signed-rp"
	mtlsPKJWTClientID = "pkjwt-bound-rp"
	mtlsLoopbackCIDR  = "127.0.0.1/32"
)

// mtlsNow pins the providers' clock so client assertions are minted
// without reading the wall clock.
var mtlsNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type mtlsClock struct{}

func (mtlsClock) Now() time.Time { return mtlsNow }

// newMTLSFixture builds, each with every client registered:
//   - direct: the OP terminates TLS itself, no root CAs, so a PKI chain
//     counts as verified only through the handshake;
//   - directRoots: the same with op.WithMTLSRootCAs;
//   - proxyPKI: a trusted loopback proxy forwards the certificate and the
//     OP re-verifies chains through op.WithMTLSRootCAs;
//   - untrusted: the proxy header is honoured from 192.0.2.0/24 only, so
//     a loopback caller's header is ignored.
//
// The clients are one tls_client_auth client per matcher kind, a
// self_signed_tls_client_auth client, and a private_key_jwt client whose
// tokens are certificate-bound.
func newMTLSFixture(t *testing.T) *mtlsFixture {
	t.Helper()
	f := &mtlsFixture{
		pki:   newMTLSPKI(t, "mtls-test-ca"),
		rogue: newMTLSPKI(t, "mtls-rogue-ca"),
		pkjwt: newPKJWTKeypair(t, "pkjwt-bound"),
	}
	f.selfCert = mtlsSelfSigned(t, mtlsSelfClientID)
	f.otherSelf = mtlsSelfSigned(t, "other-self-signed")
	f.intruder = f.pki.leafFor(t, "intruder")

	all := make([]op.ClientSeed, 0, len(mtlsMatcherKinds)+2)
	for _, kind := range mtlsMatcherKinds {
		all = append(all, mtlsTLSClientSeed("pki-"+strings.ReplaceAll(kind, "_", "-"), kind))
	}
	all = append(all, mtlsSelfSignedSeed(t, mtlsSelfClientID, f.selfCert), op.PrivateKeyJWTClient{
		ID:           mtlsPKJWTClientID,
		JWKS:         f.pkjwt.PublicJWKSet(t),
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "api"},
		GrantTypes:   mtlsClientGrants(),
	})

	provider := func(extra ...op.Option) http.Handler {
		opts := append(mtlsEndpointOptions(), op.WithStaticClients(all...))
		opts = append(opts, extra...)
		return testkit.NewProvider(t, testkit.WithClock(mtlsClock{}), testkit.WithOptions(opts...)).OP
	}
	f.direct = mtlsDirect(t, provider(), f.pki)
	f.directRoots = mtlsDirect(t, provider(op.WithMTLSRootCAs(f.pki.pool)), f.pki)
	f.proxyPKI = mtlsProxied(t, provider(
		op.WithMTLSProxy(op.MTLSProxy{HeaderName: mtlsAuthHeader, TrustedProxies: []string{mtlsLoopbackCIDR}}),
		op.WithMTLSRootCAs(f.pki.pool),
	))
	f.untrusted = mtlsProxied(t, provider(
		op.WithMTLSProxy(op.MTLSProxy{HeaderName: mtlsAuthHeader, TrustedProxies: []string{"192.0.2.0/24"}}),
		op.WithMTLSRootCAs(f.pki.pool),
	))
	return f
}

// pkjwtTokenRequest is a client_credentials request from the
// private_key_jwt client, sent to base.
func (f *mtlsFixture) pkjwtTokenRequest(t *testing.T, base string) *http.Request {
	t.Helper()
	claims := pkjwtClaims(mtlsPKJWTClientID, testkit.DefaultIssuer, mtlsNow)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		t.Fatalf("jti: %v", err)
	}
	// A fresh jti per request, so no assertion is refused as a replay.
	claims["jti"] = base64.RawURLEncoding.EncodeToString(jti)
	assertion := signedClientAssertion(t, f.pkjwt, claims)
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"api"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// mtlsCase is one endpoint × method × topology × validity × matcher cell.
type mtlsCase struct {
	endpoint, method, topology, validity, matcher string
}

// run sends c's request and asserts its outcome.
func (f *mtlsFixture) run(tb testing.TB, c mtlsCase) {
	tb.Helper()
	topo, srv, clientID, cert, ok := f.arrange(tb, c)
	res := topo.send(tb, mtlsEndpointRequest(tb, c.endpoint, topo.base(srv), clientID), srv, cert)
	if ok {
		mtlsAssertAuthenticated(tb, c.endpoint, res, cert)
		return
	}
	mtlsAssertInvalidClient(tb, res)
}

// arrange picks the topology, server, client and certificate for c, and
// whether authentication is expected to succeed.
func (f *mtlsFixture) arrange(tb testing.TB, c mtlsCase) (mtlsTopology, *httptest.Server, string, *tls.Certificate, bool) {
	tb.Helper()
	if c.method == "self" {
		// Every self-signed cell runs under op.WithMTLSRootCAs, which a
		// self_signed_tls_client_auth client is exempt from.
		topo := f.directRoots
		switch {
		case c.validity == mtlsUntrustedProxy:
			topo = f.untrusted
		case c.topology == "proxy":
			topo = f.proxyPKI
		}
		var cert *tls.Certificate
		switch c.validity {
		case mtlsValid, mtlsUnverified, mtlsUntrustedProxy:
			cert = &f.selfCert
		case mtlsMismatch:
			cert = &f.otherSelf
		}
		// RFC 8705 §2.2 needs no chain: a registered key authenticates
		// whether or not anything verified the certificate.
		ok := cert == &f.selfCert && c.validity != mtlsUntrustedProxy
		return topo, topo.requesting, mtlsSelfClientID, cert, ok
	}

	identity := "pki-" + strings.ReplaceAll(c.matcher, "_", "-")
	matching := f.pki.leafFor(tb, identity)
	topo, srv := f.direct, f.direct.verifying
	switch {
	case c.validity == mtlsUntrustedProxy:
		topo, srv = f.untrusted, nil
	case c.topology == "proxy":
		topo, srv = f.proxyPKI, nil
	}
	switch c.validity {
	case mtlsValid:
		return topo, srv, identity, &matching, true
	case mtlsMismatch:
		return topo, srv, identity, &f.intruder, false
	case mtlsUnverified:
		if topo.proxy != nil {
			rogue := f.rogue.leafFor(tb, identity)
			return topo, srv, identity, &rogue, false
		}
		return topo, f.direct.requesting, identity, &matching, false
	case mtlsUntrustedProxy:
		return topo, srv, identity, &matching, false
	default:
		return topo, srv, identity, nil, false
	}
}

// newMTLSDCRFixture is [newDCRFixture] on an OP with feature.MTLS, so the
// RFC 8705 §2 methods are registrable.
func newMTLSDCRFixture(t *testing.T) *dcrFixture {
	t.Helper()
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithDynamicRegistration(op.DynamicRegistration{}),
		op.WithFeature(feature.MTLS),
	))
	return &dcrFixture{tk: tk, endpoint: tk.Server.URL + "/oidc/register"}
}

// mtlsAssertRegistrationRejected fails unless POST /register refuses body
// with 400 invalid_client_metadata.
func mtlsAssertRegistrationRejected(t *testing.T, f *dcrFixture, body map[string]any) {
	t.Helper()
	resp := f.post(t, f.mintIAT(t), "", body)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if resp.StatusCode != http.StatusBadRequest || got["error"] != "invalid_client_metadata" {
		t.Fatalf("status=%d body=%s, want 400 invalid_client_metadata", resp.StatusCode, raw)
	}
}
