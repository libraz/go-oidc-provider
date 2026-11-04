package rs_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op/rs"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "https://rs.example.com/api"
	resourceURL  = "https://rs.example.com/orders"
	primaryKID   = "k1"
)

// testNow anchors every clock in this package's tests. Certificate
// validity windows are wide literal ranges, so the real clock the TLS
// stack consults never decides an outcome either.
var testNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// testClock is a settable clock shared by the verifier, the OP and its
// store, so expiry and proof windows are decided by the test.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: testNow} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// keyServer serves a JWK Set the test can replace, and counts fetches.
type keyServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	keys []josev4.JSONWebKey
	hits atomic.Int32
}

func newKeyServer(t *testing.T, keys ...josev4.JSONWebKey) *keyServer {
	t.Helper()
	ks := &keyServer{keys: keys}
	ks.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ks.hits.Add(1)
		ks.mu.Lock()
		body, err := json.Marshal(josev4.JSONWebKeySet{Keys: ks.keys})
		ks.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(ks.srv.Close)
	return ks
}

func (ks *keyServer) setKeys(keys ...josev4.JSONWebKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys = keys
}

func publicJWK(t *testing.T, key crypto.Signer, kid, alg string) josev4.JSONWebKey {
	t.Helper()
	return josev4.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: alg, Use: "sig"}
}

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return key
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// signJWS serialises claims as a compact JWS with the given header values.
// An empty kid or typ omits the header.
func signJWS(t *testing.T, alg josev4.SignatureAlgorithm, key any, kid, typ string, claims map[string]any) string {
	t.Helper()
	opts := &josev4.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(josev4.ContentType(typ))
	}
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatalf("NewSigner(%s): %v", alg, err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return out
}

// baseClaims is a complete RFC 9068 claim set for testIssuer/testAudience.
func baseClaims() map[string]any {
	return map[string]any{
		"iss":       testIssuer,
		"sub":       "user-1",
		"aud":       testAudience,
		"client_id": "client-1",
		"iat":       testNow.Unix(),
		"exp":       testNow.Add(5 * time.Minute).Unix(),
		"jti":       "token-1",
		"scope":     "read write",
	}
}

// fixture is a verifier environment backed by a local JWK Set holding
// one ES256 key under primaryKID.
type fixture struct {
	ks    *keyServer
	key   *ecdsa.PrivateKey
	clock *testClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := newECKey(t, elliptic.P256())
	return &fixture{
		ks:    newKeyServer(t, publicJWK(t, key, primaryKID, "ES256")),
		key:   key,
		clock: newTestClock(),
	}
}

func (f *fixture) config() rs.Config {
	return rs.Config{
		Issuer:              testIssuer,
		Audience:            testAudience,
		JWKSURI:             f.ks.srv.URL + "/jwks",
		HTTPClient:          f.ks.srv.Client(),
		AllowPrivateNetwork: true,
		Clock:               f.clock,
	}
}

func (f *fixture) verifier(t *testing.T, mutate ...func(*rs.Config)) *rs.Verifier {
	t.Helper()
	cfg := f.config()
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := rs.New(cfg)
	if err != nil {
		t.Fatalf("rs.New: %v", err)
	}
	return v
}

// token mints an ES256 at+jwt over baseClaims after mutate edits them.
func (f *fixture) token(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	claims := baseClaims()
	if mutate != nil {
		mutate(claims)
	}
	return signJWS(t, josev4.ES256, f.key, primaryKID, "at+jwt", claims)
}

// newRequest builds a GET to resourceURL. An empty scheme sends no
// Authorization header.
func newRequest(t *testing.T, scheme, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, resourceURL, nil)
	if scheme != "" {
		req.Header.Set("Authorization", scheme+" "+token)
	}
	return req
}

// wantError asserts err is an *rs.Error with the given status and code.
func wantError(t *testing.T, err error, status int, code string) *rs.Error {
	t.Helper()
	var e *rs.Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v (%T), want *rs.Error", err, err)
	}
	if e.Status != status || e.Code != code {
		t.Fatalf("got status=%d code=%q (%s), want status=%d code=%q", e.Status, e.Code, e.Description, status, code)
	}
	return e
}

func mustVerify(t *testing.T, v *rs.Verifier, req *http.Request) *rs.Token {
	t.Helper()
	tok, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return tok
}

func randomID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b)
}

// proofKey signs DPoP proofs (RFC 9449 §4.2) with one key.
type proofKey struct {
	alg  josev4.SignatureAlgorithm
	priv crypto.Signer
	jkt  string
}

func newProofKey(t *testing.T, alg josev4.SignatureAlgorithm) proofKey {
	t.Helper()
	var priv crypto.Signer
	switch alg {
	case josev4.ES256:
		priv = newECKey(t, elliptic.P256())
	case josev4.RS256, josev4.PS256:
		priv = newRSAKey(t)
	case josev4.EdDSA:
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		priv = edKey
	default:
		t.Fatalf("unsupported proof alg %s", alg)
	}
	jwk := josev4.JSONWebKey{Key: priv.Public()}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return proofKey{alg: alg, priv: priv, jkt: base64.RawURLEncoding.EncodeToString(sum)}
}

// proof returns a fresh proof for method/htu at iat. A non-empty
// accessToken adds the matching ath claim.
func (k proofKey) proof(t *testing.T, method, htu string, iat time.Time, accessToken string) string {
	t.Helper()
	return k.proofWithNonce(t, method, htu, iat, accessToken, "")
}

// proofWithNonce is proof with a server-provided nonce claim; an empty
// nonce omits it.
func (k proofKey) proofWithNonce(t *testing.T, method, htu string, iat time.Time, accessToken, nonce string) string {
	t.Helper()
	opts := (&josev4.SignerOptions{}).
		WithType("dpop+jwt").
		WithHeader("jwk", josev4.JSONWebKey{Key: k.priv.Public()})
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: k.alg, Key: k.priv}, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := map[string]any{
		"jti": randomID(t),
		"htm": method,
		"htu": htu,
		"iat": iat.Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign proof: %v", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize proof: %v", err)
	}
	return out
}

// clientCert is a client certificate and its key, issued by testCA.
type clientCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// testCA issues client certificates for the mTLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	next atomic.Int64
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key := newECKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rs test ca"},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	ca := &testCA{cert: cert, key: key}
	ca.next.Store(100)
	return ca
}

func (ca *testCA) issue(t *testing.T, cn string) clientCert {
	t.Helper()
	key := newECKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.next.Add(1)),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}
	return clientCert{cert: cert, key: key}
}

// thumbprint is the RFC 8705 §3.1 x5t#S256 of cert.
func thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// challenges splits a DPoPAllowed WWW-Authenticate value into its Bearer
// and DPoP challenges.
func challenges(t *testing.T, header string) (bearer, dpop string) {
	t.Helper()
	i := strings.Index(header, ", DPoP")
	if !strings.HasPrefix(header, "Bearer") || i < 0 {
		t.Fatalf("WWW-Authenticate = %q, want a Bearer and a DPoP challenge", header)
	}
	return header[:i], header[i+2:]
}
