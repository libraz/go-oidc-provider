//go:build apiverify

package apiverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const example50ClientID = "fapi-tls-jwks-client"

// TestExample50FAPITLSJWKS proves the copy-paste path the example documents:
// a public JWKS is registered for private_key_jwt, an RSA TLS-1.2 listener
// starts with operator-style files, and a DPoP-bound client-credentials
// request reaches /token over that listener.
func TestExample50FAPITLSJWKS(t *testing.T) {
	addr := reserveLoopbackAddr(t)
	issuer := "https://" + addr
	certPath, keyPath := writeTLSCertificate(t, addr)
	clientKey, jwksPath := writeClientJWKS(t)

	p := buildAndStartWithEnv(t, "../../50-fapi-tls-jwks", []string{
		"FAPI_ADDR=" + addr,
		"FAPI_ISSUER=" + issuer,
		"FAPI_CERT=" + certPath,
		"FAPI_KEY=" + keyPath,
		"FAPI_JWKS=" + jwksPath,
	})
	defer p.kill()

	tokenURL := issuer + "/oidc/token"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // test-only self-signed listener.
	}}, Timeout: 5 * time.Second}
	pollTLS(t, p, client, issuer+"/.well-known/openid-configuration")

	now := time.Now().UTC()
	assertion := signES256(t, clientKey,
		map[string]any{"alg": "ES256", "kid": "example-50-client", "typ": "JWT"},
		map[string]any{
			"iss": example50ClientID, "sub": example50ClientID,
			"aud": tokenURL, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "example-50-assertion",
		},
	)
	dpop := signES256(t, clientKey,
		map[string]any{"alg": "ES256", "kid": "example-50-client", "typ": "dpop+jwt", "jwk": publicJWK(t, &clientKey.PublicKey, "example-50-client")},
		map[string]any{"htm": "POST", "htu": tokenURL, "iat": now.Unix(), "jti": "example-50-dpop"},
	)
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"api:read"},
		"client_id":             {example50ClientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpop)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v\n%s", err, p.readLog())
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS12 {
		t.Fatalf("TLS version=%v want TLS 1.2", resp.TLS)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v\n%s", resp.StatusCode, body, p.readLog())
	}
	if token, _ := body["access_token"].(string); token == "" {
		t.Fatalf("token response missing access_token: %v", body)
	}
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listener: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}
	return addr
}

func writeTLSCertificate(t *testing.T, addr string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate TLS key: %v", err)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(host)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create TLS certificate: %v", err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	return certPath, keyPath
}

func writePEM(t *testing.T, path, kind string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeClientJWKS(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	raw, err := json.Marshal(map[string]any{"keys": []any{publicJWK(t, &key.PublicKey, "example-50-client")}})
	if err != nil {
		t.Fatalf("marshal client JWKS: %v", err)
	}
	path := filepath.Join(t.TempDir(), "client.jwks.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write client JWKS: %v", err)
	}
	return key, path
}

func publicJWK(t *testing.T, key *ecdsa.PublicKey, kid string) map[string]any {
	t.Helper()
	// Bytes returns the uncompressed SEC 1 point 0x04 || X || Y; for P-256
	// the JWK coordinates are its two 32-byte halves.
	point, err := key.Bytes()
	if err != nil {
		t.Fatalf("encode client public key: %v", err)
	}
	return map[string]any{
		"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:]),
	}
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	encoded := func(value map[string]any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal JWT value: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := encoded(header) + "." + encoded(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func pollTLS(t *testing.T, p *proc, client *http.Client, endpoint string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if exited, code := p.poll(); exited {
			t.Fatalf("example exited with code %d before TLS readiness:\n%s", code, p.readLog())
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatalf("build TLS readiness probe: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for TLS example readiness:\n%s", p.readLog())
}
