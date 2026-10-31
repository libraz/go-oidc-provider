//go:build apiverify

package apiverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// 53 promises production wiring that survives a restart: keys read from a
// directory (generated on first boot, kid = RFC 7638 thumbprint), the OP
// schema validated rather than created, and an existing users table whose
// bcrypt hashes are rewritten as argon2id on the first login.
//
// So the probe boots twice on the same key directory and database. The
// first boot migrates, signs alice in and must log the rewrite. The
// second boot only validates the schema, must publish the same kid, and
// signs alice in again without a rewrite: that login verifies against the
// argon2id hash the first one stored, which proves the rewrite was
// persisted and still accepts the password.
func TestExample53ProductionSQL(t *testing.T) {
	const (
		baseURL  = "http://127.0.0.1:8080"
		dir      = "../../53-production-sql"
		rehashed = "bcrypt password hash rewritten as argon2id"
	)
	data := t.TempDir()
	keysDir := filepath.Join(data, "keys")
	env := []string{
		"EXAMPLE53_KEYS_DIR=" + keysDir,
		// EXAMPLE53_DSN is a modernc.org/sqlite DSN, here a file in the
		// test's own temp dir so both boots share it.
		"EXAMPLE53_DSN=file:" + filepath.Join(data, "op.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
	}
	alice := exampleUser{username: "alice@example.com", password: "alice-password"}

	// kill waits for the process to exit, so it must run exactly once: the
	// first boot is stopped before the second binds the same port.
	first := buildAndStartWithEnv(t, dir, append(append([]string{}, env...), "EXAMPLE53_MIGRATE=1"))
	firstStopped := false
	defer func() {
		if !firstStopped {
			first.kill()
		}
	}()
	kid, sub := example53SignIn(t, first, baseURL, alice)
	if want := p256KeyFileThumbprint(t, filepath.Join(keysDir, "signing.pem")); kid != want {
		t.Fatalf("JWKS kid = %q, want the RFC 7638 thumbprint of the generated key %q", kid, want)
	}
	waitForLog(t, first, rehashed, 10*time.Second)
	firstStopped = true
	first.kill()

	second := buildAndStartWithEnv(t, dir, env)
	defer second.kill()
	gotKid, gotSub := example53SignIn(t, second, baseURL, alice)
	if gotKid != kid {
		t.Fatalf("kid after restart = %q, want %q from the same key file", gotKid, kid)
	}
	if gotSub != sub {
		t.Fatalf("sub after restart = %q, want the stored subject %q", gotSub, sub)
	}
	if strings.Contains(second.readLog(), rehashed) {
		t.Fatalf("the second login rewrote the hash again, so the first rewrite was not stored:\n%s", second.readLog())
	}
}

// example53SignIn asserts JWKS publishes exactly one key, signs user in
// through the built-in HTML screens, redeems the code, and checks the ID
// token is signed with that key and carries the users-table subject
// column, not the row id, as sub. It returns the kid and the sub.
func example53SignIn(t *testing.T, p *proc, baseURL string, user exampleUser) (string, string) {
	t.Helper()
	const (
		clientID    = "production-sql-rp"
		secret      = "production-sql-demo-secret-rotate-me"
		redirectURI = "http://127.0.0.1:8081/callback"
	)
	doc := pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	raw := pollHTTP(t, p, baseURL+discoveryEndpointPath(t, doc, "jwks_uri"), 5*time.Second)
	if err := json.Unmarshal([]byte(raw), &jwks); err != nil {
		t.Fatalf("parse JWKS: %v\n%s", err, raw)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid == "" {
		t.Fatalf("JWKS = %s, want exactly one key with a kid", raw)
	}
	kid := jwks.Keys[0].Kid

	b := newBrowser(t, baseURL)
	params := authorizeParams(clientID, redirectURI, "openid profile email")
	b.signIn(baseURL+discoveryEndpointPath(t, doc, "authorization_endpoint")+"?"+params.Encode(), htmlSubmitter{}, user)
	idToken := redeemForIDToken(t, baseURL+discoveryEndpointPath(t, doc, "token_endpoint"),
		clientID, secret, authorizationCode(t, b.finalURL), redirectURI)

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", idToken)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	decodeJWTPart(t, parts[0], &header)
	decodeJWTPart(t, parts[1], &claims)
	if header.Kid != kid {
		t.Fatalf("id_token kid = %q, want the published %q", header.Kid, kid)
	}
	if !example53Subject.MatchString(claims.Sub) {
		t.Fatalf("id_token sub = %q, want the 32-hex-digit app_users subject column", claims.Sub)
	}
	return kid, claims.Sub
}

var example53Subject = regexp.MustCompile(`^[0-9a-f]{32}$`)

func decodeJWTPart(t *testing.T, part string, out any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode JWS segment: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("parse JWS segment: %v\n%s", err, raw)
	}
}

// p256KeyFileThumbprint computes the RFC 7638 thumbprint of the P-256
// PKCS#8 key at path: SHA-256 over the required members in lexicographic
// order, base64url without padding.
func p256KeyFileThumbprint(t *testing.T, path string) string {
	t.Helper()
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated signing key: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS#8 key: %v", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("%s holds a %T, want an ECDSA key", path, parsed)
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil || len(point) != 65 {
		t.Fatalf("encode public key: %v (len %d)", err, len(point))
	}
	enc := base64.RawURLEncoding
	members := `{"crv":"P-256","kty":"EC","x":"` + enc.EncodeToString(point[1:33]) + `","y":"` + enc.EncodeToString(point[33:]) + `"}`
	sum := sha256.Sum256([]byte(members))
	return enc.EncodeToString(sum[:])
}
