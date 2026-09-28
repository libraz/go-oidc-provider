package op_test

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestFAPITLSConfig_TLS12FloorAndAllowlist asserts the helper floors
// TLS at v1.2, leaves TLS 1.3 negotiable, and restricts TLS 1.2 to
// exactly the FAPI 1.0 Advanced §8.5 ECDHE_RSA AEAD allowlist. The
// list is RSA-keyed because OFCS's DisallowInsecureCipher condition
// rejects ECDSA variants even though FAPI 1.0 lists them.
func TestFAPITLSConfig_TLS12FloorAndAllowlist(t *testing.T) {
	t.Parallel()

	cfg := op.FAPITLSConfig()
	if cfg == nil {
		t.Fatal("FAPITLSConfig returned nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		t.Errorf("MaxVersion = %#x caps below TLS 1.3", cfg.MaxVersion)
	}
	want := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	if len(cfg.CipherSuites) != len(want) {
		t.Fatalf("CipherSuites length = %d, want %d", len(cfg.CipherSuites), len(want))
	}
	for i, c := range cfg.CipherSuites {
		if c != want[i] {
			t.Errorf("CipherSuites[%d] = %#x, want %#x", i, c, want[i])
		}
	}
}

// TestFAPITLSConfig_ReturnsFreshConfig asserts repeated calls return
// independent values so a caller mutating MinVersion / CipherSuites
// on one returned config does not contaminate the next.
func TestFAPITLSConfig_ReturnsFreshConfig(t *testing.T) {
	t.Parallel()

	a := op.FAPITLSConfig()
	b := op.FAPITLSConfig()
	if a == b {
		t.Fatal("FAPITLSConfig returned the same pointer twice")
	}
	a.CipherSuites[0] = 0
	if b.CipherSuites[0] == 0 {
		t.Fatal("mutation on one config bled into the next")
	}
}

// TestFAPITLSConfig_Handshakes drives real handshakes against a
// listener using the helper: a default client lands on TLS 1.3, and a
// TLS 1.2 client offering only a suite outside the allowlist is
// refused.
func TestFAPITLSConfig_Handshakes(t *testing.T) {
	t.Parallel()

	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = op.FAPITLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()

	dial := func(cfg *tls.Config) (*tls.Conn, error) {
		conn, err := (&tls.Dialer{Config: cfg}).DialContext(t.Context(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		return conn.(*tls.Conn), nil
	}

	//nolint:gosec // G402: the test server's certificate is self-signed; only protocol negotiation is under test.
	conn, err := dial(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("default client handshake: %v", err)
	}
	if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Errorf("negotiated version = %#x, want TLS 1.3", v)
	}
	_ = conn.Close()

	//nolint:gosec // G402: see above; the TLS 1.2 cap is the point of this probe.
	conn, err = dial(&tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("TLS 1.2 handshake with a suite outside the allowlist succeeded")
	}
}

// TestLoadPublicJWKS_NormalizesAsymmetricKeys writes private RSA, EC,
// and OKP JWKs, then asserts the result contains exactly the
// key-type public members and standard public metadata. In
// particular, RSA "oth" and unknown extensions prove normalization
// is an allowlist rather than an incomplete private-member denylist.
func TestLoadPublicJWKS_NormalizesAsymmetricKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	input := `{
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "ec-1",
                "use": "sig",
                "key_ops": ["verify"],
                "alg": "ES256",
                "x": "tn47XpuJUkfY7CDSmu5fayO7EnPvG9u9uqVb-Ifmthc",
                "y": "k5a3GEPNL35HRcw-Ajt5rfJ5llU7HomRBQfWWroFva8",
                "d": "ec-private",
                "private_extension": "ec-extension-private"
            },
            {
                "kty": "RSA",
                "kid": "rsa-1",
                "x5u": "https://client.example/jwk.pem",
                "x5c": ["public-certificate"],
                "x5t": "sha1-thumbprint",
                "x5t#S256": "sha256-thumbprint",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
                "e": "AQAB",
                "d": "rsa-private",
                "p": "rsa-private-p",
                "q": "rsa-private-q",
                "dp": "rsa-private-dp",
                "dq": "rsa-private-dq",
                "qi": "rsa-private-qi",
                "oth": [{"r": "rsa-private-r", "d": "rsa-private-d", "t": "rsa-private-t"}],
                "k": "not-an-rsa-public-member",
                "private_extension": "rsa-extension-private"
            },
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "okp-1",
                "x": "11qYAYLefBMpvp2a-MHyU-JbJwkYxH5rE9t6qYSfHAo",
                "d": "okp-private",
                "private_extension": "okp-extension-private"
            }
        ]
    }`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := op.LoadPublicJWKS(path)
	if err != nil {
		t.Fatalf("LoadPublicJWKS: %v", err)
	}

	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("re-parse output: %v", err)
	}
	if len(parsed.Keys) != 3 {
		t.Fatalf("Keys length = %d, want 3", len(parsed.Keys))
	}

	wantMembers := [][]string{
		{"kty", "crv", "kid", "use", "key_ops", "alg", "x", "y"},
		{"kty", "kid", "x5u", "x5c", "x5t", "x5t#S256", "n", "e"},
		{"kty", "crv", "kid", "x"},
	}
	for i, key := range parsed.Keys {
		if len(key) != len(wantMembers[i]) {
			t.Errorf("Keys[%d] member count = %d, want %d: %v", i, len(key), len(wantMembers[i]), key)
		}
		for _, member := range wantMembers[i] {
			if _, ok := key[member]; !ok {
				t.Errorf("Keys[%d] lost allowed public member %q: %v", i, member, key)
			}
		}
	}

	for _, secret := range []string{
		"ec-private",
		"ec-extension-private",
		"rsa-private",
		"rsa-private-p",
		"rsa-private-q",
		"rsa-private-dp",
		"rsa-private-dq",
		"rsa-private-qi",
		"rsa-private-r",
		"rsa-private-d",
		"rsa-private-t",
		"not-an-rsa-public-member",
		"rsa-extension-private",
		"okp-private",
		"okp-extension-private",
	} {
		if strings.Contains(string(out), secret) {
			t.Errorf("normalized JWKS still contains private fixture %q: %s", secret, out)
		}
	}
}

// TestLoadPublicJWKS_RejectsSymmetricKey proves an oct JWK is not
// transformed into an empty or metadata-only key. Its "k" member is
// the key itself, so a public-half representation cannot exist.
func TestLoadPublicJWKS_RejectsSymmetricKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "oct-private.json")
	input := `{"keys":[{"kty":"oct","kid":"symmetric-1","alg":"HS256","k":"oct-private-material"}]}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := op.LoadPublicJWKS(path)
	if err == nil {
		t.Fatalf("expected symmetric-key rejection, got output %s", out)
	}
	if out != nil {
		t.Errorf("output = %s, want nil after symmetric-key rejection", out)
	}
	var e *op.Error
	if !errors.As(err, &e) {
		t.Fatalf("error is not *op.Error: %v", err)
	}
	if !strings.Contains(e.Description, "symmetric oct") {
		t.Errorf("description=%q must identify the unsupported symmetric key shape", e.Description)
	}
	if strings.Contains(e.Description, "oct-private-material") {
		t.Errorf("description=%q leaks symmetric key material", e.Description)
	}
}

// TestLoadPublicJWKS_RejectsUnsupportedKeyType ensures an unknown
// key type is rejected instead of passing members whose public or
// private meaning LoadPublicJWKS cannot know.
func TestLoadPublicJWKS_RejectsUnsupportedKeyType(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "unknown-kty.json")
	input := `{"keys":[{"kty":"future-private-type","kid":"future-1","secret":"private-material"}]}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := op.LoadPublicJWKS(path)
	if err == nil {
		t.Fatalf("expected unsupported-key rejection, got output %s", out)
	}
	if out != nil {
		t.Errorf("output = %s, want nil after unsupported-key rejection", out)
	}
	var e *op.Error
	if !errors.As(err, &e) {
		t.Fatalf("error is not *op.Error: %v", err)
	}
	if !strings.Contains(e.Description, "unsupported kty") {
		t.Errorf("description=%q must identify the unsupported key type", e.Description)
	}
	if strings.Contains(e.Description, "private-material") {
		t.Errorf("description=%q leaks unknown key material", e.Description)
	}
}

// TestLoadPublicJWKS_RejectsMissingFile asserts the helper wraps a
// missing-file error in a configuration_error [*op.Error] and
// includes the path in the description so operators can locate the
// bad input. The error description MUST NOT carry key material —
// here we only inspect that the path is mentioned.
func TestLoadPublicJWKS_RejectsMissingFile(t *testing.T) {
	t.Parallel()

	_, err := op.LoadPublicJWKS(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	var e *op.Error
	if !errors.As(err, &e) {
		t.Fatalf("error is not *op.Error: %v", err)
	}
	if !strings.Contains(e.Description, "absent.json") {
		t.Errorf("description=%q must mention the missing file path", e.Description)
	}
}

// TestLoadPublicJWKS_RejectsMalformedJSON asserts non-JSON input
// surfaces as a configuration_error wrapping the parser failure.
func TestLoadPublicJWKS_RejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := op.LoadPublicJWKS(path)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	var e *op.Error
	if !errors.As(err, &e) {
		t.Fatalf("error is not *op.Error: %v", err)
	}
	if !strings.Contains(e.Description, "bad.json") {
		t.Errorf("description=%q must mention the offending file path", e.Description)
	}
}

// TestLoadPublicJWKS_RejectsEmptyKeyset asserts a JWKS file with an
// empty "keys" array produces a configuration_error so a typo in
// generation does not silently register a client without a usable
// key.
func TestLoadPublicJWKS_RejectsEmptyKeyset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := op.LoadPublicJWKS(path)
	if err == nil {
		t.Fatal("expected error for empty keyset, got nil")
	}
	var e *op.Error
	if !errors.As(err, &e) {
		t.Fatalf("error is not *op.Error: %v", err)
	}
	if !strings.Contains(e.Description, "no keys") {
		t.Errorf("description=%q must explain the empty keyset", e.Description)
	}
}

// TestLoadPublicJWKS_DoesNotLeakAbsolutePath pins the contract that
// the error description MUST identify the bad file by its base name
// only, never by its absolute filesystem path. A leaked path lets an
// attacker who reads error_description / audit logs map the host's
// directory layout, which the OP must not expose.
//
// The check covers filesystem, syntax, empty-set, and key-shape
// errors so a future refactor must keep the pattern across branches.
func TestLoadPublicJWKS_DoesNotLeakAbsolutePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Verify that the temp dir genuinely produces an absolute path so
	// the assertion below has teeth.
	probe := filepath.Join(dir, "probe.json")
	if !filepath.IsAbs(probe) {
		t.Fatalf("test setup: t.TempDir produced a non-absolute path %q", probe)
	}

	cases := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{
			name: "missing file",
			setup: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(dir, "missing-secret-tenant.json")
			},
		},
		{
			name: "malformed json",
			setup: func(t *testing.T) string {
				t.Helper()
				p := filepath.Join(dir, "broken-secret-tenant.json")
				if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				return p
			},
		},
		{
			name: "empty keyset",
			setup: func(t *testing.T) string {
				t.Helper()
				p := filepath.Join(dir, "blank-secret-tenant.json")
				if err := os.WriteFile(p, []byte(`{"keys":[]}`), 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				return p
			},
		},
		{
			name: "symmetric key",
			setup: func(t *testing.T) string {
				t.Helper()
				p := filepath.Join(dir, "oct-secret-tenant.json")
				input := `{"keys":[{"kty":"oct","k":"private-material"}]}`
				if err := os.WriteFile(p, []byte(input), 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				return p
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := tc.setup(t)
			_, err := op.LoadPublicJWKS(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var e *op.Error
			if !errors.As(err, &e) {
				t.Fatalf("error is not *op.Error: %v", err)
			}
			if strings.Contains(e.Description, dir) {
				t.Errorf("description=%q leaks the absolute directory %q", e.Description, dir)
			}
			base := filepath.Base(path)
			if !strings.Contains(e.Description, base) {
				t.Errorf("description=%q must mention the base name %q so operators can locate the bad input", e.Description, base)
			}
		})
	}
}
