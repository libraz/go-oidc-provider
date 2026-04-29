package op_test

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestFAPITLSConfig_PinsTLS12 asserts the helper returns a
// configuration that pins TLS to v1.2 and lists exactly the FAPI 1.0
// Advanced §8.5 ECDHE_RSA AEAD allowlist. The list is RSA-keyed
// because OFCS's DisallowInsecureCipher condition rejects ECDSA
// variants even though FAPI 1.0 lists them.
func TestFAPITLSConfig_PinsTLS12(t *testing.T) {
	t.Parallel()

	cfg := op.FAPITLSConfig()
	if cfg == nil {
		t.Fatal("FAPITLSConfig returned nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.MaxVersion != tls.VersionTLS12 {
		t.Errorf("MaxVersion = %#x, want %#x", cfg.MaxVersion, tls.VersionTLS12)
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

// TestLoadPublicJWKS_StripsPrivateParams writes a JWKS with an EC
// private key (with "d") and an RSA-shaped private key (with d, p,
// q, dp, dq, qi) to a temp file, loads it, and asserts every
// private parameter is stripped while public parameters survive.
func TestLoadPublicJWKS_StripsPrivateParams(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	input := `{
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "ec-1",
                "x": "tn47XpuJUkfY7CDSmu5fayO7EnPvG9u9uqVb-Ifmthc",
                "y": "k5a3GEPNL35HRcw-Ajt5rfJ5llU7HomRBQfWWroFva8",
                "d": "jJIxf76uD4dK01r2oxsG5fv1XjOZFdJpdWWUuSh5Dxs"
            },
            {
                "kty": "RSA",
                "kid": "rsa-1",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
                "e": "AQAB",
                "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD",
                "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQB",
                "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobL",
                "dp": "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0o",
                "dq": "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huU",
                "qi": "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYz"
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
	if len(parsed.Keys) != 2 {
		t.Fatalf("Keys length = %d, want 2", len(parsed.Keys))
	}
	for i, k := range parsed.Keys {
		for _, p := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, ok := k[p]; ok {
				t.Errorf("Keys[%d] still carries %q: %v", i, p, k[p])
			}
		}
	}
	// Public parameters survive.
	ec := parsed.Keys[0]
	if ec["kty"] != "EC" || ec["crv"] != "P-256" || ec["kid"] != "ec-1" {
		t.Errorf("EC public params lost: %v", ec)
	}
	if _, ok := ec["x"]; !ok {
		t.Error("EC x lost")
	}
	if _, ok := ec["y"]; !ok {
		t.Error("EC y lost")
	}
	rsa := parsed.Keys[1]
	if rsa["kty"] != "RSA" || rsa["kid"] != "rsa-1" {
		t.Errorf("RSA public params lost: %v", rsa)
	}
	if _, ok := rsa["n"]; !ok {
		t.Error("RSA n lost")
	}
	if _, ok := rsa["e"]; !ok {
		t.Error("RSA e lost")
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

// TestLoadPublicJWKS_DoesNotLeakAbsolutePath pins the F-4 contract:
// the error description MUST identify the bad file by its base name
// only, never by its absolute filesystem path. A leaked path lets an
// attacker who reads error_description / audit logs map the host's
// directory layout, which the OP must not expose.
//
// The check covers all three error paths LoadPublicJWKS can take —
// missing file, malformed JSON, empty keyset — so a future refactor
// that adds a fourth branch must keep the pattern.
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
