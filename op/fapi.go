package op

import (
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
)

// FAPITLSConfig returns the [*tls.Config] FAPI 2.0 §6.1.2 mandates
// for an authorization server endpoint: TLS 1.2 only with the
// FAPI 1.0 Advanced §8.5 ECDHE_RSA AEAD allowlist.
//
// MinVersion and MaxVersion are both pinned at [tls.VersionTLS12]
// because Go's TLS 1.3 cipher list is not configurable, so the only
// way to keep CHACHA20_POLY1305 (which is not on the FAPI allowlist)
// off the wire is to negotiate TLS 1.2. The cipher list is
// RSA-keyed because the OFCS DisallowInsecureCipher condition follows
// the strict FAPI 1.0 RW allowlist (RSA-keyed AEAD only) and the
// matching deployment must therefore use an RSA server certificate.
//
// Embedders running an mTLS-only or ECDSA-cert deployment may layer
// stricter / different cipher choices on top by composing their own
// [*tls.Config]; the helper exists so the common FAPI conformance
// case is one line instead of fifteen.
func FAPITLSConfig() *tls.Config {
	//nolint:gosec // G402: deliberate TLS-1.2 cap so the FAPI 1.0 RW cipher allowlist applies.
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// LoadPublicJWKS reads a JSON Web Key Set from path and returns a
// public-only normalized JWK Set. The helper exists so an embedder
// registering a `private_key_jwt` client can hand the OP only the
// public half of the key — the private material lives in the
// client's signing pipeline, never on the AS.
//
// RSA, EC, and OKP keys are accepted. Each output key is constructed
// from a key-type-specific allowlist:
//
//   - RSA: "n" and "e"
//   - EC: "crv", "x", and "y"
//   - OKP: "crv" and "x"
//
// The standard public metadata members "kty", "use", "key_ops",
// "alg", "kid", "x5u", "x5c", "x5t", and "x5t#S256" are also
// retained. All other members are discarded rather than relying on
// a private-parameter denylist. Symmetric "oct" keys and unsupported
// or missing key types are rejected because they cannot have a
// public half.
//
// The error path is intentionally narrow: failures identify the file
// by its base name (via [filepath.Base]) so the operator can locate
// the bad input without leaking the directory layout of the host
// (audit logs / error_description responses MUST NOT carry an
// absolute filesystem path that would expose host directory
// layout). No key material —
// public or otherwise — is ever logged or formatted into the error
// message.
func LoadPublicJWKS(path string) ([]byte, error) {
	base := filepath.Base(path)
	//nolint:gosec // G304: path is operator-supplied at construction time.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: read " + base,
			Cause:       err,
		}
	}
	var input struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: parse " + base,
			Cause:       err,
		}
	}
	if len(input.Keys) == 0 {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: " + base + " contains no keys",
		}
	}

	output := struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}{
		Keys: make([]map[string]json.RawMessage, 0, len(input.Keys)),
	}
	for _, key := range input.Keys {
		publicKey, reason := normalizePublicJWK(key)
		if reason != "" {
			return nil, &Error{
				Code:        codeConfiguration,
				Description: "LoadPublicJWKS: " + base + " " + reason,
			}
		}
		output.Keys = append(output.Keys, publicKey)
	}

	out, err := json.Marshal(output)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: marshal " + base,
			Cause:       err,
		}
	}
	return out, nil
}

func normalizePublicJWK(key map[string]json.RawMessage) (map[string]json.RawMessage, string) {
	var keyType string
	if err := json.Unmarshal(key["kty"], &keyType); err != nil || keyType == "" {
		return nil, "contains a key with missing or invalid kty"
	}

	commonMembers := []string{
		"kty",
		"use",
		"key_ops",
		"alg",
		"kid",
		"x5u",
		"x5c",
		"x5t",
		"x5t#S256",
	}
	var keyTypeMembers []string
	switch keyType {
	case "RSA":
		keyTypeMembers = []string{"n", "e"}
	case "EC":
		keyTypeMembers = []string{"crv", "x", "y"}
	case "OKP":
		keyTypeMembers = []string{"crv", "x"}
	case "oct":
		return nil, "contains a symmetric oct key"
	default:
		return nil, "contains a key with unsupported kty"
	}

	publicKey := make(map[string]json.RawMessage, len(commonMembers)+len(keyTypeMembers))
	for _, member := range commonMembers {
		if value, ok := key[member]; ok {
			publicKey[member] = value
		}
	}
	for _, member := range keyTypeMembers {
		if value, ok := key[member]; ok {
			publicKey[member] = value
		}
	}
	return publicKey, ""
}
