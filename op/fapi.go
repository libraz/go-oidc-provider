package op

import (
	"crypto/tls"
	"encoding/json"
	"os"
)

// jwkPrivateParams enumerates the JWK members that hold private key
// material across the alg families the library cares about: "d" is
// the EC private scalar (RFC 7518 §6.2.2) and the RSA private
// exponent (RFC 7518 §6.3.2.1); "p", "q", "dp", "dq", "qi" are the
// RSA-only CRT parameters (RFC 7518 §6.3.2.2-§6.3.2.6).
// [LoadPublicJWKS] strips every entry so a public-half JWKS never
// carries private material by accident.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var jwkPrivateParams = []string{"d", "p", "q", "dp", "dq", "qi"}

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

// LoadPublicJWKS reads a JSON Web Key Set from path and returns the
// JSON bytes with every private parameter removed. The helper exists
// so an embedder registering a `private_key_jwt` client can hand the
// OP only the public half of the key — the private material lives in
// the client's signing pipeline, never on the AS.
//
// The stripped parameters are:
//
//   - "d" (EC and RSA private exponent / scalar; RFC 7518 §6.2.2 / §6.3.2)
//   - "p", "q", "dp", "dq", "qi" (RSA-only CRT parameters; RFC 7518 §6.3.2)
//
// All other JWK members (kty, crv, x, y, n, e, kid, use, alg, …) are
// preserved verbatim so the resulting bytes are a valid JWK Set the
// OP can register on [store.Client.JWKs].
//
// The error path is intentionally narrow: failures wrap the file
// path so the operator can locate the bad input, but no key
// material — public or otherwise — is ever logged or formatted into
// the error message.
func LoadPublicJWKS(path string) ([]byte, error) {
	//nolint:gosec // G304: path is operator-supplied at construction time.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: read " + path,
			Cause:       err,
		}
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: parse " + path,
			Cause:       err,
		}
	}
	if len(set.Keys) == 0 {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: " + path + " contains no keys",
		}
	}
	for _, k := range set.Keys {
		for _, p := range jwkPrivateParams {
			delete(k, p)
		}
	}
	out, err := json.Marshal(set)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "LoadPublicJWKS: marshal " + path,
			Cause:       err,
		}
	}
	return out, nil
}
