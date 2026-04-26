// Package jose wraps the third-party JOSE implementation used by the
// library. Every signing or verification path in the codebase MUST go
// through this package; direct imports of the underlying library from
// feature packages are forbidden by depguard so that we have a single
// place to enforce algorithm allow-lists, JWS header policy, and key
// rotation semantics.
package jose

// Algorithm is the type-driven enumeration of signing algorithms accepted
// anywhere in this codebase. Storing the value on the wire is fine, but
// every place that *acts* on an algorithm name (header parsing, signer
// selection, verification) MUST go through this type.
//
// "none" is intentionally absent. There is no zero-value-as-none; the zero
// value is [AlgUnspecified] and is rejected at every entry point. This
// closes RFC 7519 §6 / RFC 8725 §2.1 algorithm-confusion attacks
// structurally rather than through runtime checks.
type Algorithm string

const (
	// AlgUnspecified is the zero value. It is never a valid choice and
	// every codepath that reads an algorithm MUST reject it.
	AlgUnspecified Algorithm = ""

	// AlgRS256 is RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3).
	// Allowed for OIDC Core compatibility; FAPI 2.0 prefers PS256.
	AlgRS256 Algorithm = "RS256"

	// AlgPS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	// (RFC 7518 §3.5). Required by FAPI 2.0 Message Signing.
	AlgPS256 Algorithm = "PS256"

	// AlgES256 is ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
	AlgES256 Algorithm = "ES256"

	// AlgEdDSA is Edwards-curve DSA, RFC 8037. Implementations MUST use
	// Ed25519; Ed448 is not enabled.
	AlgEdDSA Algorithm = "EdDSA"
)

// IsAllowed reports whether a is one of the algorithms enabled in this
// codebase. Symmetric algorithms (HS256/384/512) and "none" are never
// allowed and therefore always return false. The check is constant-time
// over the small allow-list rather than a map lookup so that nothing in
// the codebase can register a new algorithm at runtime.
func (a Algorithm) IsAllowed() bool {
	switch a {
	case AlgRS256, AlgPS256, AlgES256, AlgEdDSA:
		return true
	case AlgUnspecified:
		return false
	default:
		return false
	}
}

// String returns the wire form of the algorithm. The empty string is the
// canonical representation of [AlgUnspecified] — callers MUST treat that
// value as invalid.
func (a Algorithm) String() string { return string(a) }

// ParseAlgorithm converts a JWS "alg" header value into an [Algorithm].
// It returns ([AlgUnspecified], false) for unknown values, "none", and the
// HMAC family. Callers MUST treat ok=false as a hard rejection — never as
// an opportunity to fall back to an alternative algorithm.
func ParseAlgorithm(s string) (Algorithm, bool) {
	a := Algorithm(s)
	if !a.IsAllowed() {
		return AlgUnspecified, false
	}
	return a, true
}
