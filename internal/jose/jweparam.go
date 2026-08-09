package jose

// JWE key-management algorithms (`alg` header) and content-encryption
// algorithms (`enc` header) accepted by this package. The two
// allow-lists are intentionally small and asymmetric-only:
//
//   - Asymmetric `alg`s (RSA-OAEP-* family, ECDH-ES family) avoid the
//     symmetric-secret derivation patterns that pair badly with our
//     "client_secret is increasingly optional" stance.
//   - AES-GCM `enc` values avoid the AES-CBC-HS family entirely so the
//     padding-oracle attack surface is structurally absent.
//
// Algorithms outside the allow-list cannot be added at runtime;
// extending the lists requires editing this file and re-running the
// allow-list tests.

// JWEAlg names a JWE key-management algorithm (`alg` header).
//
// The string form matches RFC 7518 §4 verbatim so values can be
// embedded in JWE headers and discovery documents without conversion.
type JWEAlg string

// JWEEnc names a JWE content-encryption algorithm (`enc` header).
//
// The string form matches RFC 7518 §5 verbatim so values can be
// embedded in JWE headers and discovery documents without conversion.
type JWEEnc string

// Allowed JWE key-management algorithms. The list is closed: every
// `alg` outside this set is rejected before any cryptographic
// operation runs.
const (
	// JWEAlgRSAOAEP256 is RSAES OAEP using SHA-256 and MGF1 with
	// SHA-256 (RFC 7518 §4.3 / RFC 8017). The default for RP
	// compatibility.
	JWEAlgRSAOAEP256 JWEAlg = "RSA-OAEP-256"

	// JWEAlgECDHES is ECDH-ES direct key agreement (no key wrap)
	// (RFC 7518 §4.6). Supports P-256 / P-384 / P-521 EC keys.
	JWEAlgECDHES JWEAlg = "ECDH-ES"

	// JWEAlgECDHESA128KW is ECDH-ES with AES-128 key wrap
	// (RFC 7518 §4.6).
	JWEAlgECDHESA128KW JWEAlg = "ECDH-ES+A128KW"

	// JWEAlgECDHESA256KW is ECDH-ES with AES-256 key wrap
	// (RFC 7518 §4.6).
	JWEAlgECDHESA256KW JWEAlg = "ECDH-ES+A256KW"
)

// Allowed JWE content-encryption algorithms. The list is closed.
const (
	// JWEEncA128GCM is AES-128 in GCM mode (RFC 7518 §5.3).
	// Widely interoperable; preferred for legacy RP support.
	JWEEncA128GCM JWEEnc = "A128GCM"

	// JWEEncA256GCM is AES-256 in GCM mode (RFC 7518 §5.3).
	// Preferred for new deployments.
	JWEEncA256GCM JWEEnc = "A256GCM"
)

// IsAllowed reports whether a is on the JWE `alg` allow-list.
//
// The check is constant-time over the small allow-list rather than a
// map lookup so that nothing in the codebase can register a new
// algorithm at runtime.
func (a JWEAlg) IsAllowed() bool {
	switch a {
	case JWEAlgRSAOAEP256, JWEAlgECDHES, JWEAlgECDHESA128KW, JWEAlgECDHESA256KW:
		return true
	default:
		return false
	}
}

// String returns the wire form of a.
func (a JWEAlg) String() string { return string(a) }

// IsAllowed reports whether e is on the JWE `enc` allow-list.
func (e JWEEnc) IsAllowed() bool {
	switch e {
	case JWEEncA128GCM, JWEEncA256GCM:
		return true
	default:
		return false
	}
}

// String returns the wire form of e.
func (e JWEEnc) String() string { return string(e) }

// ParseJWEAlg converts a JWE `alg` header value into a [JWEAlg]. It
// returns ([JWEAlg](""), false) for any value outside the allow-list,
// including the deliberately excluded `RSA1_5`, `dir`, `A*KW`, `A*GCMKW`,
// and `none`. Callers MUST treat ok=false as a hard rejection.
func ParseJWEAlg(s string) (JWEAlg, bool) {
	a := JWEAlg(s)
	if !a.IsAllowed() {
		return JWEAlg(""), false
	}
	return a, true
}

// ParseJWEEnc converts a JWE `enc` header value into a [JWEEnc]. It
// returns ([JWEEnc](""), false) for any value outside the allow-list,
// including the deliberately excluded `A128CBC-HS256`, `A192*`, and
// `A256CBC-HS512`. Callers MUST treat ok=false as a hard rejection.
func ParseJWEEnc(s string) (JWEEnc, bool) {
	e := JWEEnc(s)
	if !e.IsAllowed() {
		return JWEEnc(""), false
	}
	return e, true
}

// AllowedJWEAlgs returns the closed list of JWE `alg` values this
// package accepts. The slice is the canonical source for discovery
// `*_encryption_alg_values_supported` advertisements.
//
// The function returns a fresh slice on every call so callers cannot
// mutate the package-internal allow-list.
func AllowedJWEAlgs() []JWEAlg {
	return []JWEAlg{
		JWEAlgRSAOAEP256,
		JWEAlgECDHES,
		JWEAlgECDHESA128KW,
		JWEAlgECDHESA256KW,
	}
}

// AllowedJWEEncs returns the closed list of JWE `enc` values this
// package accepts. The slice is the canonical source for discovery
// `*_encryption_enc_values_supported` advertisements.
func AllowedJWEEncs() []JWEEnc {
	return []JWEEnc{
		JWEEncA128GCM,
		JWEEncA256GCM,
	}
}

// JWEPolicy is the deployment-level narrowing of the package
// allow-lists. The package lists above are the ceiling and cannot be
// widened; a policy only removes values from them.
//
// The zero value permits everything the package permits, so a caller
// that never narrows can pass a zero [JWEPolicy] and keep the library
// default. A nil slice means "no narrowing for this half"; an empty
// non-nil slice means "permit nothing", which is how an operator
// disables JWE negotiation without also removing the keyset.
//
// One policy value is shared by every surface that negotiates JWE —
// inbound decryption ([Decrypt] via [EncryptionPolicyResolver]),
// outbound recipient selection, and the client-registration validator —
// so an operator-imposed restriction cannot hold on one surface while
// another silently keeps accepting the excluded value.
type JWEPolicy struct {
	// Algs narrows the key-management algorithms. Nil leaves
	// [AllowedJWEAlgs] in force.
	Algs []JWEAlg

	// Encs narrows the content-encryption algorithms. Nil leaves
	// [AllowedJWEEncs] in force.
	Encs []JWEEnc
}

// AllowsAlg reports whether a survives both the package allow-list and
// the policy narrowing.
func (p JWEPolicy) AllowsAlg(a JWEAlg) bool {
	if !a.IsAllowed() {
		return false
	}
	if p.Algs == nil {
		return true
	}
	for _, allowed := range p.Algs {
		if allowed == a {
			return true
		}
	}
	return false
}

// AllowsEnc reports whether e survives both the package allow-list and
// the policy narrowing.
func (p JWEPolicy) AllowsEnc(e JWEEnc) bool {
	if !e.IsAllowed() {
		return false
	}
	if p.Encs == nil {
		return true
	}
	for _, allowed := range p.Encs {
		if allowed == e {
			return true
		}
	}
	return false
}

// ParseJWEAlgPolicy converts the wire form of a JWE `alg` into a
// [JWEAlg] and applies p in one step. It returns ok=false for a value
// outside the package allow-list and for a value the policy removed;
// callers MUST treat both the same way, because the distinction is
// operator configuration an unauthenticated peer has no business
// learning.
func ParseJWEAlgPolicy(s string, p JWEPolicy) (JWEAlg, bool) {
	a, ok := ParseJWEAlg(s)
	if !ok || !p.AllowsAlg(a) {
		return JWEAlg(""), false
	}
	return a, true
}

// ParseJWEEncPolicy mirrors [ParseJWEAlgPolicy] for the JWE `enc`
// header.
func ParseJWEEncPolicy(s string, p JWEPolicy) (JWEEnc, bool) {
	e, ok := ParseJWEEnc(s)
	if !ok || !p.AllowsEnc(e) {
		return JWEEnc(""), false
	}
	return e, true
}
