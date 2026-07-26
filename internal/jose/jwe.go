package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	josev4 "github.com/go-jose/go-jose/v4"
)

// MaxJWEPlaintextSize caps the plaintext size returned by [Decrypt]
// to 1 MiB. Larger plaintexts are rejected with [ErrJWEPlaintextTooLarge],
// defending against compression-bomb attacks via `zip=DEF` (RFC 7516
// §4.1.3) where a small ciphertext could decompress to a multi-GiB
// plaintext. The cap also limits memory pressure under generic
// large-payload denial-of-service attempts.
const MaxJWEPlaintextSize = 1 << 20

// MaxKidlessTrialKeys caps the number of private keys [Decrypt] will trial
// when the JWE protected header omits `kid`. RFC 7516 §4.1.6 makes `kid`
// OPTIONAL, so kid-less ciphertexts are accepted, but the candidate set is
// pre-filtered by matching the protected-header `alg` against each private
// key's type (RSA vs EC) and the surviving slice is bounded by this cap so
// one attacker-supplied ciphertext cannot amplify CPU work across an
// unbounded keyset.
const MaxKidlessTrialKeys = 4

// MaxJOSENestingDepth bounds the total number of JOSE layers
// [DecryptChain] is willing to traverse when peeling a nested
// JWE-of-JWE-of-...-of-JWS chain. RFC 7519 §5.2 (`cty=JWT`) admits
// arbitrary nesting in principle; in practice every shape the OP
// receives or emits flattens to at most 2 layers (one JWE wrapping
// one JWS). The 10-layer ceiling absorbs a generous future expansion
// while keeping a malicious input from forcing the verifier into a
// stack that the per-layer 1 MiB plaintext cap alone cannot bound
// (10 layers × 1 MiB still fits a single request budget; an unbounded
// chain does not).
//
// The counter increments once per JOSE layer the verifier traverses:
// a single JWE wrapping a JWS counts as depth=2 (the JWE plus the
// inner JWS), JWE-of-JWE-of-JWS counts as depth=3, and so on. The
// 11th layer is rejected with [ErrJWENestingTooDeep].
const MaxJOSENestingDepth = 10

// JWE-related sentinel errors. Callers branch on these via
// [errors.Is]; the wrapped detail is safe to log but MUST NOT be
// returned to clients.
var (
	// ErrJWEMalformed indicates the input was not a syntactically
	// valid compact-serialised JWE: wrong number of parts, invalid
	// base64 in the protected header, or unparseable JSON in the
	// header.
	ErrJWEMalformed = errors.New("jose: malformed JWE")

	// ErrJWEAlgNotAllowed indicates the JWE protected header carries
	// an `alg` value outside [AllowedJWEAlgs] — typically `RSA1_5`,
	// `dir`, `A*KW`, `A*GCMKW`, or `none`.
	ErrJWEAlgNotAllowed = errors.New("jose: JWE alg not allowed")

	// ErrJWEEncNotAllowed indicates the JWE protected header carries
	// an `enc` value outside [AllowedJWEEncs] — typically
	// `A128CBC-HS256`, `A192*`, or `A256CBC-HS512`.
	ErrJWEEncNotAllowed = errors.New("jose: JWE enc not allowed")

	// ErrJWECritUnknown indicates the JWE protected header carries a
	// `crit` extension this package does not understand. RFC 7516
	// §4.1.13 (referencing RFC 7515 §4.1.11) requires verifiers to
	// reject any unknown critical extension. The package's understood
	// set is intentionally empty: no JWE the OP emits or accepts uses
	// `crit`.
	ErrJWECritUnknown = errors.New("jose: JWE crit not allowed")

	// ErrJWEKidUnknown indicates the JWE protected header named a
	// `kid` that does not resolve through the supplied
	// [EncryptionKeyResolver], OR (for kid-less ciphertexts) no
	// private key in the keyset matched the protected-header `alg`.
	// When `kid` is absent and at least one keyset entry matches
	// `alg`, the package falls back to bounded trial decryption (see
	// [MaxKidlessTrialKeys] and [Decrypt] doc).
	ErrJWEKidUnknown = errors.New("jose: JWE kid unknown")

	// ErrJWEDecryptFailed indicates ciphertext authentication or
	// content decryption failed. The error message is intentionally
	// uniform across all failure modes (wrong key, modified
	// ciphertext, mismatched tag) to limit padding-oracle and
	// key-oracle leakage. Detailed cause goes to the audit log only.
	ErrJWEDecryptFailed = errors.New("jose: JWE decryption failed")

	// ErrJWEPlaintextTooLarge indicates the decrypted plaintext
	// exceeds [MaxJWEPlaintextSize]. Returned both for raw plaintext
	// and for `zip=DEF`-decompressed plaintext after go-jose's
	// upstream cap is satisfied.
	ErrJWEPlaintextTooLarge = errors.New("jose: JWE plaintext exceeds size cap")

	// ErrJWENestingTooDeep indicates [DecryptChain] reached the
	// [MaxJOSENestingDepth] ceiling while peeling nested JWE layers.
	// The error fires on the 11th layer; the first 10 are accepted
	// uniformly. The class exists so the JAR / PAR wire layer can
	// surface invalid_request_object without an attacker learning
	// (via timing or error-code variation) where in the chain the
	// limit fired.
	ErrJWENestingTooDeep = errors.New("jose: JWE nesting exceeds depth cap")
)

// EncryptionKeyResolver looks up a private encryption key by its
// `kid`. Implementations wrap an embedder-supplied keyset (use=enc
// only) and live alongside the decryption-driving handler.
//
// Resolve returns the private key paired with the given kid, or
// ok=false when the kid is not known. A retired key MUST be reported
// as not-found so [Decrypt] surfaces [ErrJWEKidUnknown] uniformly.
//
// All returns the full slice of private keys in rotation order
// (newest first). [Decrypt] invokes All only when the protected
// header omits `kid` (RFC 7516 §4.1.6 permits omission), and only
// after filtering candidates by matching the header `alg` to each
// private key's type. The number of trial decrypts on this path is
// bounded by [MaxKidlessTrialKeys] so a kid-less ciphertext cannot
// amplify CPU work across an unbounded keyset.
type EncryptionKeyResolver interface {
	Resolve(kid string) (priv any, ok bool)
	All() []any
}

// EncryptionKeyResolverFunc adapts a free function plus a key-list
// slice into [EncryptionKeyResolver]. It exists for callers that
// already maintain their own keyset rotation logic.
type EncryptionKeyResolverFunc struct {
	ResolveFn func(kid string) (any, bool)
	AllFn     func() []any
}

// Resolve calls the wrapped ResolveFn.
func (f EncryptionKeyResolverFunc) Resolve(kid string) (any, bool) {
	if f.ResolveFn == nil {
		return nil, false
	}
	return f.ResolveFn(kid)
}

// All calls the wrapped AllFn.
func (f EncryptionKeyResolverFunc) All() []any {
	if f.AllFn == nil {
		return nil
	}
	return f.AllFn()
}

// DecryptedJWE is the result of a successful [Decrypt] call. It
// carries the verified plaintext alongside the protected-header
// fields the caller most often needs (kid for audit, alg/enc for
// observability, cty for nested-JWS dispatch).
//
// Plaintext is bounded by [MaxJWEPlaintextSize]; callers do not need
// to apply their own cap.
type DecryptedJWE struct {
	Plaintext   []byte
	KeyID       string
	Algorithm   JWEAlg
	Encryption  JWEEnc
	ContentType string
}

// jweProtectedHeader mirrors the JOSE protected-header fields the OP
// inspects pre-decrypt. We pre-parse the header rather than relying
// on go-jose's accessors so the alg / enc / kid / crit checks are
// visible (and auditable) before any cryptographic operation runs.
//
// Fields outside this struct are tolerated: an attacker who adds an
// unknown header parameter cannot bypass the allow-list because the
// allow-list is enforced on the parsed value, not on header
// presence.
type jweProtectedHeader struct {
	Alg  string   `json:"alg"`
	Enc  string   `json:"enc"`
	Kid  string   `json:"kid"`
	Cty  string   `json:"cty,omitempty"`
	Zip  string   `json:"zip,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Decrypt parses, validates, and decrypts a compact-serialised JWE.
//
// Validation order:
//
//  1. Compact form syntax — exactly five base64url-encoded segments
//     separated by ".".
//  2. Protected header parses as JSON.
//  3. `crit` is absent or empty.
//  4. `alg` is on [AllowedJWEAlgs].
//  5. `enc` is on [AllowedJWEEncs].
//  6. `kid` resolves through resolver — or, when `kid` is absent,
//     trial decryption runs against the subset of [resolver.All] keys
//     whose type matches the protected-header `alg`, bounded by
//     [MaxKidlessTrialKeys]. The trial loop iterates to completion so
//     wall-clock timing cannot leak which key matched.
//  7. Decrypt; reject if plaintext exceeds [MaxJWEPlaintextSize].
//
// The hardening posture is "fail uniformly": every decryption failure
// returns [ErrJWEDecryptFailed] with a generic description. The
// detailed cause is wrapped via fmt.Errorf and is safe to log, but
// MUST NOT be echoed back to clients.
//
// Decrypt does NOT verify nested JWS content (the `cty=JWT` case).
// The caller inspects [DecryptedJWE.ContentType] and routes the
// payload through [ParseSigned] + [Verify] with its own JWS
// resolver. This split keeps the JWE wrapper free of an inbound
// dependency on every caller's signing-keyset shape.
func Decrypt(raw string, resolver EncryptionKeyResolver) (DecryptedJWE, error) {
	if resolver == nil {
		return DecryptedJWE{}, fmt.Errorf("%w: nil resolver", ErrJWEMalformed)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 5 {
		return DecryptedJWE{}, fmt.Errorf("%w: expected 5 parts, got %d", ErrJWEMalformed, len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return DecryptedJWE{}, fmt.Errorf("%w: protected header base64", ErrJWEMalformed)
	}
	var hdr jweProtectedHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return DecryptedJWE{}, fmt.Errorf("%w: protected header json", ErrJWEMalformed)
	}
	if len(hdr.Crit) > 0 {
		return DecryptedJWE{}, fmt.Errorf("%w: %v", ErrJWECritUnknown, hdr.Crit)
	}
	alg, ok := ParseJWEAlg(hdr.Alg)
	if !ok {
		return DecryptedJWE{}, fmt.Errorf("%w: %q", ErrJWEAlgNotAllowed, hdr.Alg)
	}
	enc, ok := ParseJWEEnc(hdr.Enc)
	if !ok {
		return DecryptedJWE{}, fmt.Errorf("%w: %q", ErrJWEEncNotAllowed, hdr.Enc)
	}

	obj, err := josev4.ParseEncryptedCompact(raw, allowedV4KeyAlgorithms(), allowedV4ContentEncryptions())
	if err != nil {
		return DecryptedJWE{}, fmt.Errorf("%w: %w", ErrJWEMalformed, err)
	}

	plaintext, err := decryptWithResolver(obj, resolver, hdr.Kid, alg)
	if err != nil {
		return DecryptedJWE{}, err
	}
	if len(plaintext) > MaxJWEPlaintextSize {
		return DecryptedJWE{}, fmt.Errorf(
			"%w: %d bytes (cap %d)", ErrJWEPlaintextTooLarge, len(plaintext), MaxJWEPlaintextSize,
		)
	}

	return DecryptedJWE{
		Plaintext:   plaintext,
		KeyID:       hdr.Kid,
		Algorithm:   alg,
		Encryption:  enc,
		ContentType: hdr.Cty,
	}, nil
}

// decryptWithResolver runs the actual decryption attempt. When kid is
// present the resolver selects exactly one private key. When kid is absent
// (RFC 7516 §4.1.6 permits omission) the package falls back to bounded
// trial decryption: the keyset is filtered to entries whose Go type matches
// the protected-header `alg` (RSA-OAEP-* → *rsa.PrivateKey, ECDH-ES* →
// *ecdsa.PrivateKey), capped at [MaxKidlessTrialKeys], and the loop runs
// to completion regardless of an early success so wall-clock timing cannot
// leak which key matched.
func decryptWithResolver(obj *josev4.JSONWebEncryption, resolver EncryptionKeyResolver, kid string, alg JWEAlg) ([]byte, error) {
	if kid != "" {
		priv, found := resolver.Resolve(kid)
		if !found {
			return nil, fmt.Errorf("%w: %q", ErrJWEKidUnknown, kid)
		}
		// Pre-validate the resolved key's Go type against the protected-
		// header `alg` before attempting Decrypt, mirroring the check
		// [filterKeysForAlg] applies on the kid-absent trial path. go-jose
		// v4 already rejects an alg/key-shape mismatch inside Decrypt, so
		// this is defence-in-depth rather than an active gap; it keeps the
		// kid-present and kid-absent branches validating consistently
		// rather than relying solely on the underlying library's behaviour.
		if !keyMatchesAlg(priv, alg) {
			return nil, fmt.Errorf("%w: kid match", ErrJWEDecryptFailed)
		}
		pt, derr := obj.Decrypt(priv)
		if derr != nil {
			return nil, fmt.Errorf("%w: kid match", ErrJWEDecryptFailed)
		}
		return pt, nil
	}

	keys := resolver.All()
	candidates := filterKeysForAlg(keys, alg)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: kid-absent fallback", ErrJWEDecryptFailed)
	}
	if len(candidates) > MaxKidlessTrialKeys {
		return nil, fmt.Errorf("%w: kid-absent fallback", ErrJWEDecryptFailed)
	}

	var success []byte
	for _, k := range candidates {
		pt, derr := obj.Decrypt(k)
		if derr == nil && success == nil {
			success = pt
		}
	}
	if success == nil {
		return nil, fmt.Errorf("%w: kid-absent fallback", ErrJWEDecryptFailed)
	}
	return success, nil
}

// filterKeysForAlg returns the subset of keys whose Go type matches the
// JWE protected-header `alg`. Filtering by key type before any cryptographic
// operation runs bounds the trial work an attacker can amplify with one
// kid-less ciphertext: a deployment with one RSA key and one EC key only
// runs a single trial per ciphertext, regardless of the keyset's true size.
func filterKeysForAlg(keys []any, alg JWEAlg) []any {
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		if keyMatchesAlg(k, alg) {
			out = append(out, k)
		}
	}
	return out
}

func keyMatchesAlg(key any, alg JWEAlg) bool {
	switch alg {
	case JWEAlgRSAOAEP256:
		_, ok := key.(*rsa.PrivateKey)
		return ok
	case JWEAlgECDHES, JWEAlgECDHESA128KW, JWEAlgECDHESA256KW:
		_, ok := key.(*ecdsa.PrivateKey)
		return ok
	default:
		return false
	}
}

// NestedDecryption is the result of a [DecryptChain] call. Plaintext
// holds the bytes of the innermost layer (the bottom of the JWE-of-JWE
// chain); JWELayers reports how many JWE layers were peeled to reach
// it. The caller adds 1 (for the final non-JWE layer it parses, e.g.
// a JWS) when comparing against [MaxJOSENestingDepth].
//
// Outermost is the protected-header view of the outermost JWE (the
// layer the wire actually carried). Audit logs reference the outer
// kid / alg / enc rather than any nested layer because the outer key
// is the one the embedder routed to.
type NestedDecryption struct {
	Plaintext []byte
	JWELayers int
	Outermost DecryptedJWE
}

// DecryptChain peels nested JWE layers from raw, recursively decrypting
// each layer through the same resolver. The function stops as soon as
// the plaintext is no longer JWE-shaped (compact form with five
// segments) and returns the bottom plaintext alongside the number of
// JWE layers peeled.
//
// The total layer budget — JWE peels plus the caller's final non-JWE
// parse — MUST NOT exceed [MaxJOSENestingDepth]. The caller passes the
// remaining budget; DecryptChain decrements once per peel and rejects
// the (budget+1)th JWE with [ErrJWENestingTooDeep]. budget MUST be
// positive: a non-positive budget signals a programming bug and
// returns [ErrJWENestingTooDeep] uniformly so the misuse fails closed.
//
// The JOSE-level error envelope mirrors [Decrypt] verbatim: every
// failure surfaces a sentinel from [ErrJWEMalformed] / [ErrJWEAlgNotAllowed]
// / [ErrJWEEncNotAllowed] / [ErrJWEKidUnknown] / [ErrJWEDecryptFailed]
// / [ErrJWEPlaintextTooLarge] / [ErrJWENestingTooDeep]. The wrapped
// detail is safe to log but MUST NOT be returned to clients.
//
// RFC 7519 §5.2 (Nested JWT) admits arbitrary cty=JWT chains; the cap
// is a defence-in-depth measure on top of the per-layer 1 MiB
// plaintext cap. A pathological chain of 1 MiB layers would otherwise
// pin a request to ≥ N MiB of decrypt work for an attacker-chosen N.
func DecryptChain(raw string, resolver EncryptionKeyResolver, budget int) (NestedDecryption, error) {
	if budget <= 0 {
		return NestedDecryption{}, fmt.Errorf("%w: budget exhausted", ErrJWENestingTooDeep)
	}
	var outermost DecryptedJWE
	current := raw
	layers := 0
	for {
		if !looksLikeJWE(current) {
			return NestedDecryption{
				Plaintext: []byte(current),
				JWELayers: layers,
				Outermost: outermost,
			}, nil
		}
		if layers >= budget {
			return NestedDecryption{}, fmt.Errorf(
				"%w: peeled %d JWE layers (budget %d)", ErrJWENestingTooDeep, layers, budget,
			)
		}
		dec, err := Decrypt(current, resolver)
		if err != nil {
			return NestedDecryption{}, err
		}
		if layers == 0 {
			outermost = dec
		}
		layers++
		current = string(dec.Plaintext)
	}
}

// looksLikeJWE reports whether s is shaped like a compact-serialised
// JWE (RFC 7516 §3.1: five base64url segments separated by "."). The
// check is purely structural — a real JWE parse happens inside
// [Decrypt]. Used by [DecryptChain] to decide whether to peel another
// layer.
func looksLikeJWE(s string) bool {
	return strings.Count(s, ".") == 4
}

// allowedV4KeyAlgorithms returns the slice of go-jose v4
// [josev4.KeyAlgorithm] constants matching [AllowedJWEAlgs]. Keeping
// the mapping in one place lets us audit it alongside [JWEAlg.IsAllowed].
func allowedV4KeyAlgorithms() []josev4.KeyAlgorithm {
	return []josev4.KeyAlgorithm{
		josev4.RSA_OAEP_256,
		josev4.ECDH_ES,
		josev4.ECDH_ES_A128KW,
		josev4.ECDH_ES_A256KW,
	}
}

// allowedV4ContentEncryptions returns the slice of go-jose v4
// [josev4.ContentEncryption] constants matching [AllowedJWEEncs].
func allowedV4ContentEncryptions() []josev4.ContentEncryption {
	return []josev4.ContentEncryption{
		josev4.A128GCM,
		josev4.A256GCM,
	}
}
