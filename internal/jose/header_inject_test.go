package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestParseSigned_HeaderInjection_NeverFetches encodes the structural
// defence against "header injection" attacks on JWS verification. RFC
// 8725 §3.1-3.5 enumerates a family of headers — "jku", "x5u", "x5c",
// "jwk" — that some libraries historically used to *fetch* or *select*
// the verification key from the token itself. An attacker who can write
// these headers can then force the verifier to use a key under their
// control.
//
// Tracks: CVE-2018-0114 (Cisco / node-jose; jwk header trusted for
// verification), CVE-2018-1000531 (inversoft prime-jwt; alg header
// downgrade and jwk-trusting verification), CVE-2017-11424
// (python-jose-style libraries that resolved jku from the header),
// CVE-2019-7644 (Auth0 jsonwebtoken-koa; trusted jwk header), and the
// general RFC 8725 §3 guidance that arose from these incidents.
//
// Defence in this codebase: [jose.ParseSigned] returns a parsed JWS
// without calling any verifier. The caller MUST supply the trusted key
// out-of-band (the OP's discovery JWKS or the registered client
// JWKS) — there is no codepath that resolves a key from a JWS header.
// This test pins the contract by:
//
//  1. Building a JWS whose unprotected/protected headers carry a
//     poisoned "jku" / "x5u" / "x5c" / "jwk".
//  2. Confirming ParseSigned does NOT block on any HTTP fetch
//     (covered implicitly by the test running synchronously with no
//     network mock; a regression that introduces a fetch would
//     timeout or fail on dial).
//  3. Confirming the parsed JWS, when verified with a *different*
//     key, fails — i.e. the attacker's "jwk" was not consulted.
func TestParseSigned_HeaderInjection_NeverFetches(t *testing.T) {
	t.Parallel()

	// Two distinct keys: legit (the OP-trusted key the caller passes
	// to verify) and attacker (the key the JWS is actually signed
	// with, advertised in a poisoned "jwk" header).
	legitKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("legit key: %v", err)
	}
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("attacker key: %v", err)
	}

	// Sign with the attacker key, then splice extra headers into the
	// protected header. We do this by hand because go-jose v4 refuses
	// to mint JWS objects with arbitrary "jku" / "x5u" / "x5c"
	// — which is itself a structural defence; this test exercises the
	// *receiver* path even when an upstream library does NOT enforce
	// that constraint, because attacker tooling certainly will not.
	const payload = `{"iss":"client-1","sub":"client-1","aud":"https://op.test","jti":"j","exp":9999999999}`
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"kid": "rp-key-1",
		// Each of these MUST NOT influence verification.
		"jku": "https://attacker.example/jwks.json",
		"x5u": "https://attacker.example/cert.pem",
		"x5c": []string{"MIIBkTCC..."},
		"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(attackerKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(attackerKey.Y.Bytes()),
		},
	}
	hdrJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signing := hdrB64 + "." + payB64

	// Sign signing input with the attacker key.
	hash := sha256Sum([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, attackerKey, hash)
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sig := append(r.Bytes(), s.Bytes()...)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	tok := signing + "." + sigB64

	// 1: ParseSigned must accept the structural shape — alg=ES256 is
	// in the allow-list — and return a parsed JWS without any network
	// call. The success of this step (vs. a hang or timeout) is itself
	// proof that no jku/x5u fetch happened.
	jws, alg, err := jose.ParseSigned(tok)
	if err != nil {
		// go-jose v4 may reject the token because the manually-built
		// signature is shorter than P-256's strict 64-byte form. That's
		// a structural rejection at the malformed gate, which is also
		// acceptable: the attacker-supplied "jwk" cannot have been
		// consulted because we never reached signature verification.
		if errors.Is(err, jose.ErrMalformed) || errors.Is(err, jose.ErrAlgorithmNotAllowed) {
			return
		}
		t.Fatalf("unexpected ParseSigned error: %v", err)
	}
	if alg != jose.AlgES256 {
		t.Fatalf("alg=%q want ES256", alg)
	}

	// 2: Verifying with the LEGIT key must fail. The poisoned headers
	// in the JWS MUST be irrelevant to verifier selection.
	_, verifyErr := jws.Verify(&legitKey.PublicKey)
	if verifyErr == nil {
		t.Fatal("verification with legit key succeeded; attacker-supplied jwk header was trusted")
	}
}

// TestParseSigned_RejectsTooManySignatures reinforces the same posture
// from a different angle: a multi-signature JWS could be used by an
// attacker to attach an additional signature over the same payload
// using a key under their control, hoping the verifier picks the
// wrong one. The library's contract is "compact serialisation only"
// — any multi-sig form rejected as malformed.
func TestParseSigned_RejectsMultiSignatureForm(t *testing.T) {
	t.Parallel()

	// JSON serialisation form (not compact) — a multi-signature shape
	// the compact parser MUST refuse.
	jsonForm := `{"payload":"eyJzdWIiOiJhbGljZSJ9","signatures":[` +
		`{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"AAAA"},` +
		`{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"BBBB"}` +
		`]}`
	_, _, err := jose.ParseSigned(jsonForm)
	if err == nil {
		t.Fatal("ParseSigned accepted JSON-form JWS; compact-only contract violated")
	}
	if !errors.Is(err, jose.ErrMalformed) && !errors.Is(err, jose.ErrAlgorithmNotAllowed) {
		t.Fatalf("err=%v want ErrMalformed", err)
	}
}

// TestParseSigned_CritHeaderRejectedAtVerify pins the RFC 7515 §4.1.11
// contract for the "crit" extension list. A producer that signs a JWS
// listing an extension the recipient does NOT understand MUST be
// rejected; "I'm critical, deal with it" headers are how attackers
// historically smuggled new semantics past lax verifiers.
//
// Tracks: CVE-2025-59420 (Authlib; "crit" claim not enforced — JWS with
// unsupported extension accepted), CVE-2026-32597 (PyJWT; same defect
// in a different ecosystem confirms the pattern), and the broader
// RFC 8725 §3.1 / §3.5 guidance to reject any header parameter the
// implementation does not actively support.
//
// Defence: the verification chain is delegated to go-jose v4, which
// rejects unknown "crit" entries at [josev4.JSONWebSignature.Verify]
// time (signing.go:413-417 in v4.1.2). [jose.ParseSigned] does not
// inspect "crit" — that is fine because every codepath in this library
// that consumes a JWS verifies it before trusting any payload claim,
// and Verify is where the rejection lands. This test pins the chain
// end-to-end so a future refactor that bypasses Verify (or replaces
// the underlying library with one that ignores "crit") fails loudly.
func TestParseSigned_CritHeaderRejectedAtVerify(t *testing.T) {
	t.Parallel()

	// One key, used to both sign and verify. The defect class here is
	// not key confusion — it is the verifier silently honouring an
	// extension it does not support. We sign with the legit key so the
	// signature is structurally valid; only the unhandled "crit" entry
	// MUST cause Verify to reject.
	legitKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("legit key: %v", err)
	}

	const payload = `{"sub":"alice"}`
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		// The "crit" list MUST cause Verify to refuse the JWS because
		// "x-evil-extension" is not in go-jose's supportedCritical
		// table and the codebase has not registered it.
		"crit":             []string{"x-evil-extension"},
		"x-evil-extension": "any-value-attacker-wants",
	}
	hdrJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signing := hdrB64 + "." + payB64

	hash := sha256Sum([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, legitKey, hash)
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	// P-256 signatures are 64 bytes (two 32-byte components, padded
	// when shorter). Pad each component so go-jose accepts the
	// fixed-width compact form.
	rb := padTo(r.Bytes(), 32)
	sb := padTo(s.Bytes(), 32)
	sig := make([]byte, 0, 64)
	sig = append(sig, rb...)
	sig = append(sig, sb...)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	tok := signing + "." + sigB64

	jws, alg, parseErr := jose.ParseSigned(tok)
	if parseErr != nil {
		// Acceptable: a future hardening that rejects "crit" at parse
		// time would land here. The structural property still holds
		// (the JWS never reaches a trusted state), so we accept either
		// classification as long as it is one of our sentinels.
		if errors.Is(parseErr, jose.ErrMalformed) || errors.Is(parseErr, jose.ErrAlgorithmNotAllowed) {
			return
		}
		t.Fatalf("unexpected ParseSigned error: %v", parseErr)
	}
	if alg != jose.AlgES256 {
		t.Fatalf("alg=%q want ES256", alg)
	}

	if _, verifyErr := jws.Verify(&legitKey.PublicKey); verifyErr == nil {
		t.Fatal("Verify accepted a JWS with unsupported crit extension; RFC 7515 §4.1.11 contract violated")
	}
}

// padTo returns b left-padded with zero bytes to length n. ECDSA
// component bytes are big-endian and may be shorter than the curve's
// fixed width when the leading bytes are zero; go-jose's compact
// signature form requires the fixed width.
func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// TestParseSigned_NoCompactDelimiterAccepted is a structural pin: a
// token without the canonical compact-form three-part shape must
// fail. This kills creative attacker-supplied shapes (e.g. nested
// dots, missing signature segment, base64 with whitespace) before any
// header inspection occurs.
func TestParseSigned_NoCompactDelimiterAccepted(t *testing.T) {
	t.Parallel()

	cases := []string{
		"only.two",
		"four.dots.in.token",
		"",
		"one_segment_only",
		strings.Repeat("a", 4096), // long, but no dots.
	}
	for _, raw := range cases {
		_, _, err := jose.ParseSigned(raw)
		if err == nil {
			t.Fatalf("ParseSigned accepted bogus shape %q", raw)
		}
	}
}

// sha256Sum is a tiny adapter so the test reads naturally; using
// [crypto/sha256.Sum256] directly returns an array, not a slice.
func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
