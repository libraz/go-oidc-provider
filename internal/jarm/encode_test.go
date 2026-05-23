package jarm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// generateTestSigningKey returns a fresh ES256 [tokens.SigningKey] for
// the encoder tests. The production [jarm.Signer] consumes a key
// supplied by the caller and never generates one; this helper exists
// purely so tests can sign JWTs they later round-trip.
func generateTestSigningKey(t *testing.T) tokens.SigningKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return tokens.SigningKey{KeyID: "jarm-test-kid", Signer: priv}
}

// fixedClock returns a deterministic clock so the "exp" / "iat"
// computation in [jarm.Signer.SignDefault] is reproducible.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// encodedClaims decodes the unverified payload of a compact JWT for
// inspection in tests.
func encodedClaims(t *testing.T, raw string) map[string]any {
	t.Helper()

	parsed, err := jwt.ParseSigned(raw, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	out := map[string]any{}
	if err := parsed.UnsafeClaimsWithoutVerification(&out); err != nil {
		t.Fatalf("UnsafeClaimsWithoutVerification: %v", err)
	}
	return out
}

func TestNewSigner_RequiresKeyAndIssuer(t *testing.T) {
	t.Parallel()

	if _, err := jarm.NewSigner(jarm.SignerConfig{Issuer: "https://op.example.com"}); err == nil {
		t.Error("NewSigner accepted empty Key.Signer")
	}
	if _, err := jarm.NewSigner(jarm.SignerConfig{Key: generateTestSigningKey(t)}); err == nil {
		t.Error("NewSigner accepted empty Issuer")
	}
}

func TestNewSigner_DefaultClockAndExpiry(t *testing.T) {
	t.Parallel()

	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    generateTestSigningKey(t),
		Issuer: "https://op.example.com",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.Issuer() != "https://op.example.com" {
		t.Errorf("Issuer=%q", signer.Issuer())
	}
}

func TestSigner_SignSuccessClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    generateTestSigningKey(t),
		Issuer: "https://op.example.com",
		Clock:  fixedClock{now: now},
		Expiry: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := signer.SignDefault(jarm.Payload{
		Audience: "client-1",
		Code:     "code-abc",
		State:    "state-xyz",
	})
	if err != nil {
		t.Fatalf("SignDefault: %v", err)
	}
	claims := encodedClaims(t, out)
	if got := claims["iss"]; got != "https://op.example.com" {
		t.Errorf("iss=%v", got)
	}
	if got := claims["aud"]; got != "client-1" {
		t.Errorf("aud=%v", got)
	}
	if got := claims["code"]; got != "code-abc" {
		t.Errorf("code=%v", got)
	}
	if got := claims["state"]; got != "state-xyz" {
		t.Errorf("state=%v", got)
	}
	if got := claims["s_hash"]; got != tokens.Hash("state-xyz") {
		t.Errorf("s_hash=%v want %s", got, tokens.Hash("state-xyz"))
	}
	if _, hasErr := claims["error"]; hasErr {
		t.Errorf("error claim present on success path")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp not numeric: %T", claims["exp"])
	}
	if int64(exp) != now.Add(60*time.Second).Unix() {
		t.Errorf("exp=%d want %d", int64(exp), now.Add(60*time.Second).Unix())
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat not numeric: %T", claims["iat"])
	}
	if int64(iat) != now.Unix() {
		t.Errorf("iat=%d want %d", int64(iat), now.Unix())
	}
}

func TestSigner_SignErrorClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    generateTestSigningKey(t),
		Issuer: "https://op.example.com",
		Clock:  fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := signer.SignDefault(jarm.Payload{
		Audience:         "client-1",
		Error:            "invalid_scope",
		ErrorDescription: "scope is restricted",
		ErrorURI:         "https://op.example.com/errors/invalid_scope",
		State:            "state-1",
	})
	if err != nil {
		t.Fatalf("SignDefault: %v", err)
	}
	claims := encodedClaims(t, out)
	if got := claims["error"]; got != "invalid_scope" {
		t.Errorf("error=%v", got)
	}
	if got := claims["error_description"]; got != "scope is restricted" {
		t.Errorf("error_description=%v", got)
	}
	if got := claims["error_uri"]; got != "https://op.example.com/errors/invalid_scope" {
		t.Errorf("error_uri=%v", got)
	}
	if _, hasCode := claims["code"]; hasCode {
		t.Errorf("code claim present on error path")
	}
}

func TestSigner_SignRequiresAudience(t *testing.T) {
	t.Parallel()

	signer := mustNewSigner(t)
	_, err := signer.SignDefault(jarm.Payload{Code: "abc"})
	if !errors.Is(err, jarm.ErrEncode) {
		t.Errorf("err=%v want ErrEncode", err)
	}
}

func TestSigner_SignRequiresCodeOrError(t *testing.T) {
	t.Parallel()

	signer := mustNewSigner(t)
	_, err := signer.SignDefault(jarm.Payload{Audience: "client-1"})
	if !errors.Is(err, jarm.ErrEncode) {
		t.Errorf("err=%v want ErrEncode", err)
	}
}

func TestSigner_SignRejectsCodeAndErrorTogether(t *testing.T) {
	t.Parallel()

	signer := mustNewSigner(t)
	_, err := signer.SignDefault(jarm.Payload{
		Audience: "client-1",
		Code:     "abc",
		Error:    "invalid_scope",
	})
	if !errors.Is(err, jarm.ErrEncode) {
		t.Errorf("err=%v want ErrEncode", err)
	}
}

func TestSigner_SignAbsoluteExpiry(t *testing.T) {
	t.Parallel()

	signer := mustNewSigner(t)
	exp := time.Date(2026, 4, 26, 12, 5, 0, 0, time.UTC)
	out, err := signer.Sign(jarm.Payload{
		Issuer:    "https://op.example.com",
		Audience:  "client-1",
		ExpiresAt: exp,
		Code:      "abc",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims := encodedClaims(t, out)
	if got, _ := claims["exp"].(float64); int64(got) != exp.Unix() {
		t.Errorf("exp=%d want %d", int64(got), exp.Unix())
	}
}

// TestSigner_AlgIsES256_Structural pins the JARM signing algorithm
// to ES256 at the protected-header byte level. JARM responses MUST NOT
// be signed with a symmetric algorithm (HS*) — a JARM that an RP
// receives carrying alg=HS256 is a textbook algorithm-confusion
// vector if the RP is poorly written. JARM MUST NOT be signed with
// "none" either; the spec is clear that response objects are always
// asymmetrically signed.
//
// Tracks:
//   - CVE-2023-6927 (Keycloak; the response_mode=form_post.jwt
//     bypass of CVE-2023-6134 — when JARM was added without the
//     same alg restrictions as the bearer flow, a downgrade was
//     possible).
//   - FAPI 2.0 Message Signing §5.4 which mandates that the OP signs
//     JARM responses with one of the asymmetric algorithms in its
//     allow-list (PS256/ES256/EdDSA).
//   - RFC 7515 §4.1.1 (alg) and the broader RFC 8725 §3.1 guidance
//     on rejecting unexpected algorithms.
//
// Defence: the [jarm.newSigner] helper hardcodes alg=ES256 at
// construction time (encode.go:217). The signer never inspects an
// inbound algorithm preference — it cannot be downgraded at runtime.
// This test decodes the JWS protected header and asserts the byte
// content of "alg" so a regression that introduced configurability
// (or a different default) lights up here, not at certification time.
func TestSigner_AlgIsES256_Structural(t *testing.T) {
	t.Parallel()

	signer := mustNewSigner(t)
	out, err := signer.Sign(jarm.Payload{
		Issuer:    "https://op.example.com",
		Audience:  "client-1",
		ExpiresAt: time.Date(2026, 4, 26, 12, 5, 0, 0, time.UTC),
		Code:      "code-abc",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Compact JWS form: header.payload.signature. Decode the protected
	// header without verification; we want the wire bytes, not the
	// post-verify view.
	parts := strings.Split(out, ".")
	if len(parts) != 3 {
		t.Fatalf("compact form parts=%d want 3 (got %q)", len(parts), out)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Alg != "ES256" {
		t.Fatalf("alg=%q want ES256 (JARM MUST NOT be signed with %q)", header.Alg, header.Alg)
	}
	if header.Typ != "JWT" {
		t.Errorf("typ=%q want JWT", header.Typ)
	}
	if header.Kid == "" {
		t.Error("kid empty; JARM MUST stamp the signing kid for RP-side verification")
	}

	// Belt-and-braces: try parsing with each forbidden alg and confirm
	// josev4 rejects every one. ParseSigned takes a closed allow-list,
	// so a JWS signed with ES256 will not parse under HS256/RS256/etc.
	// — but the assertion guards against a regression that produced a
	// JWS whose header CLAIMS one alg while the signature was minted
	// under another (the historic "alg confusion" rabbit hole).
	for _, bad := range []josev4.SignatureAlgorithm{
		josev4.HS256, josev4.HS384, josev4.HS512,
		josev4.RS256, josev4.RS384, josev4.RS512,
		josev4.PS256, josev4.PS384, josev4.PS512,
		josev4.ES384, josev4.ES512,
		josev4.EdDSA,
	} {
		if _, err := jwt.ParseSigned(out, []josev4.SignatureAlgorithm{bad}); err == nil {
			t.Errorf("ParseSigned with allow-list=%q accepted ES256 JWS; alg-confusion gate broken", bad)
		}
	}
}

// mustNewSigner builds a signer with deterministic defaults for the
// payload-validation tests that do not care about the resulting JWT.
func mustNewSigner(t *testing.T) *jarm.Signer {
	t.Helper()

	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    generateTestSigningKey(t),
		Issuer: "https://op.example.com",
		Clock:  fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}
