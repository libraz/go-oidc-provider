package jarm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
