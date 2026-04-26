package tokens_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// fakeClock returns a fixed time and is intentionally minimal; the
// verifier reads Now() exactly once per Verify call so a constant
// suffices for every test in this file.
type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

func mustKeySet(tb testing.TB, kid string) (*keys.Set, keys.Entry) {
	tb.Helper()
	entry, err := keys.GenerateES256(kid)
	if err != nil {
		tb.Fatalf("GenerateES256: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		tb.Fatalf("NewSet: %v", err)
	}
	return set, entry
}

func signed(tb testing.TB, entry keys.Entry, claims tokens.AccessTokenClaims) string {
	tb.Helper()
	jws, err := tokens.SignAccessToken(tokens.FromInternalEntry(entry), claims)
	if err != nil {
		tb.Fatalf("SignAccessToken: %v", err)
	}
	return jws
}

func TestVerify_RoundTripSingleAudience(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	want := tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-1",
		Scope:     []string{"openid", "profile"},
	}
	jws := signed(t, entry, want)

	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: now.Add(time.Minute)},
	}
	got, kid, err := v.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if kid != "kid-1" {
		t.Errorf("kid=%q want kid-1", kid)
	}
	if got.Issuer != want.Issuer || got.Subject != want.Subject {
		t.Errorf("iss/sub mismatch: got=%+v want=%+v", got, want)
	}
	if got.ClientID != want.ClientID {
		t.Errorf("client_id=%q want %q", got.ClientID, want.ClientID)
	}
	if got.JTI != want.JTI {
		t.Errorf("jti=%q want %q", got.JTI, want.JTI)
	}
	if got.IssuedAt != want.IssuedAt || got.ExpiresAt != want.ExpiresAt {
		t.Errorf("iat/exp mismatch: got=(%d,%d) want=(%d,%d)",
			got.IssuedAt, got.ExpiresAt, want.IssuedAt, want.ExpiresAt)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "https://api.example.com" {
		t.Errorf("aud=%v want [\"https://api.example.com\"]", got.Audience)
	}
	if strings.Join(got.Scope, " ") != "openid profile" {
		t.Errorf("scope=%v want [openid profile]", got.Scope)
	}
}

func TestVerify_RoundTripMultipleAudiences(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	want := tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com", "https://billing.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-multi",
	}
	jws := signed(t, entry, want)

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: want.Issuer, Clock: fakeClock{now: now}}
	got, _, err := v.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.Audience) != 2 ||
		got.Audience[0] != "https://api.example.com" ||
		got.Audience[1] != "https://billing.example.com" {
		t.Errorf("aud=%v want both audiences preserved in order", got.Audience)
	}
}

func TestVerify_ExpiredReturnsExpiredSentinel(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	issuedAt := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: issuedAt.Add(time.Minute).Unix(),
		JTI:       "expired-1",
	})

	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: issuedAt.Add(time.Hour)},
	}
	_, _, err := v.Verify(jws)
	if !errors.Is(err, tokens.ErrAccessTokenExpired) {
		t.Fatalf("err=%v want ErrAccessTokenExpired", err)
	}
}

func TestVerify_FutureIATReturnsMalformed(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	tokenNow := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  tokenNow.Unix(),
		ExpiresAt: tokenNow.Add(time.Hour).Unix(),
		JTI:       "future-iat",
	})

	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: tokenNow.Add(-time.Hour)},
	}
	_, _, err := v.Verify(jws)
	if !errors.Is(err, tokens.ErrAccessTokenMalformed) {
		t.Fatalf("err=%v want ErrAccessTokenMalformed", err)
	}
}

func TestVerify_IssuerMismatch(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://other-op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "issuer-mismatch",
	})

	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: now},
	}
	_, _, err := v.Verify(jws)
	if !errors.Is(err, tokens.ErrAccessTokenIssuerMismatch) {
		t.Fatalf("err=%v want ErrAccessTokenIssuerMismatch", err)
	}
}

func TestVerify_UnknownKidReturnsSignatureError(t *testing.T) {
	t.Parallel()

	// Sign with key A.
	_, entryA := mustKeySet(t, "kid-A")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws := signed(t, entryA, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "kid-A-token",
	})

	// Verify against a Set that only has key B.
	setB, _ := mustKeySet(t, "kid-B")
	v := &tokens.AccessTokenVerifier{Keys: setB, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}
	_, _, err := v.Verify(jws)
	if !errors.Is(err, tokens.ErrAccessTokenSignature) {
		t.Fatalf("err=%v want ErrAccessTokenSignature", err)
	}
}

func TestVerify_TamperedSignatureReturnsSignatureError(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "tamper-1",
	})

	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS expected 3 parts, got %d", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	// Flip the first byte to invalidate the signature without changing
	// its length / encoding shape.
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	tampered := strings.Join(parts, ".")

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}
	_, _, gotErr := v.Verify(tampered)
	if !errors.Is(gotErr, tokens.ErrAccessTokenSignature) {
		t.Fatalf("err=%v want ErrAccessTokenSignature", gotErr)
	}
}

func TestVerify_NotAJWTReturnsMalformed(t *testing.T) {
	t.Parallel()

	set, _ := mustKeySet(t, "kid-1")
	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com"}
	_, _, err := v.Verify("not.a.jwt")
	if !errors.Is(err, tokens.ErrAccessTokenMalformed) {
		t.Fatalf("err=%v want ErrAccessTokenMalformed", err)
	}
}

func TestVerify_RejectsHS256AsMalformed(t *testing.T) {
	t.Parallel()

	// Mint an HS256 token with go-jose directly. The verifier uses
	// internal/jose.ParseSigned which rejects HS* before any signature
	// material is touched, so the failure surfaces as
	// ErrAccessTokenMalformed (NOT ErrAccessTokenSignature).
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.HS256, Key: []byte("hs256-secret-key-bytes-32-chars--")},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": "https://op.example.com",
		"sub": "user-1",
		"aud": "client-1",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	set, _ := mustKeySet(t, "kid-1")
	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}
	_, _, gotErr := v.Verify(raw)
	if !errors.Is(gotErr, tokens.ErrAccessTokenMalformed) {
		t.Fatalf("HS256 err=%v want ErrAccessTokenMalformed", gotErr)
	}
	if errors.Is(gotErr, tokens.ErrAccessTokenSignature) {
		t.Fatalf("HS256 must not surface as ErrAccessTokenSignature; alg policy is enforced pre-verify")
	}
}

func TestVerify_RejectsAlgNoneAsMalformed(t *testing.T) {
	t.Parallel()

	// alg=none JWTs are constructed by hand: the spec defines them as
	// "header.payload." with an empty signature segment, but go-jose
	// refuses to mint them, which is the point. We craft the wire bytes
	// directly and confirm the verifier rejects them as malformed.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"kid-1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://op.example.com","sub":"u1"}`))
	raw := header + "." + payload + "."

	set, _ := mustKeySet(t, "kid-1")
	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com"}
	_, _, gotErr := v.Verify(raw)
	if !errors.Is(gotErr, tokens.ErrAccessTokenMalformed) {
		t.Fatalf("alg=none err=%v want ErrAccessTokenMalformed", gotErr)
	}
	if errors.Is(gotErr, tokens.ErrAccessTokenSignature) {
		t.Fatalf("alg=none must not surface as ErrAccessTokenSignature")
	}
}

func TestVerify_LeewayAcceptsSlightlyExpired(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	issuedAt := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	exp := issuedAt.Add(time.Minute)
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: exp.Unix(),
		JTI:       "leeway-grace",
	})

	// 5s past expiry, 10s leeway -> accepted.
	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: exp.Add(5 * time.Second)},
		Leeway: 10 * time.Second,
	}
	if _, _, err := v.Verify(jws); err != nil {
		t.Fatalf("Verify (within leeway): %v", err)
	}

	// 30s past expiry, 10s leeway -> rejected as expired.
	v.Clock = fakeClock{now: exp.Add(30 * time.Second)}
	_, _, err := v.Verify(jws)
	if !errors.Is(err, tokens.ErrAccessTokenExpired) {
		t.Fatalf("err=%v want ErrAccessTokenExpired", err)
	}
}

func TestVerify_NilClockUsesSystemClock(t *testing.T) {
	t.Parallel()

	// A nil verifier Clock must defer to the system clock without
	// panicking. The test cannot observe System time directly (lint
	// forbids time.Now in non-timex callers), so we sign a token whose
	// exp is decades in the future to be robust against scheduling
	// jitter and clock skew on slower CI runners.
	set, entry := mustKeySet(t, "kid-1")
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  0, // skip iat-future check
		ExpiresAt: farFuture,
		JTI:       "no-clock",
	})

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com"}
	if _, _, err := v.Verify(jws); err != nil {
		t.Fatalf("Verify with nil Clock: %v", err)
	}
}
