package tokens_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
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

// TestVerify_RoundTripAuthorizationDetails pins the RFC 9068 §2.2.3
// authorization_details claim through the verify path: the verifier decodes
// the array back onto AccessTokenClaims, and because decodeAccessTokenClaims
// uses json.Decoder+UseNumber a bare-integer amount that exceeds the
// float64 integer-exact range (2^53) survives as a json.Number carrying the
// exact decimal string rather than being widened to a lossy float64.
//
// The token is minted with go-jose directly from a pre-marshaled JSON
// payload so the "amount" reaches the wire as a bare JSON number (a JWT a
// peer OP / token endpoint could legitimately have signed); go-jose's
// typed Claims() helper would otherwise stringify a json.Number, which
// would not exercise the float64-widening hazard.
func TestVerify_RoundTripAuthorizationDetails(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	const bigAmount = "100000000000000001" // > 2^53, not float64-exact.

	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: josev4.JSONWebKey{
			Key:   entry.Signer,
			KeyID: entry.KeyID,
			Use:   "sig",
		}},
		(&josev4.SignerOptions{}).WithType("at+jwt"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload := []byte(`{` +
		`"iss":"https://op.example.com","sub":"user-1","aud":"https://api.example.com",` +
		`"client_id":"client-1","jti":"at-rar-verify",` +
		`"iat":` + itoa(now.Unix()) + `,"exp":` + itoa(now.Add(time.Hour).Unix()) + `,` +
		`"authorization_details":[{"type":"payment_initiation","amount":` + bigAmount + `}]}`)
	// Sign at the JWS level (not the typed jwt builder) so the raw JSON
	// payload reaches the wire verbatim with a bare-number amount.
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	jws, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}
	got, _, err := v.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.AuthorizationDetails) != 1 {
		t.Fatalf("authorization_details length=%d want 1", len(got.AuthorizationDetails))
	}
	if got.AuthorizationDetails[0]["type"] != "payment_initiation" {
		t.Errorf("type=%v want payment_initiation", got.AuthorizationDetails[0]["type"])
	}
	amount, ok := got.AuthorizationDetails[0]["amount"].(json.Number)
	if !ok {
		t.Fatalf("amount type=%T want json.Number (UseNumber preserves precision)", got.AuthorizationDetails[0]["amount"])
	}
	if amount.String() != bigAmount {
		t.Errorf("amount=%q want %q", amount.String(), bigAmount)
	}
}

// itoa is a tiny strconv.FormatInt wrapper kept local so the raw-JSON
// payload above reads as a single string concatenation.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

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

// TestVerify_RetiredKidReturnsSignatureError pins the H-F1 contract on
// the JWT access-token verify path: a token whose kid header names an
// [keys.Entry] whose [keys.Entry.NotAfter] has elapsed surfaces as
// [tokens.ErrAccessTokenSignature], indistinguishable from an unknown
// kid. The wire response the resource server emits is RFC 6750
// invalid_token regardless, but the audit observer (wired in op.New)
// still fires [op.AuditKeyRetiredKidPresented] so SOC tooling sees the
// post-rotation forge attempt.
//
// The test also checks the observer fires exactly once per Verify
// call, since a regression that loses the observer wiring would let
// the gate flip silent.
//
// Tracks H-F1.
func TestVerify_RetiredKidReturnsSignatureError(t *testing.T) {
	t.Parallel()

	// Build a single-entry keyset and sign with it. We then rebuild
	// the verifier-side Set with the entry marked as retired so the
	// retirement gate flips while the signature itself remains valid.
	entry, err := keys.GenerateES256("kid-retired")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now := deadline.Add(time.Hour)

	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "retired-kid-token",
	})

	var observed atomic.Int64
	var observedKid atomic.Value
	retired := keys.Entry{KeyID: entry.KeyID, Signer: entry.Signer, NotAfter: deadline}
	set, err := keys.NewSet(
		[]keys.Entry{retired},
		keys.WithClock(func() time.Time { return now }),
		keys.WithRetiredKidObserver(func(kid string) {
			observed.Add(1)
			observedKid.Store(kid)
		}),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: now},
	}
	_, _, gotErr := v.Verify(jws)
	if !errors.Is(gotErr, tokens.ErrAccessTokenSignature) {
		t.Fatalf("err=%v want ErrAccessTokenSignature on retired kid", gotErr)
	}

	if got := observed.Load(); got != 1 {
		t.Fatalf("retired-kid observer fired %d times; want exactly 1", got)
	}
	if got, _ := observedKid.Load().(string); got != "kid-retired" {
		t.Errorf("observer kid=%q want kid-retired", got)
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

// TestVerify_AlgConfusion_HSUsingECPublicKeyBytesAsSecret reproduces the
// canonical algorithm-confusion attack: the attacker reads the OP's
// published JWKS, takes the public-key material of an asymmetric key,
// and uses those bytes as the secret for an HS256 token. A naive
// verifier that derives the algorithm from the token's "alg" header
// without pinning it to the configured key would accept the token.
//
// Tracks: CVE-2015-9235 (jsonwebtoken; root case),
// CVE-2016-10555 (jwt-simple Node library), CVE-2024-54150 (cjwt),
// CVE-2026-22817 / CVE-2026-27804 / CVE-2026-23552 (Hono cluster, 2026),
// CVE-2026-33322 (MinIO OIDC), CVE-2026-48526 (PyJWT — an asymmetric
// public JWK was accepted as the shared secret for HMAC verification,
// this exact attack reached through the key-resolution API rather than
// the alg header). All share the same root cause: the
// verifier consults the token's alg header instead of pinning the
// algorithm to the resolved key. RFC 8725 §2.1 prescribes the fix.
//
// The library closes this structurally: jose.ParseSigned rejects HS*
// before any key is touched, so the verifier never reaches the
// signature stage. Failure surfaces as ErrAccessTokenMalformed (NOT
// ErrAccessTokenSignature), which is the post-condition we pin.
func TestVerify_AlgConfusion_HSUsingECPublicKeyBytesAsSecret(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	pub, ok := entry.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", entry.Signer.Public())
	}

	// Serialise the EC public key as a stable byte stream — exactly what
	// an attacker would obtain by fetching the published JWKS and
	// concatenating x||y, or by pulling the SubjectPublicKeyInfo bytes.
	// Treat the resulting bytes as a raw HMAC secret.
	hmacSecret := append(pub.X.Bytes(), pub.Y.Bytes()...)

	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.HS256, Key: hmacSecret},
		(&josev4.SignerOptions{}).WithType("JWT").WithHeader("kid", "kid-1"),
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

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}
	_, _, gotErr := v.Verify(raw)
	if !errors.Is(gotErr, tokens.ErrAccessTokenMalformed) {
		t.Fatalf("alg-confusion err=%v want ErrAccessTokenMalformed", gotErr)
	}
	if errors.Is(gotErr, tokens.ErrAccessTokenSignature) {
		t.Fatalf("alg-confusion must NOT surface as ErrAccessTokenSignature; alg policy must reject pre-verify")
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

// TestVerify_RoundTripGrantID pins ADR 0025's decode side: a token
// minted with a non-empty GrantID survives encode → decode and the
// "gid" private claim re-projects onto AccessTokenClaims.GrantID.
func TestVerify_RoundTripGrantID(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-gid")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-gid-roundtrip",
		GrantID:   "g123",
	})

	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: now},
	}
	got, _, err := v.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.GrantID != "g123" {
		t.Errorf("GrantID=%q want %q (ADR 0025 round trip)", got.GrantID, "g123")
	}
}

// TestVerify_LegacyTokenWithoutGidDecodesEmpty pins the verifier's
// non-enforcement contract: a token with no "gid" claim still verifies
// cleanly and surfaces an empty GrantID. The consumer (userinfo /
// introspection) decides what to do with the empty value — that is
// Wave 5's concern, not the verifier's.
func TestVerify_LegacyTokenWithoutGidDecodesEmpty(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-legacy")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	// GrantID intentionally left zero-value: the SignAccessToken merge
	// drops "gid" from the wire under omitempty equivalence, so the
	// resulting JWT models a legacy / pre-ADR-0025 access token.
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-legacy",
	})

	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: now},
	}
	got, _, err := v.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.GrantID != "" {
		t.Errorf("GrantID=%q want empty (legacy AT without gid)", got.GrantID)
	}
}

// TestVerify_RejectsIDTokenTypAtAccessTokenSlot pins the at+jwt typ
// header check (RFC 9068 §2.1 / §4). The defence is structural: even
// when an ID token (typ=JWT) shares the OP's signing key with the
// JWT-shaped access token, presenting it at /userinfo or /introspect
// MUST be rejected because resource servers consume the typ tag to
// distinguish the two formats.
//
// The token is signed with the OP's ES256 key but with typ=JWT (the ID
// token shape). Verify MUST surface ErrAccessTokenTypeMismatch before
// the signature verifies — otherwise an ID token leaking through a
// resource-server endpoint would resolve as a valid access token.
func TestVerify_RejectsIDTokenTypAtAccessTokenSlot(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: entry.Signer},
		(&josev4.SignerOptions{}).WithType("JWT").WithHeader("kid", entry.KeyID),
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

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}
	_, _, gotErr := v.Verify(raw)
	if !errors.Is(gotErr, tokens.ErrAccessTokenTypeMismatch) {
		t.Fatalf("typ=JWT err=%v want ErrAccessTokenTypeMismatch", gotErr)
	}
	if errors.Is(gotErr, tokens.ErrAccessTokenSignature) {
		t.Fatalf("typ mismatch must NOT leak as ErrAccessTokenSignature; pin lives pre-verify")
	}
}

// TestVerify_RejectsMissingTypHeader pins that a JWT without any typ
// header at all is rejected. RFC 9068 §2.1 mandates an explicit typ
// value; an absent header would otherwise default to "JWT" by RFC 7519
// §5.1 convention, so an attacker minting a header without typ would
// otherwise pass the at+jwt-only branch.
func TestVerify_RejectsMissingTypHeader(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: entry.Signer},
		(&josev4.SignerOptions{}).WithHeader("kid", entry.KeyID),
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

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}
	_, _, gotErr := v.Verify(raw)
	if !errors.Is(gotErr, tokens.ErrAccessTokenTypeMismatch) {
		t.Fatalf("missing typ err=%v want ErrAccessTokenTypeMismatch", gotErr)
	}
}

// TestVerify_RejectsMissingRequiredClaim pins the rule that every
// claim RFC 9068 §2.2 marks REQUIRED for an at+jwt access token
// (iss / sub / aud / client_id / iat / exp) MUST cause the verifier
// to refuse the token as malformed. The wrapped cause names the
// offending claim for log diagnosis but never reaches the wire
// envelope (RFC 6750 §3.1 invalid_token).
//
// The matrix builds otherwise-valid tokens with one claim removed
// at a time so the failure attribution is unambiguous: a regression
// that drops a row stops failing exactly that row, and the audit
// log stops naming the missing claim.
func TestVerify_RejectsMissingRequiredClaim(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	full := tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "required-claim",
	}
	mutators := []struct {
		name string
		mut  func(*tokens.AccessTokenClaims)
	}{
		{"missing-iss", func(c *tokens.AccessTokenClaims) { c.Issuer = "" }},
		{"missing-sub", func(c *tokens.AccessTokenClaims) { c.Subject = "" }},
		{"missing-aud", func(c *tokens.AccessTokenClaims) { c.Audience = nil }},
		{"missing-client_id", func(c *tokens.AccessTokenClaims) { c.ClientID = "" }},
		{"missing-iat", func(c *tokens.AccessTokenClaims) { c.IssuedAt = 0 }},
		{"missing-exp", func(c *tokens.AccessTokenClaims) { c.ExpiresAt = 0 }},
	}
	for _, tc := range mutators {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := full
			tc.mut(&claims)
			jws := signed(t, entry, claims)
			v := &tokens.AccessTokenVerifier{
				Keys:   set,
				Issuer: "https://op.example.com",
				Clock:  fakeClock{now: now},
			}
			_, _, err := v.Verify(jws)
			if !errors.Is(err, tokens.ErrAccessTokenMalformed) {
				t.Fatalf("%s err=%v want ErrAccessTokenMalformed", tc.name, err)
			}
		})
	}
}

// TestVerify_RequireJTIRejectsMissingJTI pins the opt-in jti
// requirement. RFC 9068 §2.2 marks jti RECOMMENDED rather than
// REQUIRED, so the default verifier accepts a jti-less token; a
// caller whose revocation strategy keys on jti (registry / denylist)
// MUST flip [AccessTokenVerifier.RequireJTI] to true so the
// pre-revocation gate refuses the wire-shape that would silently
// bypass revocation.
func TestVerify_RequireJTIRejectsMissingJTI(t *testing.T) {
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
		// JTI omitted on purpose.
	})

	// Default verifier (RequireJTI=false) accepts.
	v := &tokens.AccessTokenVerifier{
		Keys:   set,
		Issuer: "https://op.example.com",
		Clock:  fakeClock{now: now},
	}
	if _, _, err := v.Verify(jws); err != nil {
		t.Fatalf("RequireJTI=false err=%v want nil", err)
	}

	// Opt-in verifier rejects.
	strict := &tokens.AccessTokenVerifier{
		Keys:       set,
		Issuer:     "https://op.example.com",
		Clock:      fakeClock{now: now},
		RequireJTI: true,
	}
	if _, _, err := strict.Verify(jws); !errors.Is(err, tokens.ErrAccessTokenMalformed) {
		t.Fatalf("RequireJTI=true err=%v want ErrAccessTokenMalformed", err)
	}
}

func TestVerify_NilClockUsesSystemClock(t *testing.T) {
	t.Parallel()

	// A nil verifier Clock must defer to the system clock without
	// panicking. The test cannot observe System time directly (lint
	// forbids time.Now() in non-timex callers), so we sign a token whose
	// exp is decades in the future to be robust against scheduling
	// jitter and clock skew on slower CI runners. iat is anchored at
	// a fixed past timestamp (2000-01-01) so the iat-future gate is
	// satisfied and the required-iat check passes.
	set, entry := mustKeySet(t, "kid-1")
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	farPast := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	jws := signed(t, entry, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		ClientID:  "client-1",
		IssuedAt:  farPast,
		ExpiresAt: farFuture,
		JTI:       "no-clock",
	})

	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com"}
	if _, _, err := v.Verify(jws); err != nil {
		t.Fatalf("Verify with nil Clock: %v", err)
	}
}
