package tokens_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

func newTestSigner(tb testing.TB) tokens.SigningKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	return tokens.SigningKey{KeyID: "k1", Signer: priv}
}

func decodePayload(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("compact JWS expected 3 parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("decode payload: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("unmarshal: %v", err)
	}
	return out
}

func decodeHeader(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		tb.Fatalf("decode header: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("unmarshal header: %v", err)
	}
	return out
}

func TestSignIDToken_BasicShape(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	claims := tokens.IDTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		AuthTime:  now.Add(-5 * time.Minute).Unix(),
		Nonce:     "n-0S6_WzA2Mj",
	}
	jws, err := tokens.SignIDToken(key, claims)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	header := decodeHeader(t, jws)
	if header["alg"] != "ES256" || header["kid"] != "k1" || header["typ"] != "JWT" {
		t.Errorf("header=%v", header)
	}
}

// TestSignAccessToken_TypHeader pins RFC 9068 §2.1: a JWT-shaped
// access token MUST carry typ="at+jwt" so a resource server can
// distinguish it from an ID token (typ="JWT") and reject any inbound
// JWT whose typ does not match — the structural defence against
// cross-token confusion (RFC 9068 §5).
func TestSignAccessToken_TypHeader(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-typ",
		Scope:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	header := decodeHeader(t, jws)
	if header["typ"] != "at+jwt" {
		t.Errorf("typ=%v want at+jwt (RFC 9068 §2.1)", header["typ"])
	}
	if header["alg"] != "ES256" || header["kid"] != "k1" {
		t.Errorf("header=%v", header)
	}
}

// TestSignIDToken_TypHeader_Distinct pins the distinct typ between
// id_token and access_token: an attacker who replays an ID token
// against a resource server that strict-checks typ will be rejected
// because the typ values differ ("JWT" vs "at+jwt", RFC 9068 §2.1).
func TestSignIDToken_TypHeader_Distinct(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	idt, err := tokens.SignIDToken(key, tokens.IDTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	at, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-distinct",
		Scope:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	idHdr := decodeHeader(t, idt)
	atHdr := decodeHeader(t, at)
	if idHdr["typ"] == atHdr["typ"] {
		t.Errorf("id_token typ=%v access_token typ=%v want distinct", idHdr["typ"], atHdr["typ"])
	}
	if idHdr["typ"] != "JWT" {
		t.Errorf("id_token typ=%v want JWT", idHdr["typ"])
	}
	if atHdr["typ"] != "at+jwt" {
		t.Errorf("access_token typ=%v want at+jwt", atHdr["typ"])
	}
	payload := decodePayload(t, idt)
	if payload["iss"] != "https://op.example.com" || payload["sub"] != "user-1" {
		t.Errorf("payload=%v", payload)
	}
	if payload["aud"] != "client-1" {
		t.Errorf("aud=%v want bare-string for single audience", payload["aud"])
	}
	if _, ok := payload["nonce"]; ok {
		t.Errorf("omitempty broken for nonce (none was supplied): %v", payload["nonce"])
	}
	if _, ok := payload["acr"]; ok {
		t.Errorf("omitempty broken for acr: %v", payload["acr"])
	}
}

func TestSignIDToken_MultipleAudiencesEncodeAsArray(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws, err := tokens.SignIDToken(key, tokens.IDTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1", "client-2"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	payload := decodePayload(t, jws)
	aud, ok := payload["aud"].([]any)
	if !ok || len(aud) != 2 {
		t.Errorf("aud=%v want 2-element array", payload["aud"])
	}
}

func TestSignIDToken_RejectsExtraStandardCollision(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	_, err := tokens.SignIDToken(key, tokens.IDTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Extra:     map[string]any{"sub": "attacker"},
	})
	if err == nil {
		t.Fatal("expected collision error, got nil")
	}
}

func TestSignIDToken_ExtraClaimsCarried(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws, err := tokens.SignIDToken(key, tokens.IDTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Extra:     map[string]any{"email": "user@example.com"},
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	payload := decodePayload(t, jws)
	if payload["email"] != "user@example.com" {
		t.Errorf("extra email lost: %v", payload["email"])
	}
}

func TestSignAccessToken_ScopeJoinAndJTI(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-1",
		Scope:     []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	payload := decodePayload(t, jws)
	if payload["scope"] != "openid profile" {
		t.Errorf("scope=%v want \"openid profile\"", payload["scope"])
	}
	if payload["jti"] != "at-1" {
		t.Errorf("jti=%v", payload["jti"])
	}
	if payload["client_id"] != "client-1" {
		t.Errorf("client_id=%v", payload["client_id"])
	}
}

// TestSignAccessToken_GrantIDEmbedsGidClaim pins ADR 0025's wire
// contract: when AccessTokenClaims.GrantID is non-empty the encoded
// payload carries the "gid" private claim verbatim. The claim is
// meaningful only to the issuing OP (RFC 7519 §4.3); resource servers
// MUST ignore it.
func TestSignAccessToken_GrantIDEmbedsGidClaim(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-gid",
		Scope:     []string{"openid"},
		GrantID:   "g123",
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	payload := decodePayload(t, jws)
	if payload["gid"] != "g123" {
		t.Errorf("gid=%v want \"g123\" (ADR 0025 wire contract)", payload["gid"])
	}
}

// TestSignAccessToken_GrantIDOmitemptyWhenEmpty pins the omitempty
// equivalent for the map-based merge: a zero-value GrantID MUST NOT
// appear on the wire so legacy / RevocationStrategyJTIRegistry
// deployments emit unchanged bytes (ADR 0025 §Wire change).
func TestSignAccessToken_GrantIDOmitemptyWhenEmpty(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "at-no-gid",
		Scope:     []string{"openid"},
		// GrantID intentionally left zero-value.
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	payload := decodePayload(t, jws)
	if v, ok := payload["gid"]; ok {
		t.Errorf("gid present with zero-value GrantID: %v (omitempty equivalent broken)", v)
	}
}

func TestSignIDToken_NilSignerReturnsSentinel(t *testing.T) {
	t.Parallel()
	_, err := tokens.SignIDToken(tokens.SigningKey{KeyID: "k1"}, tokens.IDTokenClaims{})
	if err == nil {
		t.Fatal("expected sentinel error for nil Signer")
	}
}

func TestHash_AtHashLeftHalfBase64URL(t *testing.T) {
	t.Parallel()

	// "Jahfdo7lpA4o..." is the canonical example from OIDC Core 1.0
	// §3.1.3.6 example: SHA-256 of the access_token, take the first
	// 16 bytes, base64url-encode without padding. We don't recreate
	// the exact spec example because the access_token there is taken
	// from a different fixture; instead we verify the function's
	// shape: 22 chars, no padding, decodes to 16 bytes.
	got := tokens.Hash("hello")
	if len(got) != 22 {
		t.Errorf("len=%d want 22", len(got))
	}
	if strings.ContainsAny(got, "=") {
		t.Errorf("padding leaked: %q", got)
	}
	b, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(b) != 16 {
		t.Errorf("decoded len=%d want 16", len(b))
	}
}

func TestSignedToken_VerifiesAgainstJWKS(t *testing.T) {
	t.Parallel()

	// Build a real keys.Set from the same key; the OP would publish
	// the JWKS view of that set, and an RP would verify the token
	// against it. The test confirms tokens.SignIDToken's output is
	// compatible with that JWKS verification path end-to-end.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{{KeyID: "kid-roundtrip", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jws, err := tokens.SignIDToken(tokens.FromInternalEntry(set.Active()), tokens.IDTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	parsed, err := josev4.ParseSigned(jws, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	jwks := set.JWKS()
	if len(jwks.Keys) == 0 {
		t.Fatal("set.JWKS empty")
	}
	if _, err := parsed.Verify(jwks.Keys[0]); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
