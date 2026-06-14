package userinfo_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// rpEncryptionKeypair holds an RP-side RSA keypair plus its public-key
// JWK marshalled into a JWKS document. The OP encrypts the userinfo
// JWE to the public half; the test decrypts with the private half to
// recover the inner JWS and pin the wire shape.
type rpEncryptionKeypair struct {
	priv *rsa.PrivateKey
	jwks json.RawMessage
}

// newRPEncryptionKeypair generates a fresh 2048-bit RSA key — the
// minimum allowed by [internal/clientencjwks] and [internal/jose] —
// and marshals its public half into a JWKS the OP can ingest as
// [store.Client.JWKs]. Each test calls this helper so parallel tests
// do not share key material; the cost is acceptable because the
// encryption path is exercised in only a handful of cases.
func newRPEncryptionKeypair(tb testing.TB) rpEncryptionKeypair {
	tb.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := josev4.JSONWebKey{
		Key:       &k.PublicKey,
		KeyID:     "rp-enc-1",
		Use:       "enc",
		Algorithm: "RSA-OAEP-256",
	}
	body, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{jwk}})
	if err != nil {
		tb.Fatalf("marshal jwks: %v", err)
	}
	return rpEncryptionKeypair{priv: k, jwks: body}
}

func newWeakRPEncryptionKeypair(tb testing.TB) rpEncryptionKeypair {
	tb.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // intentional weak key for floor-rejection test
	if err != nil {
		tb.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := josev4.JSONWebKey{
		Key:       &k.PublicKey,
		KeyID:     "rp-weak-enc",
		Use:       "enc",
		Algorithm: "RSA-OAEP-256",
	}
	body, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{jwk}})
	if err != nil {
		tb.Fatalf("marshal jwks: %v", err)
	}
	return rpEncryptionKeypair{priv: k, jwks: body}
}

// putClient seeds the in-memory client store with the supplied
// record. The userinfo handler resolves the AT-bound client through
// [HandlerDeps.Clients]; tests use this helper to wire encryption
// metadata onto the client without going through the registration
// endpoint's full validation.
func (f *userInfoFixture) putClient(tb testing.TB, c *store.Client) {
	tb.Helper()
	if err := f.prov.Store.RegisterClient(context.Background(), c); err != nil {
		tb.Fatalf("Store.RegisterClient: %v", err)
	}
}

// newJWTAcceptGet returns a GET /userinfo request whose Accept header
// opts into the JWT-shape response (OIDC Core 1.0 §5.3.1.1). An empty
// Accept header keeps the JSON-shape default.
func (f *userInfoFixture) newJWTAcceptGet(tb testing.TB, token string) *http.Request {
	tb.Helper()
	req := f.newGet(tb, token)
	req.Header.Set("Accept", "application/jwt")
	return req
}

// TestHandler_EncryptionMetadataForcesJWTShape pins the §10.2 /
// §5.3.2 downgrade guard: a client carrying
// userinfo_encrypted_response_alg / _enc receives a nested JWE even
// when the request did not opt into the JWT shape via Accept.
func TestHandler_EncryptionMetadataForcesJWTShape(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	kp := newRPEncryptionKeypair(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com", "email_verified": true})
	f.putClient(t, &store.Client{
		ID:                           "client-enc-json",
		UserInfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserInfoEncryptedResponseEnc: "A256GCM",
		JWKs:                         kp.jwks,
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = "client-enc-json"
	})

	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/jwt" {
		t.Errorf("Content-Type=%q want application/jwt", got)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	got := strings.TrimSpace(string(raw))
	if segs := strings.Split(got, "."); len(segs) != 5 {
		t.Fatalf("body must be a 5-segment JWE, got %d segments: %s", len(segs), got)
	}
	jwe, err := josev4.ParseEncrypted(got,
		[]josev4.KeyAlgorithm{josev4.RSA_OAEP_256},
		[]josev4.ContentEncryption{josev4.A256GCM},
	)
	if err != nil {
		t.Fatalf("ParseEncrypted: %v", err)
	}
	innerBytes, err := jwe.Decrypt(kp.priv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	parsed, err := jwt.ParseSigned(string(innerBytes), []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned inner: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(f.signer.Signer.Public(), &claims); err != nil {
		t.Fatalf("verify inner Claims: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub=%v want user-1", claims["sub"])
	}
}

// TestHandler_JWTShape_NoEncryptionMetadata pins the signed-only
// branch: a client without encryption metadata served on the JWT
// shape receives a 3-segment JWS with Content-Type application/jwt.
// The signed body's iss / aud are stamped per OIDC Core 1.0 §5.3.2.
func TestHandler_JWTShape_NoEncryptionMetadata(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com", "email_verified": true})
	f.putClient(t, &store.Client{
		ID: "client-jwt-only",
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = "client-jwt-only"
	})

	resp := f.doRequest(t, f.newJWTAcceptGet(t, token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/jwt" {
		t.Errorf("Content-Type=%q want application/jwt", got)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	got := strings.TrimSpace(string(raw))
	if segs := strings.Split(got, "."); len(segs) != 3 {
		t.Fatalf("body must be a 3-segment JWS, got %d segments: %s", len(segs), got)
	}

	// Verify the JWS with the OP's public key and pin sub / iss / aud.
	parsed, err := jwt.ParseSigned(got, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(f.signer.Signer.Public(), &claims); err != nil {
		t.Fatalf("verify Claims: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub=%v want user-1", claims["sub"])
	}
	if claims["iss"] != f.prov.Issuer {
		t.Errorf("iss=%v want %q", claims["iss"], f.prov.Issuer)
	}
	if claims["aud"] != "client-jwt-only" {
		t.Errorf("aud=%v want client-jwt-only", claims["aud"])
	}
}

// TestHandler_JWTShape_EncryptedRSA pins the canonical signed-then-
// encrypted JWT shape: a client registered with encryption metadata
// AND a working RSA `use=enc` key receives a 5-segment JWE whose
// inner JWS is the OP's userinfo signing output. The test decrypts
// the JWE with the RP's private key and verifies the inner JWS with
// the OP's public key.
func TestHandler_JWTShape_EncryptedRSA(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	kp := newRPEncryptionKeypair(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com", "email_verified": true})
	f.putClient(t, &store.Client{
		ID:                           "client-jwe",
		UserInfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserInfoEncryptedResponseEnc: "A256GCM",
		JWKs:                         kp.jwks,
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = "client-jwe"
	})

	resp := f.doRequest(t, f.newJWTAcceptGet(t, token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/jwt" {
		t.Errorf("Content-Type=%q want application/jwt", got)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	got := strings.TrimSpace(string(raw))
	if segs := strings.Split(got, "."); len(segs) != 5 {
		t.Fatalf("body must be a 5-segment JWE, got %d segments: %s", len(segs), got)
	}

	jwe, err := josev4.ParseEncrypted(got,
		[]josev4.KeyAlgorithm{josev4.RSA_OAEP_256},
		[]josev4.ContentEncryption{josev4.A256GCM},
	)
	if err != nil {
		t.Fatalf("ParseEncrypted: %v", err)
	}
	if cty, _ := jwe.Header.ExtraHeaders["cty"].(string); cty != "JWT" {
		t.Errorf("cty=%v want JWT", jwe.Header.ExtraHeaders["cty"])
	}
	innerBytes, err := jwe.Decrypt(kp.priv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	innerJWS := string(innerBytes)
	if segs := strings.Split(innerJWS, "."); len(segs) != 3 {
		t.Fatalf("inner JWS must be 3 segments, got %d: %s", len(segs), innerJWS)
	}
	parsed, err := jwt.ParseSigned(innerJWS, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned inner: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(f.signer.Signer.Public(), &claims); err != nil {
		t.Fatalf("verify inner Claims: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub=%v want user-1", claims["sub"])
	}
	if claims["aud"] != "client-jwe" {
		t.Errorf("aud=%v want client-jwe", claims["aud"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("email=%v want alice@example.com", claims["email"])
	}
}

// TestHandler_JWTShape_EncryptionRequested_NoMatchingKey pins the
// no-silent-downgrade contract: a client that registered encryption
// metadata but published no `use=enc` key MUST surface a 500 rather
// than the signed JWS in the clear. Falling back to signed-only
// would defeat the opt-in confidentiality property.
func TestHandler_JWTShape_EncryptionRequested_NoMatchingKey(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	// Register a client whose JWKS contains only `use=sig` keys; the
	// resolver will collapse to ErrNoMatchingKey.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	sigJWK := josev4.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     "rp-sig-1",
		Use:       "sig",
		Algorithm: "RS256",
	}
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{sigJWK}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	f.putClient(t, &store.Client{
		ID:                           "client-jwe-bad-keys",
		UserInfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserInfoEncryptedResponseEnc: "A256GCM",
		JWKs:                         jwks,
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = "client-jwe-bad-keys"
	})

	resp := f.doRequest(t, f.newJWTAcceptGet(t, token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 500 (resolver failure must NOT downgrade to signed); body=%s", resp.StatusCode, dump)
	}
	// Ensure the wire body did not leak a JWS / JWE shape — the
	// silent-downgrade regression would emit a 3-segment body here.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.Count(string(raw), ".") >= 2 {
		t.Errorf("500 body must not contain a JWS/JWE shape: %s", raw)
	}
}

func TestHandler_JWTShape_EncryptionRequested_WeakKey(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	kp := newWeakRPEncryptionKeypair(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	f.putClient(t, &store.Client{
		ID:                           "client-jwe-weak",
		UserInfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserInfoEncryptedResponseEnc: "A256GCM",
		JWKs:                         kp.jwks,
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = "client-jwe-weak"
	})

	resp := f.doRequest(t, f.newJWTAcceptGet(t, token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 500; body=%s", resp.StatusCode, dump)
	}
}
