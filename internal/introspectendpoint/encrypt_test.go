package introspectendpoint_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// rsaEncJWKs builds an inline JWK Set carrying a single RSA public
// key marked `use=enc` + `alg=RSA-OAEP-256`. The serialised bytes are
// destined for [store.Client.JWKs] so the resolver picks the key up
// without an outbound HTTP fetch (and without exposing a JWKsURI to
// the SSRF deny-list).
func rsaEncJWKs(t *testing.T, priv *rsa.PrivateKey, kid string) json.RawMessage {
	t.Helper()
	set := josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Use:       "enc",
			Algorithm: "RSA-OAEP-256",
		}},
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// rsaSigOnlyJWKs builds an inline JWK Set that omits any `use=enc`
// entry. The resolver should surface ErrNoMatchingKey, which the
// handler must collapse onto a 500 server_error envelope rather than
// silently emitting an unencrypted body.
func rsaSigOnlyJWKs(t *testing.T, priv *rsa.PrivateKey, kid string) json.RawMessage {
	t.Helper()
	set := josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Use:       "sig",
			Algorithm: "RS256",
		}},
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// mustRSAKey returns a freshly-generated 2048-bit RSA private key.
// Tests use it both as the recipient key (public half advertised in
// the client's JWKs) and to decrypt the JWE the handler emits.
func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func mustWeakRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // intentional weak key for floor-rejection test
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

// privKeyResolver implements [jose.EncryptionKeyResolver] over a
// single (kid, *rsa.PrivateKey) pair. The test uses it to decrypt the
// JWE the handler emits.
type privKeyResolver struct {
	kid string
	key *rsa.PrivateKey
}

func (r privKeyResolver) Resolve(kid string) (any, bool) {
	if kid == r.kid {
		return r.key, true
	}
	return nil, false
}

func (r privKeyResolver) All() []any { return []any{r.key} }

// TestHandler_Encrypted_JSONDefault_IgnoresMetadata confirms a
// client that registered introspection_encrypted_response_alg / _enc
// still receives the legacy JSON body when neither the Accept header
// nor the JWT-force gate selects RFC 9701. Encryption is layered
// strictly on top of the JWT path; a JSON-asking RP is unchanged.
func TestHandler_Encrypted_JSONDefault_IgnoresMetadata(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-enc-json-default")

	priv := mustRSAKey(t)
	mutated := *client
	mutated.JWKs = rsaEncJWKs(t, priv, "rp-enc-1")
	mutated.IntrospectionEncryptedResponseAlg = "RSA-OAEP-256"
	mutated.IntrospectionEncryptedResponseEnc = "A256GCM"
	if err := f.prov.Store.UpdateClient(context.Background(), &mutated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active=%v want true; body=%v", body["active"], body)
	}
}

// TestHandler_Encrypted_NoMetadata_EmitsSigned confirms that a JWT
// introspection response for a client without
// introspection_encrypted_response_alg / _enc stays a 3-segment JWS.
// The encryption splice MUST treat ErrNoEncryptionConfigured as
// "encryption not requested" and pass the signed body through
// verbatim.
func TestHandler_Encrypted_NoMetadata_EmitsSigned(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-enc-no-metadata")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.postWithAccept(t, form, client.ID, secret, jwtAccept)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != jwtAccept {
		t.Errorf("Content-Type=%q want %q", got, jwtAccept)
	}
	raw := readBody(t, resp)
	if got := strings.Count(raw, "."); got != 2 {
		t.Errorf("body has %d dots; want 2 (JWS); body=%q", got, raw)
	}
}

// TestHandler_Encrypted_HappyPath_RoundTrip drives the splice
// end-to-end: a client with RSA `use=enc` JWKs and a registered
// (alg, enc) pair receives a 5-segment JWE on /introspect. The test
// decrypts with the private key, parses the inner JWS, and checks
// the claim shape matches signIntrospectionJWT's allow-list (iss /
// aud / iat / token_introspection.{active, client_id, sub}).
func TestHandler_Encrypted_HappyPath_RoundTrip(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-enc-happy")

	priv := mustRSAKey(t)
	mutated := *client
	mutated.JWKs = rsaEncJWKs(t, priv, "rp-enc-happy")
	mutated.IntrospectionEncryptedResponseAlg = "RSA-OAEP-256"
	mutated.IntrospectionEncryptedResponseEnc = "A256GCM"
	if err := f.prov.Store.UpdateClient(context.Background(), &mutated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Subject = "user-enc"
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.postWithAccept(t, form, client.ID, secret, jwtAccept)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != jwtAccept {
		t.Errorf("Content-Type=%q want %q", got, jwtAccept)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}

	raw := readBody(t, resp)
	if got := strings.Count(raw, "."); got != 4 {
		t.Fatalf("body has %d dots; want 4 (JWE); body=%q", got, raw)
	}

	resolver := privKeyResolver{kid: "rp-enc-happy", key: priv}
	dec, err := jose.Decrypt(raw, resolver)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec.ContentType != "JWT" {
		t.Errorf("cty=%q want JWT", dec.ContentType)
	}

	innerJWS := string(dec.Plaintext)
	parsed, err := jwt.ParseSigned(innerJWS, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned inner: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(f.publicSigner(t), &claims); err != nil {
		t.Fatalf("inner Claims: %v", err)
	}
	if claims["iss"] != f.prov.Issuer {
		t.Errorf("iss=%v want %q", claims["iss"], f.prov.Issuer)
	}
	if claims["aud"] != client.ID {
		t.Errorf("aud=%v want %q", claims["aud"], client.ID)
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat not numeric: %T", claims["iat"])
	}
	intro, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection missing: %v", claims)
	}
	if active, _ := intro["active"].(bool); !active {
		t.Errorf("token_introspection.active=%v want true", intro["active"])
	}
	if intro["client_id"] != client.ID {
		t.Errorf("token_introspection.client_id=%v want %q", intro["client_id"], client.ID)
	}
	if intro["sub"] != "user-enc" {
		t.Errorf("token_introspection.sub=%v want user-enc", intro["sub"])
	}
}

// TestHandler_Encrypted_NoMatchingKey_ServerError confirms the
// downgrade-protection rule from RFC 9701 §5: when the client opted
// into encryption but its JWKs contains no `use=enc` key, the
// handler MUST NOT silently emit a signed-only body. The path
// instead collapses onto the 500 server_error envelope so the RP
// notices the configuration fault.
func TestHandler_Encrypted_NoMatchingKey_ServerError(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-enc-no-match")

	priv := mustRSAKey(t)
	mutated := *client
	mutated.JWKs = rsaSigOnlyJWKs(t, priv, "rp-sig-only")
	mutated.IntrospectionEncryptedResponseAlg = "RSA-OAEP-256"
	mutated.IntrospectionEncryptedResponseEnc = "A256GCM"
	if err := f.prov.Store.UpdateClient(context.Background(), &mutated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.postWithAccept(t, form, client.ID, secret, jwtAccept)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 500; body=%s", resp.StatusCode, dump)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "server_error" {
		t.Errorf("error=%v want server_error", body["error"])
	}
}

func TestHandler_Encrypted_WeakKey_ServerError(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-enc-weak")

	priv := mustWeakRSAKey(t)
	mutated := *client
	mutated.JWKs = rsaEncJWKs(t, priv, "rp-weak")
	mutated.IntrospectionEncryptedResponseAlg = "RSA-OAEP-256"
	mutated.IntrospectionEncryptedResponseEnc = "A256GCM"
	if err := f.prov.Store.UpdateClient(context.Background(), &mutated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.postWithAccept(t, form, client.ID, secret, jwtAccept)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 500; body=%s", resp.StatusCode, dump)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "server_error" {
		t.Errorf("error=%v want server_error", body["error"])
	}
}
