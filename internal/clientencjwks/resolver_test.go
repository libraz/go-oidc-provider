package clientencjwks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/store"
)

// mustRSAKey returns a fresh 2048-bit RSA keypair. The bit floor
// matches the OP allow-list so the resolver accepts the produced kid.
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

// inlineJWKs marshals the supplied keys into a JWKS JSON document
// suitable for [store.Client.JWKs]. Helper centralises the
// json.RawMessage round-trip so individual tests stay focused on the
// assertion under test.
func inlineJWKs(t *testing.T, keys ...josev4.JSONWebKey) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(josev4.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// rsaPublicJWK builds a public-key JWK with the supplied use / alg /
// kid for the given private key.
func rsaPublicJWK(priv *rsa.PrivateKey, kid, use, alg string) josev4.JSONWebKey {
	return josev4.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Use:       use,
		Algorithm: alg,
	}
}

// jwksHandler returns an http.Handler that serves body verbatim with
// the supplied status / content-type.
func jwksHandler(status int, body []byte) http.Handler {
	return jwksHandlerWithContentType(status, body, "application/jwk-set+json")
}

func jwksHandlerWithContentType(status int, body []byte, contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

func TestResolveRecipient_InlineJWKs_HappyPath(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	jwk := rsaPublicJWK(priv, "k1", "enc", "RSA-OAEP-256")
	client := &store.Client{
		ID:   "rp",
		JWKs: inlineJWKs(t, jwk),
	}

	r := clientencjwks.New(clientencjwks.Config{})
	rcpt, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("ResolveRecipient: %v", err)
	}
	if rcpt.Alg != jose.JWEAlgRSAOAEP256 {
		t.Errorf("alg=%q want %q", rcpt.Alg, jose.JWEAlgRSAOAEP256)
	}
	if rcpt.Enc != jose.JWEEncA256GCM {
		t.Errorf("enc=%q want %q", rcpt.Enc, jose.JWEEncA256GCM)
	}
	if rcpt.KeyID != "k1" {
		t.Errorf("kid=%q want %q", rcpt.KeyID, "k1")
	}
	if rcpt.Key == nil {
		t.Error("recipient key is nil")
	}
}

func TestResolveRecipient_JWKsURI_HappyPath(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	body, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{rsaPublicJWK(priv, "k2", "enc", "RSA-OAEP-256")},
	})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(jwksHandler(http.StatusOK, body))
	defer srv.Close()

	client := &store.Client{
		ID:      "rp",
		JWKsURI: srv.URL,
	}
	r := clientencjwks.New(clientencjwks.Config{AllowPrivateNetwork: true})
	rcpt, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A128GCM")
	if err != nil {
		t.Fatalf("ResolveRecipient: %v", err)
	}
	if rcpt.KeyID != "k2" {
		t.Errorf("kid=%q want %q", rcpt.KeyID, "k2")
	}
	if rcpt.Enc != jose.JWEEncA128GCM {
		t.Errorf("enc=%q want %q", rcpt.Enc, jose.JWEEncA128GCM)
	}
}

func TestResolveRecipient_OnlySigKey_ErrNoMatchingKey(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	jwk := rsaPublicJWK(priv, "sig-only", "sig", "RS256")
	client := &store.Client{ID: "rp", JWKs: inlineJWKs(t, jwk)}

	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrNoMatchingKey) {
		t.Fatalf("err=%v want ErrNoMatchingKey", err)
	}
}

func TestResolveRecipient_InlineJWKs_WeakRSARejected(t *testing.T) {
	t.Parallel()

	priv := mustWeakRSAKey(t)
	jwk := rsaPublicJWK(priv, "weak-rsa", "enc", "RSA-OAEP-256")
	client := &store.Client{ID: "rp", JWKs: inlineJWKs(t, jwk)}

	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrWeakRecipientKey) {
		t.Fatalf("err=%v want ErrWeakRecipientKey", err)
	}
}

func TestResolveRecipient_BothEmpty_ErrNoEncryptionConfigured(t *testing.T) {
	t.Parallel()

	client := &store.Client{ID: "rp"}
	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), client, "", "")
	if !errors.Is(err, clientencjwks.ErrNoEncryptionConfigured) {
		t.Fatalf("err=%v want ErrNoEncryptionConfigured", err)
	}
}

func TestResolveRecipient_DisallowedAlg(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	jwk := rsaPublicJWK(priv, "k1", "enc", "RSA1_5")
	client := &store.Client{ID: "rp", JWKs: inlineJWKs(t, jwk)}

	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA1_5", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrAlgNotAllowed) {
		t.Fatalf("err=%v want ErrAlgNotAllowed", err)
	}
}

func TestResolveRecipient_DisallowedEnc(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	jwk := rsaPublicJWK(priv, "k1", "enc", "RSA-OAEP-256")
	client := &store.Client{ID: "rp", JWKs: inlineJWKs(t, jwk)}

	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A128CBC-HS256")
	if !errors.Is(err, clientencjwks.ErrAlgNotAllowed) {
		t.Fatalf("err=%v want ErrAlgNotAllowed", err)
	}
}

func TestResolveRecipient_PartialMetadata(t *testing.T) {
	t.Parallel()

	client := &store.Client{ID: "rp"}
	r := clientencjwks.New(clientencjwks.Config{})

	// Partial metadata (alg without enc) is a configuration bug
	// from the RP; the resolver collapses it onto ErrAlgNotAllowed
	// so the wire response stays opaque.
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "")
	if !errors.Is(err, clientencjwks.ErrAlgNotAllowed) {
		t.Fatalf("alg-only err=%v want ErrAlgNotAllowed", err)
	}
	_, err = r.ResolveRecipient(context.Background(), client, "", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrAlgNotAllowed) {
		t.Fatalf("enc-only err=%v want ErrAlgNotAllowed", err)
	}
}

func TestResolveRecipient_NoJWKsAndNoURI(t *testing.T) {
	t.Parallel()

	client := &store.Client{ID: "rp"}
	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrJWKSConfigured) {
		t.Fatalf("err=%v want ErrJWKSConfigured", err)
	}
}

func TestResolveRecipient_JWKsURI_500(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwksHandler(http.StatusInternalServerError, []byte(`{}`)))
	defer srv.Close()

	client := &store.Client{ID: "rp", JWKsURI: srv.URL}
	r := clientencjwks.New(clientencjwks.Config{AllowPrivateNetwork: true})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestResolveRecipient_JWKsURI_RejectsBadContentType(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	body, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{rsaPublicJWK(priv, "k2", "enc", "RSA-OAEP-256")},
	})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(jwksHandlerWithContentType(http.StatusOK, body, "text/html"))
	defer srv.Close()

	client := &store.Client{ID: "rp", JWKsURI: srv.URL}
	r := clientencjwks.New(clientencjwks.Config{AllowPrivateNetwork: true})
	_, err = r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
	if !strings.Contains(err.Error(), "content-type") {
		t.Fatalf("err=%v want content-type detail", err)
	}
}

func TestResolveRecipient_JWKsURI_BodyExceedsCap(t *testing.T) {
	t.Parallel()

	// Stuff the response with more bytes than the configured cap so
	// the io.LimitReader+1 trip returns "body exceeds N bytes".
	big := make([]byte, 4096)
	for i := range big {
		big[i] = '0'
	}
	srv := httptest.NewServer(jwksHandler(http.StatusOK, big))
	defer srv.Close()

	client := &store.Client{ID: "rp", JWKsURI: srv.URL}
	r := clientencjwks.New(clientencjwks.Config{
		AllowPrivateNetwork: true,
		MaxBodyBytes:        128, // way smaller than 4096
	})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err=%v want descriptive 'exceeds' wrap", err)
	}
}

func TestResolveRecipient_SSRFRefusal_LoopbackHostname(t *testing.T) {
	t.Parallel()

	// Loopback host without AllowPrivateNetwork flag must be
	// refused by the SSRF gate; the resolver collapses the refusal
	// onto ErrJWKSFetch so the caller branches uniformly.
	client := &store.Client{ID: "rp", JWKsURI: "http://localhost:1/jwks"}
	r := clientencjwks.New(clientencjwks.Config{}) // AllowPrivateNetwork=false
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestResolveRecipient_InlineJWKs_EmptyUseAllowed(t *testing.T) {
	t.Parallel()

	// RFC 7517 §4.2 marks `use` OPTIONAL; an RP that omits it
	// publishes a key the resolver may still pick (the alg check
	// disambiguates). The test pins that behaviour so the resolver
	// matches the JAR-side default.
	priv := mustRSAKey(t)
	jwk := rsaPublicJWK(priv, "no-use", "", "RSA-OAEP-256")
	client := &store.Client{ID: "rp", JWKs: inlineJWKs(t, jwk)}

	r := clientencjwks.New(clientencjwks.Config{})
	rcpt, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("ResolveRecipient: %v", err)
	}
	if rcpt.KeyID != "no-use" {
		t.Errorf("kid=%q want %q", rcpt.KeyID, "no-use")
	}
}

func TestResolveRecipient_InlineJWKs_AlgUnspecifiedAllowed(t *testing.T) {
	t.Parallel()

	// A key without an `alg` advertisement is treated as compatible
	// with any allowed alg the caller registered. RFC 7517 §4.4
	// makes `alg` OPTIONAL.
	priv := mustRSAKey(t)
	jwk := rsaPublicJWK(priv, "no-alg", "enc", "")
	client := &store.Client{ID: "rp", JWKs: inlineJWKs(t, jwk)}

	r := clientencjwks.New(clientencjwks.Config{})
	rcpt, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("ResolveRecipient: %v", err)
	}
	if rcpt.KeyID != "no-alg" {
		t.Errorf("kid=%q want %q", rcpt.KeyID, "no-alg")
	}
}

func TestResolveRecipient_NilClient(t *testing.T) {
	t.Parallel()

	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), nil, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrJWKSConfigured) {
		t.Fatalf("err=%v want ErrJWKSConfigured", err)
	}
}

func TestResolveRecipient_InlineJWKs_MalformedJSON(t *testing.T) {
	t.Parallel()

	client := &store.Client{
		ID:   "rp",
		JWKs: json.RawMessage(`{"keys":[`), // truncated JSON
	}
	r := clientencjwks.New(clientencjwks.Config{})
	_, err := r.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}
