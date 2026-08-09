package op

// The tests in this file live in package op (not op_test) so they can
// drive [buildClientEncryptionResolver] directly. Reaching the same
// seam from outside would need a full authorization-code flow ending in
// an encrypted id_token, which observes the wiring only indirectly.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/store"
)

// recordingTransport forwards to a real transport and records the URLs
// it carried, so a test can prove a fetch went through this transport
// and not the package default.
type recordingTransport struct {
	inner http.RoundTripper
	mu    sync.Mutex
	urls  []string
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.urls = append(t.urls, r.URL.String())
	t.mu.Unlock()
	return t.inner.RoundTrip(r)
}

func (t *recordingTransport) seen() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.urls...)
}

// TestBuildClientEncryptionResolver_UsesInjectedTransport pins the
// wiring [WithJWKSHTTPTransport] is supposed to have. The JAR and
// private_key_jwt fetchers already took the injected transport; the
// outbound-encryption fetcher did not, so on a deployment fronting its
// RPs with an internal CA the first encrypted id_token failed TLS
// verification while every other JWKS fetch succeeded.
func TestBuildClientEncryptionResolver_UsesInjectedTransport(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	body, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     "rp-enc",
		Use:       "enc",
		Algorithm: "RSA-OAEP-256",
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	rt := &recordingTransport{inner: http.DefaultTransport}
	resolver := buildClientEncryptionResolver(&config{
		jwksHTTPTransport:       rt,
		allowPrivateNetworkJWKS: true,
	})
	client := &store.Client{ID: "rp", JWKsURI: srv.URL}

	rcpt, err := resolver.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("ResolveRecipient: %v", err)
	}
	if rcpt.KeyID != "rp-enc" {
		t.Fatalf("kid=%q want rp-enc", rcpt.KeyID)
	}
	if seen := rt.seen(); len(seen) != 1 || seen[0] != srv.URL {
		t.Fatalf("injected transport saw %v; the fetch did not go through it", seen)
	}
}

// TestBuildClientEncryptionResolver_CarriesNarrowing pins the other
// half of the same builder: the deployment's alg narrowing reaches the
// outbound resolver, so a client registered for an excluded algorithm
// gets no recipient rather than a response encrypted with it.
func TestBuildClientEncryptionResolver_CarriesNarrowing(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	inline, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     "rp-enc",
		Use:       "enc",
		Algorithm: "RSA-OAEP-256",
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	client := &store.Client{ID: "rp", JWKs: inline}

	cfg := &config{
		encryptionAlgsAllowed:    []string{"ECDH-ES"},
		encryptionAlgsAllowedSet: true,
	}
	_, err = buildClientEncryptionResolver(cfg).
		ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if err == nil {
		t.Fatal("narrowed resolver produced a recipient for an excluded alg")
	}
}

// TestConfigJWEPolicy_NarrowingRoundTrip pins the conversion the whole
// enforcement chain depends on: an untouched half stays nil (the
// library allow-list), a narrowed half becomes exactly the operator's
// subset, and an explicitly empty narrowing permits nothing rather than
// collapsing back to the default.
func TestConfigJWEPolicy_NarrowingRoundTrip(t *testing.T) {
	t.Parallel()

	var unset config
	policy := unset.jwePolicy()
	if policy.Algs != nil || policy.Encs != nil {
		t.Fatalf("unset config produced a narrowing: %+v", policy)
	}
	if !policy.AllowsAlg(jose.JWEAlgRSAOAEP256) {
		t.Error("unset config rejects a shipped alg")
	}

	narrowed := config{
		encryptionAlgsAllowed:    []string{"ECDH-ES"},
		encryptionAlgsAllowedSet: true,
		encryptionEncsAllowed:    []string{},
		encryptionEncsAllowedSet: true,
	}
	policy = narrowed.jwePolicy()
	if policy.AllowsAlg(jose.JWEAlgRSAOAEP256) {
		t.Error("narrowed config admits the excluded alg")
	}
	if !policy.AllowsAlg(jose.JWEAlgECDHES) {
		t.Error("narrowed config rejects the retained alg")
	}
	if policy.AllowsEnc(jose.JWEEncA256GCM) {
		t.Error("empty enc narrowing still permits an enc")
	}
}
