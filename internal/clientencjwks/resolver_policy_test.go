package clientencjwks_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestResolveRecipient_PolicyRejectsExcludedAlg pins the outbound half
// of an operator narrowing: a client registered for an algorithm the
// deployment excluded gets no recipient, so no id_token / userinfo /
// JARM / introspection response is ever wrapped in it — even though
// the client's JWKS carries a perfectly usable key for it.
func TestResolveRecipient_PolicyRejectsExcludedAlg(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	client := &store.Client{
		ID:   "rp",
		JWKs: inlineJWKs(t, rsaPublicJWK(priv, "k1", "enc", "RSA-OAEP-256")),
	}

	// The same client resolves without the narrowing.
	open := clientencjwks.New(clientencjwks.Config{})
	if _, err := open.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM"); err != nil {
		t.Fatalf("ResolveRecipient without policy: %v", err)
	}

	narrowed := clientencjwks.New(clientencjwks.Config{
		Policy: jose.JWEPolicy{Algs: []jose.JWEAlg{jose.JWEAlgECDHES}},
	})
	_, err := narrowed.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if !errors.Is(err, clientencjwks.ErrAlgNotAllowed) {
		t.Fatalf("ResolveRecipient with policy: got %v want %v", err, clientencjwks.ErrAlgNotAllowed)
	}
}

// TestResolveRecipient_PolicyRejectsExcludedEnc mirrors the alg case
// for the content-encryption half.
func TestResolveRecipient_PolicyRejectsExcludedEnc(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	client := &store.Client{
		ID:   "rp",
		JWKs: inlineJWKs(t, rsaPublicJWK(priv, "k1", "enc", "RSA-OAEP-256")),
	}

	narrowed := clientencjwks.New(clientencjwks.Config{
		Policy: jose.JWEPolicy{Encs: []jose.JWEEnc{jose.JWEEncA256GCM}},
	})
	_, err := narrowed.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A128GCM")
	if !errors.Is(err, clientencjwks.ErrAlgNotAllowed) {
		t.Fatalf("ResolveRecipient with policy: got %v want %v", err, clientencjwks.ErrAlgNotAllowed)
	}
}

// TestResolveRecipient_PolicyAdmitsRetainedPair guards against a
// narrowing that rejects everything: the pair the operator kept must
// still resolve.
func TestResolveRecipient_PolicyAdmitsRetainedPair(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	client := &store.Client{
		ID:   "rp",
		JWKs: inlineJWKs(t, rsaPublicJWK(priv, "k1", "enc", "RSA-OAEP-256")),
	}

	narrowed := clientencjwks.New(clientencjwks.Config{
		Policy: jose.JWEPolicy{
			Algs: []jose.JWEAlg{jose.JWEAlgRSAOAEP256},
			Encs: []jose.JWEEnc{jose.JWEEncA256GCM},
		},
	})
	rcpt, err := narrowed.ResolveRecipient(context.Background(), client, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("ResolveRecipient: %v", err)
	}
	if rcpt.KeyID != "k1" {
		t.Fatalf("kid=%q want k1", rcpt.KeyID)
	}
}
