package clientauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fakeClientStore is a tiny [store.ClientStore] for the resolver tests.
// It returns a preconfigured client when the lookup id matches the seed
// and [store.ErrNotFound] otherwise — exactly the contract the resolver
// requires.
type fakeClientStore struct {
	seed map[string]*store.Client
}

func (s fakeClientStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	if c, ok := s.seed[id]; ok {
		return c, nil
	}
	return nil, store.ErrNotFound
}

const sampleJWK = `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","kid":"k1","alg":"ES256"}]}`

func TestStoreJWKSResolver_InlineJWKsHit(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"alice": {ID: "alice", JWKs: json.RawMessage(sampleJWK)},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	keys, err := r.JWKS(context.Background(), "alice")
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("len(Keys)=%d, want 1", len(keys.Keys))
	}
	if got := keys.Keys[0].KeyID; got != "k1" {
		t.Errorf("kid=%q want %q", got, "k1")
	}
}

func TestStoreJWKSResolver_UnknownClient(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{seed: nil})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	_, err = r.JWKS(context.Background(), "nobody")
	if !errors.Is(err, clientauth.ErrJWKSNotConfigured) {
		t.Errorf("err=%v, want ErrJWKSNotConfigured", err)
	}
}

func TestStoreJWKSResolver_ClientWithoutKeys(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"empty": {ID: "empty"},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	_, err = r.JWKS(context.Background(), "empty")
	if !errors.Is(err, clientauth.ErrJWKSNotConfigured) {
		t.Errorf("err=%v, want ErrJWKSNotConfigured", err)
	}
}

func TestStoreJWKSResolver_JWKsURIRejected(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"url-only": {ID: "url-only", JWKsURI: "https://client.example.com/jwks"},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	_, err = r.JWKS(context.Background(), "url-only")
	if !errors.Is(err, clientauth.ErrJWKSURIUnsupported) {
		t.Errorf("err=%v, want ErrJWKSURIUnsupported", err)
	}
}

func TestStoreJWKSResolver_MalformedInline(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"bad": {ID: "bad", JWKs: json.RawMessage(`{not-json`)},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	_, err = r.JWKS(context.Background(), "bad")
	if err == nil {
		t.Fatal("expected error for malformed JWKs, got nil")
	}
}

func TestStoreJWKSResolver_NilStoreRejected(t *testing.T) {
	t.Parallel()

	if _, err := clientauth.NewStoreJWKSResolver(nil); err == nil {
		t.Fatal("expected error from nil store, got nil")
	}
}

func TestStoreJWKSResolver_EmptyKeysSlice(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"none": {ID: "none", JWKs: json.RawMessage(`{"keys":[]}`)},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	_, err = r.JWKS(context.Background(), "none")
	if !errors.Is(err, clientauth.ErrJWKSNotConfigured) {
		t.Errorf("err=%v, want ErrJWKSNotConfigured", err)
	}
}
