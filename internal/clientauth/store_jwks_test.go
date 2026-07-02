package clientauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

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

// fakeURLFetcher returns a canned response (or canned error) regardless
// of the URL. The test exercises the resolver's URLFetcher seam without
// depending on any HTTP machinery.
type fakeURLFetcher struct {
	keys *josev4.JSONWebKeySet
	err  error
}

func (f fakeURLFetcher) Fetch(_ context.Context, _ string) (*josev4.JSONWebKeySet, error) {
	return f.keys, f.err
}

func TestStoreJWKSResolver_JWKsURIFetched(t *testing.T) {
	t.Parallel()

	var keys josev4.JSONWebKeySet
	if err := json.Unmarshal([]byte(sampleJWK), &keys); err != nil {
		t.Fatalf("seed JWKs: %v", err)
	}
	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"url-only": {ID: "url-only", JWKsURI: "https://client.example.com/jwks"},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	r.SetURLFetcher(fakeURLFetcher{keys: &keys})
	got, err := r.JWKS(context.Background(), "url-only")
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "k1" {
		t.Errorf("got Keys=%+v", got.Keys)
	}
}

func TestStoreJWKSResolver_JWKsURIFetchError(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"url-only": {ID: "url-only", JWKsURI: "https://client.example.com/jwks"},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	wantErr := errors.New("upstream timeout")
	r.SetURLFetcher(fakeURLFetcher{err: wantErr})
	_, err = r.JWKS(context.Background(), "url-only")
	if !errors.Is(err, wantErr) {
		t.Errorf("err=%v, want wrapped %v", err, wantErr)
	}
}

func TestStoreJWKSResolver_JWKsURIEmptyKeys(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"url-only": {ID: "url-only", JWKsURI: "https://client.example.com/jwks"},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	r.SetURLFetcher(fakeURLFetcher{keys: &josev4.JSONWebKeySet{}})
	_, err = r.JWKS(context.Background(), "url-only")
	if !errors.Is(err, clientauth.ErrJWKSNotConfigured) {
		t.Errorf("err=%v, want ErrJWKSNotConfigured", err)
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

// fakeFreshURLFetcher implements both the plain fetch and the
// cache-bypassing FetchFresh so the resolver's RefreshJWKS seam can be
// exercised. Each method returns its own keyset so a test can tell which
// path ran.
type fakeFreshURLFetcher struct {
	cached *josev4.JSONWebKeySet
	fresh  *josev4.JSONWebKeySet
	freshN *int
}

func (f fakeFreshURLFetcher) Fetch(_ context.Context, _ string) (*josev4.JSONWebKeySet, error) {
	return f.cached, nil
}

func (f fakeFreshURLFetcher) FetchFresh(_ context.Context, _ string) (*josev4.JSONWebKeySet, error) {
	*f.freshN++
	return f.fresh, nil
}

func TestStoreJWKSResolver_RefreshJWKSRefetchesURI(t *testing.T) {
	t.Parallel()

	var cached, fresh josev4.JSONWebKeySet
	if err := json.Unmarshal([]byte(sampleJWK), &cached); err != nil {
		t.Fatalf("seed cached: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","kid":"k2","alg":"ES256"}]}`), &fresh); err != nil {
		t.Fatalf("seed fresh: %v", err)
	}
	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"url-only": {ID: "url-only", JWKsURI: "https://client.example.com/jwks"},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	freshN := 0
	r.SetURLFetcher(fakeFreshURLFetcher{cached: &cached, fresh: &fresh, freshN: &freshN})

	got, err := r.RefreshJWKS(context.Background(), "url-only")
	if err != nil {
		t.Fatalf("RefreshJWKS: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "k2" {
		t.Errorf("got Keys=%+v, want the FetchFresh keyset (kid k2)", got.Keys)
	}
	if freshN != 1 {
		t.Errorf("FetchFresh calls=%d, want 1", freshN)
	}
}

func TestStoreJWKSResolver_RefreshJWKSInlineReturnsInline(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"inline": {ID: "inline", JWKs: json.RawMessage(sampleJWK)},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	got, err := r.RefreshJWKS(context.Background(), "inline")
	if err != nil {
		t.Fatalf("RefreshJWKS: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "k1" {
		t.Errorf("got Keys=%+v, want the inline keyset (kid k1)", got.Keys)
	}
}

func TestStoreJWKSResolver_RefreshJWKSUnsupportedFetcher(t *testing.T) {
	t.Parallel()

	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{
		seed: map[string]*store.Client{
			"url-only": {ID: "url-only", JWKsURI: "https://client.example.com/jwks"},
		},
	})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	// fakeURLFetcher implements only Fetch, not FetchFresh.
	r.SetURLFetcher(fakeURLFetcher{keys: &josev4.JSONWebKeySet{}})
	_, err = r.RefreshJWKS(context.Background(), "url-only")
	if !errors.Is(err, clientauth.ErrJWKSURIUnsupported) {
		t.Errorf("err=%v, want ErrJWKSURIUnsupported", err)
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
