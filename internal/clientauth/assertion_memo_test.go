package clientauth_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// countingClientStore counts GetClient calls so a test can assert the
// per-request memo collapses the resolver's repeated lookups.
type countingClientStore struct {
	inner store.ClientStore
	calls int
}

func (s *countingClientStore) GetClient(ctx context.Context, id string) (*store.Client, error) {
	s.calls++
	return s.inner.GetClient(ctx, id)
}

// TestPrivateKeyJWTVerifier_MemoisesClientLookup pins that a single
// assertion verification hits the backing ClientStore exactly once, even
// though the resolver resolves the client through two seams on the happy
// path (the alg-pin check and the JWKS lookup). Without the memo this
// would be two round-trips per verification against a SQL-backed store.
func TestPrivateKeyJWTVerifier_MemoisesClientLookup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv := newRSAKey(t)
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{
		rsaSigJWK(&priv.PublicKey, "rp-key-1"),
	}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	counter := &countingClientStore{inner: fakeClientStore{seed: map[string]*store.Client{
		"client-1": {ID: "client-1", JWKs: jwks},
	}}}
	resolver, err := clientauth.NewStoreJWKSResolver(counter)
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: resolver,
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: keyselectAud,
		Clock:    fixedClock{now: now}.Now,
	}

	assertion := signRSAAssertion(t, priv, "rp-key-1", keyselectClaims(now, "j-memo"))
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if counter.calls != 1 {
		t.Fatalf("GetClient called %d times, want 1 (per-request memo)", counter.calls)
	}
}
