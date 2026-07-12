package clientauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrivateKeyJWTVerifier_NoKeysRunsTimingShim pins L-14: a known
// client that has no usable JWKS is rejected through the same fixed-cost
// verify path as a wrong-signature attempt, closing the timing channel
// that would otherwise let an attacker distinguish "client has no keys"
// from "client has keys, bad signature". The test drives the branch
// through the public surface and asserts the uniform ErrCredentialsInvalid
// rejection; the code-coverage hit on the dummy verify is the regression
// guard (a wall-clock assertion would be flaky).
func TestPrivateKeyJWTVerifier_NoKeysRunsTimingShim(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv := newRSAKey(t)

	// Client exists but registered neither inline JWKs nor a JWKsURI:
	// JWKS resolution fails with no signature work on the naive path.
	resolver, err := clientauth.NewStoreJWKSResolver(fakeClientStore{seed: map[string]*store.Client{
		"client-1": {ID: "client-1"},
	}})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: resolver,
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: keyselectAud,
		Clock:    fixedClock{now: now}.Now,
	}

	assertion := signRSAAssertion(t, priv, "rp-key-1", keyselectClaims(now, "j-nokeys"))
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("no-keys client Verify: err=%v want ErrCredentialsInvalid", err)
	}
}
