package jar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/op/store"
)

// failingFreshResolver serves a stale keyset and fails the forced refetch.
type failingFreshResolver struct {
	stale *josev4.JSONWebKeySet
	err   error
}

func (r *failingFreshResolver) Resolve(context.Context, *store.Client) (*josev4.JSONWebKeySet, error) {
	return r.stale, nil
}

func (r *failingFreshResolver) ResolveFresh(context.Context, *store.Client) (*josev4.JSONWebKeySet, error) {
	return nil, r.err
}

// TestVerify_KeySourceFaultIsServerSide pins that a JWKS fetch refused for
// capacity or failing transiently surfaces as ErrKeySourceUnavailable, on
// the first resolution and on the rotation refetch, while a plain fetch
// failure stays a client-side request-object error.
func TestVerify_KeySourceFaultIsServerSide(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, _, _ := signedRequestObject(t, happyClaims(now), "kid-rotated")
	_, staleJWK, _ := signedRequestObject(t, happyClaims(now), "kid-old")
	stale := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{*staleJWK}}
	overloaded := &rpjwks.TransientError{Cause: rpjwks.ErrOverloaded}
	client := &store.Client{ID: testClientID, JWKsURI: "https://rp.example.com/jwks"}

	for _, tc := range []struct {
		name     string
		resolver jar.JWKSResolver
		server   bool
	}{
		{"resolve overloaded", &staticResolver{err: overloaded}, true},
		{"resolve bare overload", &staticResolver{err: rpjwks.ErrOverloaded}, true},
		{"refetch overloaded", &failingFreshResolver{stale: stale, err: overloaded}, true},
		{"resolve fetch failure", &staticResolver{err: jar.ErrJWKSFetch}, false},
		{"refetch fetch failure", &failingFreshResolver{stale: stale, err: jar.ErrJWKSFetch}, false},
	} {
		v, err := jar.NewVerifier(jar.VerifierConfig{
			Issuer:          testIssuer,
			Resolver:        tc.resolver,
			Clock:           fakeClock{now: now},
			AllowMissingNbf: true,
			AllowMissingJTI: true,
		})
		if err != nil {
			t.Fatalf("%s: NewVerifier: %v", tc.name, err)
		}
		_, err = v.Verify(context.Background(), raw, testClientID, client)
		if err == nil {
			t.Fatalf("%s: Verify succeeded", tc.name)
		}
		if got := errors.Is(err, jar.ErrKeySourceUnavailable); got != tc.server {
			t.Errorf("%s: errors.Is(ErrKeySourceUnavailable)=%v want %v (err=%v)", tc.name, got, tc.server, err)
		}
	}
}
