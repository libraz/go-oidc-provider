package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const replayTestAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.

func replayTestKey(t *testing.T) (*ecdsa.PrivateKey, *josev4.JSONWebKeySet) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
	}}}
}

func replayTestAssertion(t *testing.T, priv *ecdsa.PrivateKey, clientID, jti string, now time.Time) string {
	t.Helper()
	return signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": replayTestAud,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
}

func TestPrivateKeyJWTVerifier_OverlongJTIRejectedBeforeMark(t *testing.T) {
	t.Parallel()

	priv, keys := replayTestKey(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jtis := &recordingJTIStore{}
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: keys},
		JTIStore: jtis,
		Audience: replayTestAud,
		Clock:    fixedClock{now: now}.Now,
	}

	err := v.Verify(context.Background(), "client-1", replayTestAssertion(t, priv, "client-1", strings.Repeat("j", 257), now))
	if !errors.Is(err, clientauth.ErrAssertionMalformed) {
		t.Fatalf("257-byte jti err=%v, want ErrAssertionMalformed", err)
	}
	if jtis.jti != "" {
		t.Fatalf("replay store written for an overlong jti: %q", jtis.jti)
	}
	if err := v.Verify(context.Background(), "client-1", replayTestAssertion(t, priv, "client-1", strings.Repeat("j", 256), now)); err != nil {
		t.Fatalf("256-byte jti err=%v, want accepted", err)
	}
}

// Client ids may contain the key separator; ("a:b", "c") and ("a", "b:c")
// must not share a replay marker.
func TestPrivateKeyJWTVerifier_DistinctClientsDoNotShareJTIMarker(t *testing.T) {
	t.Parallel()

	priv, keys := replayTestKey(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: keys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: replayTestAud,
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "a:b", replayTestAssertion(t, priv, "a:b", "c", now)); err != nil {
		t.Fatalf("client a:b: %v", err)
	}
	if err := v.Verify(context.Background(), "a", replayTestAssertion(t, priv, "a", "b:c", now)); err != nil {
		t.Fatalf("client a with jti b:c collided with client a:b: %v", err)
	}
}

type failingClientStore struct{ err error }

func (s failingClientStore) GetClient(context.Context, string) (*store.Client, error) {
	return nil, s.err
}

type overloadedFreshFetcher struct{ cached *josev4.JSONWebKeySet }

func (f overloadedFreshFetcher) Fetch(context.Context, string) (*josev4.JSONWebKeySet, error) {
	return f.cached, nil
}

func (f overloadedFreshFetcher) FetchFresh(context.Context, string) (*josev4.JSONWebKeySet, error) {
	return nil, fmt.Errorf("jar: fetch: %w", &rpjwks.TransientError{Cause: rpjwks.ErrOverloaded})
}

// Key-resolution failures caused by the OP itself (store outage, URL-load
// capacity) must reach the wire as server_error, never invalid_client.
func TestPrivateKeyJWTVerifier_ServerSideKeyFaultIsNotInvalidClient(t *testing.T) {
	t.Parallel()

	priv, _ := replayTestKey(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	urlClient := map[string]*store.Client{
		"client-1": {ID: "client-1", JWKsURI: "https://client.example.com/jwks"},
	}
	overloaded := fmt.Errorf("jar: fetch: %w", &rpjwks.TransientError{Cause: rpjwks.ErrOverloaded})
	var staleKeys josev4.JSONWebKeySet
	if err := json.Unmarshal([]byte(sampleJWK), &staleKeys); err != nil {
		t.Fatalf("seed JWKs: %v", err)
	}

	cases := []struct {
		name    string
		clients store.ClientStore
		fetcher clientauth.URLFetcher
	}{
		{name: "jwks_uri_overloaded", clients: fakeClientStore{seed: urlClient}, fetcher: fakeURLFetcher{err: overloaded}},
		{name: "rotation_refetch_overloaded", clients: fakeClientStore{seed: urlClient}, fetcher: overloadedFreshFetcher{cached: &staleKeys}},
		{name: "client_store_outage", clients: failingClientStore{err: errors.New("db: connection refused")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := clientauth.NewStoreJWKSResolver(tc.clients)
			if err != nil {
				t.Fatalf("NewStoreJWKSResolver: %v", err)
			}
			if tc.fetcher != nil {
				r.SetURLFetcher(tc.fetcher)
			}
			v := &clientauth.PrivateKeyJWTVerifier{
				Resolver: r,
				JTIStore: &recordingJTIStore{},
				Audience: replayTestAud,
				Clock:    fixedClock{now: now}.Now,
			}
			err = v.Verify(context.Background(), "client-1", replayTestAssertion(t, priv, "client-1", "j-1", now))
			if err == nil || errors.Is(err, clientauth.ErrCredentialsInvalid) {
				t.Fatalf("err=%v, want a server-side error", err)
			}
			rec := httptest.NewRecorder()
			endpointsupport.WriteAuthnError(rec, err, false)
			if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"server_error"`) {
				t.Fatalf("wire=%d %s, want 500 server_error", rec.Code, rec.Body.String())
			}
		})
	}
}

// A jwks_uri that genuinely fails to serve keys stays a client fault.
func TestPrivateKeyJWTVerifier_JWKSFetchFailureStaysInvalidClient(t *testing.T) {
	t.Parallel()

	priv, _ := replayTestKey(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	r, err := clientauth.NewStoreJWKSResolver(fakeClientStore{seed: map[string]*store.Client{
		"client-1": {ID: "client-1", JWKsURI: "https://client.example.com/jwks"},
	}})
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	r.SetURLFetcher(fakeURLFetcher{err: errors.New("upstream returned 404")})
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: r,
		JTIStore: &recordingJTIStore{},
		Audience: replayTestAud,
		Clock:    fixedClock{now: now}.Now,
	}
	err = v.Verify(context.Background(), "client-1", replayTestAssertion(t, priv, "client-1", "j-1", now))
	if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("err=%v, want ErrCredentialsInvalid", err)
	}
}
