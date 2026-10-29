package clientauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	internaljose "github.com/libraz/go-oidc-provider/internal/jose"
)

// refreshingResolver answers RefreshJWKS with a fixed keyset so a test can
// hand the rotation retry a refetch result of its choosing.
type refreshingResolver struct {
	keys  *josev4.JSONWebKeySet
	fresh *josev4.JSONWebKeySet
}

func (r refreshingResolver) JWKS(context.Context, string) (*josev4.JSONWebKeySet, error) {
	return r.keys, nil
}

func (r refreshingResolver) RefreshJWKS(context.Context, string) (*josev4.JSONWebKeySet, error) {
	return r.fresh, nil
}

func ecJWKSet(tb testing.TB, kids ...string) *josev4.JSONWebKeySet {
	tb.Helper()
	set := &josev4.JSONWebKeySet{}
	for _, kid := range kids {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			tb.Fatalf("GenerateKey: %v", err)
		}
		set.Keys = append(set.Keys, josev4.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Use: "sig"})
	}
	return set
}

func kidlessJWS(tb testing.TB) *josev4.JSONWebSignature {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.ES256, Key: key}, nil)
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	signed, err := signer.Sign([]byte(`{}`))
	if err != nil {
		tb.Fatalf("Sign: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		tb.Fatalf("CompactSerialize: %v", err)
	}
	jws, _, err := internaljose.ParseSigned(compact)
	if err != nil {
		tb.Fatalf("ParseSigned: %v", err)
	}
	return jws
}

// TestRefreshedKeysOnKIDMissSkipsUnchangedKeyset pins the per-request bound
// on signature trials: a refetch that hands back the keyset already tried
// (an inline-JWKs client, or a jwks_uri refetch the throttle answered from
// cache) cannot explain the miss, so it must not buy a second trial round.
func TestRefreshedKeysOnKIDMissSkipsUnchangedKeyset(t *testing.T) {
	t.Parallel()

	jws := kidlessJWS(t)
	tried := ecJWKSet(t, "a", "b", "c", "d")
	copied := &josev4.JSONWebKeySet{Keys: append([]josev4.JSONWebKey(nil), tried.Keys...)}
	rotated := ecJWKSet(t, "e")

	cases := []struct {
		name   string
		fresh  *josev4.JSONWebKeySet
		wantOK bool
	}{
		{name: "same_pointer", fresh: tried, wantOK: false},
		{name: "same_content", fresh: copied, wantOK: false},
		{name: "rotated", fresh: rotated, wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := refreshingResolver{keys: tried, fresh: tc.fresh}
			_, ok, err := refreshedKeysOnKIDMiss(context.Background(), resolver, "client-1", jws, tried)
			if err != nil {
				t.Fatalf("refreshedKeysOnKIDMiss: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tc.wantOK)
			}
		})
	}
}
