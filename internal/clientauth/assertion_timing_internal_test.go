package clientauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	internaljose "github.com/libraz/go-oidc-provider/internal/jose"
)

type timingResolver struct {
	keys *josev4.JSONWebKeySet
	err  error
}

func (r timingResolver) JWKS(context.Context, string) (*josev4.JSONWebKeySet, error) {
	return r.keys, r.err
}

//nolint:paralleltest // The test swaps the process-wide timing shim and counts it synchronously.
func TestResolveAndVerifyTimingShimRunsOnlyForUnavailableKeys(t *testing.T) {
	var burns int
	previous := burnJWTVerify
	burnJWTVerify = func() { burns++ }
	t.Cleanup(func() { burnJWTVerify = previous })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{
		Algorithm: josev4.RS256,
		Key:       key,
	}, (&josev4.SignerOptions{}).WithHeader("kid", "timing-key"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signed, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	jws, _, err := internaljose.ParseSigned(compact)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &key.PublicKey,
		KeyID:     "timing-key",
		Algorithm: string(josev4.RS256),
		Use:       "sig",
	}}}

	cases := []struct {
		name     string
		resolver JWKSResolver
		wantErr  bool
	}{
		{name: "resolver_error", resolver: timingResolver{err: errors.New("resolver unavailable")}, wantErr: true},
		{name: "nil_keyset", resolver: timingResolver{}, wantErr: true},
		{name: "empty_keyset", resolver: timingResolver{keys: &josev4.JSONWebKeySet{}}, wantErr: true},
		{name: "real_verify", resolver: timingResolver{keys: keys}},
	}
	for _, tc := range cases {
		before := burns
		_, gotErr := resolveAndVerify(context.Background(), tc.resolver, "client-1", jws)
		if (gotErr != nil) != tc.wantErr {
			t.Fatalf("%s: err=%v, wantErr=%v", tc.name, gotErr, tc.wantErr)
		}
		wantBurns := 0
		if tc.wantErr {
			wantBurns = 1
		}
		if got := burns - before; got != wantBurns {
			t.Errorf("%s: burn callback count=%d, want %d", tc.name, got, wantBurns)
		}
	}
	if burns != 3 {
		t.Fatalf("total burn callback count=%d, want 3", burns)
	}
}
