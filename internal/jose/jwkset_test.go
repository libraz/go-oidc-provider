package jose_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestParseJWKSet_RejectsPrivateKey pins that a JWKS advertised for
// signature verification is admitted only when it carries public keys.
// crypto.PublicKey is an alias for `any`, so the naive type assertion the
// parser used never failed and would have stored a client-registered
// private key as a verification key. The public-key control proves the
// tighter gate does not regress the conforming path.
func TestParseJWKSet_RejectsPrivateKey(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pubSet, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal public set: %v", err)
	}
	if _, err := jose.ParseJWKSet(pubSet); err != nil {
		t.Fatalf("public JWKS rejected: %v", err)
	}

	privSet, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: priv, KeyID: "k1", Algorithm: "RS256", Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal private set: %v", err)
	}
	if _, err := jose.ParseJWKSet(privSet); !errors.Is(err, jose.ErrUnsupportedKeyShape) {
		t.Fatalf("private JWKS: err=%v want ErrUnsupportedKeyShape", err)
	}
}
