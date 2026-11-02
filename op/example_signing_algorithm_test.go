package op_test

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// ExampleWithSigningAlgorithm builds an OP that issues RS256 for relying
// parties that verify only the OpenID Connect Core mandatory algorithm.
// The active key is a 2048-bit RSA key; the ES256 key the OP issued with
// before stays behind it with a NotAfter, so tokens it signed keep
// verifying until that deadline while every new token is RS256.
func ExampleWithSigningAlgorithm() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	previous := exampleKeyset()[0]
	previous.NotAfter = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	provider, err := op.New(
		op.WithIssuer("https://idp.example.com"),
		op.WithStore(inmem.New()),
		op.WithSigningAlgorithm(op.AlgRS256),
		op.WithKeyset(op.Keyset{
			{KeyID: "rs256-1", Signer: rsaKey},
			previous,
		}),
		op.WithCookieKeys(exampleCookieKey()),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = provider
}
