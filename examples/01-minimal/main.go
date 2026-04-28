//go:build example

// Example minimal shows the smallest embedder boilerplate that
// constructs an OpenID Connect Provider, mounts it on an
// [http.ServeMux], and starts a listener.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/minimal
//
// The example uses ephemeral signing and cookie keys generated at
// startup so it can run without configuration. A production embedder
// reads the key material from a vault / KMS, persists records in a
// real backend, and registers at least one [op.Authenticator].
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "minimal-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	// The Provider is a plain http.Handler; embedders mount it under
	// any prefix their router supports. The default mount path
	// (/oidc) is used here.
	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("minimal OP listening on :8080 (issuer https://op.example.com)")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
