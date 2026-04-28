//go:build example

// Example 12 demonstrates the public/internal scope split documented
// in ADR 0004. Scopes flagged Public appear in the discovery
// document's `scopes_supported` and on the consent prompt; scopes
// flagged internal are accepted at /authorize but never advertised
// and never rendered for user approval.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/12-scopes-public-private
//
// Then inspect:
//
//	curl http://localhost:8080/.well-known/openid-configuration | jq .scopes_supported
//
// The "openid", "profile", and "billing.read" scopes appear; the
// "internal:audit" scope is registered but absent from the
// discovery document. RPs that ask for "internal:audit" still
// receive it because the OP knows about it — the visibility flag
// only governs surface advertisement and consent rendering.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, a public HTTP
// listener, and an in-memory store. Production embedders read keys
// from a vault / KMS and persist scope catalogues alongside their
// other configuration.
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

	// Public scopes appear in discovery and on the consent prompt.
	// Internal scopes are accepted at /authorize but never advertised.
	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "scopes-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithScope(op.PublicScope("openid", "Sign you in")),
		op.WithScope(op.PublicScope("profile", "Access your basic profile")),
		op.WithScope(op.PublicScope("billing.read", "Read your billing data")),
		op.WithScope(op.InternalScope("internal:audit")),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("scopes example listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
