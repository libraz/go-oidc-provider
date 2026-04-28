//go:build example

// Example 40 demonstrates the first-party-client consent-skip path.
// The OAuth 2.1 / OIDC consent screen is required for third-party
// clients but typically disabled for the embedder's own apps (the
// "first-party" relationship). Listing client_ids in
// [op.WithFirstPartyClients] tells the orchestrator to bypass the
// consent prompt for those IDs and emit the authorization code
// immediately after the login chain succeeds.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/40-first-party-skip-consent
//
// The "first-party-app" client is registered as a public client and
// listed in WithFirstPartyClients, so /authorize redirects back to
// the SPA without rendering a consent prompt. A third-party client
// (not listed here) would still see the consent screen.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, a public HTTP
// listener, and an in-memory store. The first-party-skip behaviour
// is a deliberate trust extension; a production embedder MUST gate
// it on a registry of clients owned by the embedder's organisation
// (typically a column on the client table consulted at boot).
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
		op.WithKeyset(op.Keyset{{KeyID: "first-party-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "first-party-app",
				RedirectURIs: []string{"https://app.example.com/callback"},
				Scopes:       []string{"openid", "profile", "email"},
			},
			op.PublicClient{
				ID:           "third-party-integration",
				RedirectURIs: []string{"https://partner.example.com/callback"},
				Scopes:       []string{"openid"},
			},
		),
		// Only the first-party app skips consent. Third-party
		// clients still see the prompt.
		op.WithFirstPartyClients("first-party-app"),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("first-party example listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
