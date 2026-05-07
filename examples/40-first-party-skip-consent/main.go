//go:build example

// Example 40 demonstrates the first-party-client consent-skip path.
// OIDC Core 1.0 §3.1.2.4 expects an explicit consent prompt for
// third-party clients so the end-user authorises the release of their
// claims; that prompt is typically disabled for the embedder's own
// apps (the "first-party" relationship). Listing client_ids in
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
// Manual verification:
//
//  1. Open http://127.0.0.1:8080/.well-known/openid-configuration
//     to confirm the OP is serving.
//  2. Read the WithFirstPartyClients call below: only
//     "first-party-app" is on the consent-skip list.
//  3. In a full browser flow, that client proceeds from login
//     directly to the redirect URI; "third-party-integration" still
//     receives the normal consent prompt.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - First-party skip: a deliberate trust extension — production embedders MUST gate it on a registry of clients owned by the embedder's organisation (typically a column on the client table consulted at boot).
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("first-party-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
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
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
