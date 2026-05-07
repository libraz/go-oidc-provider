//go:build example

// Example 40 demonstrates the first-party-client auto-consent path.
// OIDC Core 1.0 §3.1.2.4 expects an explicit consent prompt for
// third-party clients so the end-user authorises the release of their
// claims; that prompt is typically disabled for the embedder's own
// apps (the "first-party" relationship). Listing client_ids in
// [op.WithFirstPartyClients] flags the embedder's intent: when an
// authenticated user reaches /authorize with one of the listed
// clients, the OP creates the grant on the user's behalf and mints
// the authorization code without rendering a consent screen.
// [op.AuditConsentGrantedFirstParty] fires on every skip so the
// audit trail captures the auto-grant.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/40-first-party-skip-consent
//
// The "first-party-app" client is registered as a public client and
// listed in [op.WithFirstPartyClients]; it round-trips through
// /authorize without a consent prompt. The "third-party-integration"
// client is registered the same way but is NOT on the skip list —
// it still drives the standard consent prompt.
//
// Validation contract: non-static clients (RFC 7591 dynamic
// registrations) cannot be added; FAPI 2.0 profiles refuse the
// combination outright. Both checks fire at op.New, not at first
// request, so misconfigurations surface during boot.
//
// RP override: a request that carries prompt=consent always renders
// the consent screen, even for first-party clients. The skip is the
// OP's posture, not the RP's; an RP that needs explicit re-confirmation
// (e.g. step-up consent) keeps full control through the standard prompt.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:8080/.well-known/openid-configuration
//     to confirm the OP is serving.
//  2. Drive /authorize with client_id=first-party-app and watch
//     the audit log: only AuditLoginSuccess (the password step) fires;
//     no consent prompt is rendered. AuditConsentGrantedFirstParty
//     fires alongside the code mint.
//  3. Drive /authorize with client_id=third-party-integration: the
//     consent screen renders as usual.
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
