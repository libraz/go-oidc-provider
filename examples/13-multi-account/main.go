//go:build example

// Example 13 demonstrates the multi-account chooser flow. The library
// ships a built-in [op.Interaction] for prompt=select_account that
// emits an [interaction.ChooserPromptData] envelope listing every
// account in the active chooser group; the SPA picks one and posts
// back the SessionID. The /authorize endpoint also routes a fresh
// prompt=login on top of an active session through
// [sessions.Manager.AddAccount], so signing in as a second account
// adds it to the chooser group rather than discarding the first.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/13-multi-account
//
// Browser walkthrough:
//
//  1. GET /oidc/auth?... → log in as alice (first account).
//     The OP issues a chooser group, sets the session cookie, and
//     redirects back to the RP with an authorization code.
//  2. GET /oidc/auth?...&prompt=login → log in as bob (second
//     account in the SAME browser).
//     ensureSession sees the active session for alice, sees the
//     subject mismatch, and routes to AddAccount instead of Issue —
//     bob joins alice's chooser group.
//  3. GET /oidc/auth?...&prompt=select_account → the chooser
//     interaction enumerates both accounts. Pick alice or bob; the
//     orchestrator binds the picked subject and rebinds the cookie
//     via [sessions.Manager.Switch] so the chooser group stays
//     intact.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Authenticator: testkit's [SubjectAuthenticator] trusts whatever subject the SPA submits — substitute a password / passkey / federated authenticator (the chooser wiring is unaffected).
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("chooser-1")

	memStore := inmem.New()
	// Two demo subjects; in a real deployment the user records come
	// from the embedder's identity backend. The chooser screen reads
	// Subject + AuthTime off the live SessionStore at render time, so
	// the User records here only matter when the orchestrator projects
	// claims into the id_token / userinfo response.
	memStore.PutUser(context.Background(), &store.User{
		Subject: "alice",
		Claims: map[string]any{
			"sub":   "alice",
			"name":  "Alice Example",
			"email": "alice@example.com",
		},
	})
	memStore.PutUser(context.Background(), &store.User{
		Subject: "bob",
		Claims: map[string]any{
			"sub":   "bob",
			"name":  "Bob Example",
			"email": "bob@example.com",
		},
	})

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		// JSONDriver renders prompts (chooser, consent, factor) as JSON
		// envelopes a SPA can consume directly. A server-rendered
		// embedder swaps to interaction.HTMLDriver and supplies a
		// chooser template via op.WithChooserUI; the orchestrator-side
		// flow is identical.
		op.WithInteraction(interaction.JSONDriver{}),
		op.WithStaticClients(
			op.ConfidentialClient{
				ID:           "demo-rp",
				Secret:       "chooser-demo-secret-rotate-me",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{"http://localhost:8081/callback"},
				Scopes:       []string{"openid", "profile", "email"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("multi-account example listening on :8080 (built-in chooser via JSONDriver)")
	log.Println("flow: log in as alice → /authorize?prompt=login as bob → /authorize?prompt=select_account")
	log.Println("the chooser response is a Prompt{Type: \"interaction.chooser\", Data: ChooserPromptData{Accounts: [...]}}")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
