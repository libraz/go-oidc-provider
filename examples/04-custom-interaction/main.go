//go:build example

// Example 04 demonstrates the [op.WithInteraction] seam. The library
// ships two reference Drivers in [op/interaction]:
//
//   - [interaction.HTMLDriver] (default, used when WithInteraction is
//     not called): server-side renders the prompts as a tiny HTML
//     form. The right choice for a server-rendered embedder.
//   - [interaction.JSONDriver]: emits the prompt as JSON and reads
//     submissions as JSON. The right choice when the embedder ships
//     a SPA that calls the OP's JSON state endpoints directly.
//
// This example swaps to JSONDriver so a SPA can call the OP without
// the HTML scaffolding. Embedders with custom requirements (mobile
// app deep-links, headless CLI flow, …) implement
// [interaction.Driver] themselves; the seam is intentionally narrow
// (Render + ParseSubmission) so a fresh implementation stays
// auditable.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/04-custom-interaction
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Driver choice: does not relax orchestrator CSRF / state-ref guarantees — those run before Render / ParseSubmission and protect every Driver equally.
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("interaction-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		op.WithInteraction(interaction.JSONDriver{}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("custom-interaction example listening on :8080 (JSONDriver)")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
