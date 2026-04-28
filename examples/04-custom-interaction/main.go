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
// PRODUCTION CAVEATS: this example uses ephemeral keys and an
// in-memory store. The choice of Driver does not relax any of the
// orchestrator's CSRF / state-ref guarantees — those run before
// Render / ParseSubmission and protect every Driver equally.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
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
		op.WithKeyset(op.Keyset{{KeyID: "interaction-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithInteraction(interaction.JSONDriver{}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("custom-interaction example listening on :8080 (JSONDriver)")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
