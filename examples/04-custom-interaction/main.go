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
// This example swaps to a thin custom driver that delegates to
// JSONDriver while demonstrating how an embedder consumes the
// orchestrator-stamped fields on [interaction.Prompt]. The wrapper
// logs the OP-resolved locale and copies it into a Content-Language
// response header so HTTP middleware (CDN cache keys, audit logs,
// observability) can branch on the rendered language without
// re-running the locale resolver. Embedders with custom requirements
// (mobile app deep-links, headless CLI flow, …) implement
// [interaction.Driver] themselves; the seam is intentionally narrow
// (Render + ParseSubmission) so a fresh implementation stays
// auditable.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/04-custom-interaction
//
// PRODUCTION CAVEATS:
//   - Keys: this example uses an ephemeral signing key from devkeys.MustEphemeral; production deployments MUST supply a persistent KMS-backed signing key via op.WithKeyset.
//   - Store: the in-memory store loses all state on restart; use op/storeadapter/sql or composite for production.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Driver choice: does not relax orchestrator CSRF / state-ref guarantees — those run before Render / ParseSubmission and protect every Driver equally.
//   - Custom Driver: the custom interaction.Driver here demonstrates the seam; production embedders should harden CSRF, rate limit submissions, and validate user input against XSS.
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

// localeAwareDriver wraps [interaction.JSONDriver] to demonstrate the
// embedder pattern for consuming the orchestrator-stamped fields on
// [interaction.Prompt]. The orchestrator runs the §L.2 locale chain
// (PreferredLocaleStore → ui_locales → __Host-oidc_locale cookie →
// Accept-Language → default) and writes the resolved tag into
// prompt.Locale before invoking Render; this driver copies the value
// into the Content-Language response header so observability stacks
// downstream see it without re-running the chain.
type localeAwareDriver struct{}

func (localeAwareDriver) Render(w http.ResponseWriter, r *http.Request, prompt interaction.Prompt) error {
	if prompt.Locale != "" {
		w.Header().Set("Content-Language", prompt.Locale)
	}
	return interaction.JSONDriver{}.Render(w, r, prompt)
}

func (localeAwareDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	return interaction.JSONDriver{}.ParseSubmission(r)
}

func main() {
	keys := devkeys.MustEphemeral("interaction-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithInteractionDriver(localeAwareDriver{}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("custom-interaction example listening on :8080 (locale-aware JSONDriver)")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
