//go:build example

// Example 16 demonstrates the [op.WithInteractionDriver] seam. The library
// ships two reference Drivers in [op/interaction]:
//
//   - [interaction.HTMLDriver] (default, used when WithInteractionDriver
//     is not called): server-side renders the prompts as a tiny HTML
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
//	(cd examples/16-custom-interaction && GOWORK=off go run -tags example .)
//
// One demo account is seeded with a password (demo / demo-password) and
// one public client is registered, so the OP produces a real prompt for
// the driver to render.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:8080/.well-known/openid-configuration
//     to confirm the OP is serving.
//
//  2. Drive an authorization request and follow the hand-off to the
//     interaction endpoint. The response is the JSONDriver envelope,
//     and its Content-Language header carries the locale the
//     orchestrator resolved from the Accept-Language request header.
//
//  3. Use this file as the reference for the custom Driver shape:
//     Render receives the resolved interaction.Prompt.Locale and
//     ParseSubmission delegates to the JSON contract unchanged.
//
// Step 2 as one command:
//
//	curl -sS -D- -o /dev/null -L -c /tmp/oidc16.jar -b /tmp/oidc16.jar \
//	  -H 'Accept-Language: ja' \
//	  'http://localhost:8080/oidc/auth?client_id=demo-spa&response_type=code&redirect_uri=http://localhost:5173/callback&scope=openid&state=s&nonce=n&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256'
//
// PRODUCTION CAVEATS:
//   - Keys: this example uses an ephemeral signing key from devkeys.MustEphemeral; production deployments MUST supply a persistent KMS-backed signing key via op.WithKeyset.
//   - Store: the in-memory store loses all state on restart; use op/storeadapter/sql or composite for production.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Login flow: one [op.PrimaryPassword] step over the demo user seed. Production embedders compose their own primary factor and MFA rules; the Driver seam is unaffected by that choice.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - Driver choice: does not relax orchestrator CSRF / state-ref guarantees — those run before Render / ParseSubmission and protect every Driver equally.
//   - Custom Driver: the custom interaction.Driver here demonstrates the seam; production embedders should harden CSRF, rate limit submissions, and validate user input against XSS.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// localeAwareDriver wraps [interaction.JSONDriver] to demonstrate the
// embedder pattern for consuming the orchestrator-stamped fields on
// [interaction.Prompt]. The orchestrator runs the locale priority
// chain (PreferredLocaleStore → ui_locales → __Host-oidc_locale cookie →
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

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr

	demoClientID    = "demo-spa"
	demoRedirectURI = "http://localhost:5173/callback"

	demoUsername = "demo"
	demoPassword = "demo-password"
	demoSubject  = "demo-user"
)

func main() {
	keys := devkeys.MustEphemeral("interaction-1")

	memStore := inmem.New()
	if err := seedUser(memStore); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// Admit "localhost" as a redirect_uri host alongside 127.0.0.1.
		op.WithAllowLocalhostLoopback(),
		// A Driver renders prompts, and prompts only exist because some
		// step in the login flow asked for input. One password step is
		// the smallest flow that gives this Driver something to render.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
		op.WithInteractionDriver(localeAwareDriver{}),
		op.WithStaticClients(op.PublicClient{
			ID:           demoClientID,
			RedirectURIs: []string{demoRedirectURI},
			Scopes:       []string{"openid", "profile"},
		}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Printf("custom-interaction example listening on %s (issuer %s, locale-aware JSONDriver)", opAddr, issuer)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedUser plants the demo subject the login flow authenticates. The
// prompt the Driver renders is the password step's, so the user record
// is what makes the walkthrough reach Render at all.
func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}
