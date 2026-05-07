//go:build example

// Example 24 demonstrates [op.WithChooserUI]: an HTML template the
// library renders for prompt=select_account instead of letting the
// JSON driver hand the chooser envelope to a SPA. The library
// passes a canonical [interaction.ChooserTemplateData] context
// (Accounts, AddAccountURL, StateRef, CSRFToken, SessionIDField,
// SubmitMethod, SubmitAction) to the template; the embedder
// controls every other aspect of the render. The flow contrasts
// with example 13, which drives the same chooser via the JSON
// driver for SPA front-ends.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/24-custom-chooser-ui
//
// Browser walkthrough:
//
//  1. GET /oidc/auth?... → log in as alice (first account in this
//     browser).
//  2. GET /oidc/auth?...&prompt=login → log in as bob (joins
//     alice's chooser group).
//  3. GET /oidc/auth?...&prompt=select_account → the chooser
//     template enumerates both accounts and lets the user pick.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Authenticator: testkit's [SubjectAuthenticator] trusts whatever subject the SPA submits — substitute a password / passkey / federated authenticator (the chooser wiring is unaffected).
//   - Template: inlined and minimal; a production embedder uses a real template directory with parsed-once startup, CSP-friendly nonces, and external CSS.
package main

import (
	"context"
	"html/template"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const chooserTemplateSrc = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Choose an account</title></head>
<body>
  <h1>Choose an account</h1>
  {{if .Accounts}}
  <ul>
    {{range .Accounts}}
    <li>
      <form method="{{$.SubmitMethod}}" action="{{$.SubmitAction}}">
        <input type="hidden" name="state_ref" value="{{$.StateRef}}">
        <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
        <input type="hidden" name="{{$.SessionIDField}}" value="{{.SessionID}}">
        <button type="submit">Continue as {{if .DisplayName}}{{.DisplayName}}{{else}}{{.Subject}}{{end}}</button>
      </form>
    </li>
    {{end}}
  </ul>
  {{else}}
  <p>No active accounts in this browser.</p>
  {{end}}
  <p><a href="{{.AddAccountURL}}">Sign in to a different account</a></p>
</body>
</html>
`

func main() {
	tmpl, err := template.New("chooser").Parse(chooserTemplateSrc)
	if err != nil {
		log.Fatalf("parse chooser template: %v", err)
	}

	keys := devkeys.MustEphemeral("chooser-ui-1")

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
		op.WithCookieKeys(keys.CookieKey),
		// HTMLDriver is the orchestrator default; setting it explicitly
		// makes this example self-documenting (compare with example 13,
		// which opts into JSONDriver for a SPA front-end).
		op.WithInteractionDriver(interaction.HTMLDriver{}),
		op.WithChooserUI(op.ChooserUI{Template: tmpl}),
		op.WithStaticClients(
			op.ConfidentialClient{
				ID:           "demo-rp",
				Secret:       "custom-chooser-demo-secret-rotate-me",
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

	log.Println("custom-chooser-ui example listening on :8080 (HTML chooser via WithChooserUI)")
	log.Println("flow: log in as alice → /authorize?prompt=login as bob → /authorize?prompt=select_account")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
