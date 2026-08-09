//go:build example

// Example 12 demonstrates [op.WithChooserUI]: an HTML template the
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
//	(cd examples/12-custom-chooser-ui && GOWORK=off go run -tags example .)
//
// Two demo accounts are seeded with passwords so the chooser has
// something to enumerate: alice / alice-password and bob /
// bob-password.
//
// Browser walkthrough:
//
//  1. GET /oidc/auth?... → sign in as alice (first account in this
//     browser).
//  2. GET /oidc/auth?...&prompt=login → sign in as bob (joins
//     alice's chooser group).
//  3. GET /oidc/auth?...&prompt=select_account → the chooser
//     template enumerates both accounts and lets the user pick.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Login flow: one [op.PrimaryPassword] step over the demo user seed. Production embedders compose their own primary factor and MFA rules; the chooser wiring is unaffected by that choice.
//   - User seed: the demo usernames / passwords are hard-coded; production embedders enrol users through their own management plane.
//   - Template: inlined and minimal; a production embedder uses a real template directory with parsed-once startup, CSP-friendly nonces, and external CSS.
package main

import (
	"context"
	"html/template"
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

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr
)

func main() {
	tmpl, err := template.New("chooser").Parse(chooserTemplateSrc)
	if err != nil {
		log.Fatalf("parse chooser template: %v", err)
	}

	keys := devkeys.MustEphemeral("chooser-ui-1")

	memStore := inmem.New()
	if err := seedAccounts(memStore); err != nil {
		log.Fatalf("seed demo accounts: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// Admit "localhost" as a redirect_uri host alongside 127.0.0.1.
		op.WithAllowLocalhostLoopback(),
		// A primary factor is what turns a browser into an account the
		// chooser can list; without it /authorize has no interaction to
		// hand the user to.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
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

	log.Printf("custom-chooser-ui example listening on %s (issuer %s, HTML chooser via WithChooserUI)", opAddr, issuer)
	log.Println("flow: sign in as alice → /authorize?prompt=login as bob → /authorize?prompt=select_account")
	log.Println("demo users: alice/alice-password, bob/bob-password")
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedAccounts materialises the two demo subjects the chooser
// enumerates. In a real deployment the user records come from the
// embedder's identity backend. The chooser screen reads Subject +
// AuthTime off the live SessionStore at render time, so the User
// records here only matter when the orchestrator projects claims into
// the id_token / userinfo response — the password credential is what
// lets a browser reach a session in the first place.
func seedAccounts(st *inmem.Store) error {
	for _, acct := range []struct {
		subject  string
		name     string
		password string
	}{
		{"alice", "Alice Example", "alice-password"},
		{"bob", "Bob Example", "bob-password"},
	} {
		hash, err := op.HashPassword(acct.password)
		if err != nil {
			return err
		}
		st.PutUserWithPassword(context.Background(), &store.User{
			Subject: acct.subject,
			Claims: map[string]any{
				"sub":   acct.subject,
				"name":  acct.name,
				"email": acct.subject + "@example.com",
			},
		}, acct.subject, hash)
	}
	return nil
}
