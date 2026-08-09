//go:build example

// Example 11 demonstrates [op.WithConsentUI]: an HTML template the
// library renders at consent time instead of the built-in screen.
// The library passes a canonical [interaction.ConsentTemplateData]
// context (Client, Scopes, StateRef, CSRFToken, ApprovedScopesField,
// SubmitMethod, SubmitAction) to the template; the embedder controls
// every other aspect of the render — branding, layout, copy, i18n.
//
// Run with the example build tag:
//
//	(cd examples/11-custom-consent-ui && GOWORK=off go run -tags example .)
//
// One demo account is seeded with a password so a browser can reach
// the consent screen: demo / demo-password.
//
// Browser walkthrough:
//
//  1. GET /oidc/auth?client_id=demo-rp&... → sign in as demo.
//  2. The custom consent template renders in place of the built-in
//     screen, listing the scopes the request asked for.
//  3. Approve — the browser is redirected back to the client's
//     redirect_uri with an authorization code.
//
// The contract the template has to honour is its submission shape: it
// must post state_ref, csrf_token, and the field named by
// ApprovedScopesField back to SubmitAction.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Login flow: one [op.PrimaryPassword] step over the demo user seed. Production embedders compose their own primary factor and MFA rules; the consent wiring is unaffected by that choice.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - Consent template: inline and minimal; a production embedder uses a real template directory with parsed-once startup, CSP-friendly nonces, and external CSS.
//   - Submission shape: this template approves every requested scope in one click. A real consent UI renders one checkbox per scope and lets the user submit a subset; client-side JS would join the checked names into the hidden `approved_scopes` field before submit.
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
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const consentTemplateSrc = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorize {{.Client.Name}}</title></head>
<body>
  <h1>{{if .Client.Name}}{{.Client.Name}}{{else}}{{.Client.ClientID}}{{end}} requests access</h1>
  {{if .Client.PolicyURI}}<p><a href="{{.Client.PolicyURI}}" target="_blank" rel="noopener">Privacy policy</a>{{if .Client.TosURI}} · <a href="{{.Client.TosURI}}" target="_blank" rel="noopener">Terms of service</a>{{end}}</p>{{end}}
  <p>The application is requesting the following scopes:</p>
  <ul>
    {{range .Scopes}}<li><strong>{{.Name}}</strong>{{if .Description}} — {{.Description}}{{end}}{{if .Required}} <em>(required)</em>{{end}}</li>{{end}}
  </ul>
  <form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">
    <input type="hidden" name="state_ref" value="{{.StateRef}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="hidden" name="{{.ApprovedScopesField}}" value="{{range $i, $s := .Scopes}}{{if $i}} {{end}}{{$s.Name}}{{end}}">
    <button type="submit">Approve</button>
  </form>
  <p><small>To deny: close this tab. The orchestrator surfaces the dropped interaction as <code>access_denied</code> back to the relying party once the cookie expires.</small></p>
</body>
</html>
`

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr

	demoUsername = "demo"
	demoPassword = "demo-password"
	demoSubject  = "demo-user"
)

func main() {
	tmpl, err := template.New("consent").Parse(consentTemplateSrc)
	if err != nil {
		log.Fatalf("parse consent template: %v", err)
	}

	keys := devkeys.MustEphemeral("consent-1")

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
		// Consent is the second half of an authorization request: the
		// user has to be signed in before the OP has anyone to ask. A
		// primary factor is what gets the browser that far.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
		op.WithStaticClients(
			op.ConfidentialClient{
				ID:           "demo-rp",
				Secret:       "custom-consent-demo-secret-rotate-me",
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

	log.Printf("custom-consent-ui example listening on %s (issuer %s)", opAddr, issuer)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedUser materialises the demo subject the walkthrough signs in as.
// In a real deployment the user record comes from the embedder's
// identity backend; the password credential is only here so a browser
// can reach the consent screen this example exists to render.
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
