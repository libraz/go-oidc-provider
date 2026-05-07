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
//	go run -tags example ./examples/11-custom-consent-ui
//
// Manual verification:
//
//  1. Open http://127.0.0.1:8080/.well-known/openid-configuration
//     to confirm the OP boots with the custom consent template.
//  2. The important contract is the template shape: it must post
//     state_ref, csrf_token, and the field named by
//     ApprovedScopesField back to SubmitAction.
//  3. To exercise the template in a browser round-trip, copy this
//     WithConsentUI wiring into 01-minimal or 02-bundle and approve
//     the requested scopes from the custom screen.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Consent template: inline and minimal; a production embedder uses a real template directory with parsed-once startup, CSP-friendly nonces, and external CSS.
//   - Submission shape: this template approves every requested scope in one click. A real consent UI renders one checkbox per scope and lets the user submit a subset; client-side JS would join the checked names into the hidden `approved_scopes` field before submit.
package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
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

func main() {
	tmpl, err := template.New("consent").Parse(consentTemplateSrc)
	if err != nil {
		log.Fatalf("parse consent template: %v", err)
	}

	keys := devkeys.MustEphemeral("consent-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("custom-consent-ui example listening on :8080")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
