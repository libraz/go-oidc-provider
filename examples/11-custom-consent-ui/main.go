//go:build example

// Example 11 demonstrates [op.WithConsentUI]: an HTML template the
// library renders at consent time instead of the built-in screen.
// The library passes a canonical context (Client, Scopes, CSRFToken)
// to the template; the embedder controls every other aspect of the
// render — branding, layout, copy, i18n.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/11-custom-consent-ui
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Consent template: inline and minimal; a production embedder uses a real template directory with parsed-once startup, CSP-friendly nonces, and external CSS.
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

const consentTemplateSrc = `
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorize {{.Client.Name}}</title></head>
<body>
  <h1>Authorize {{.Client.Name}}?</h1>
  <p>{{.Client.Name}} is requesting access to:</p>
  <ul>
    {{range .Scopes}}<li>{{.Title}}</li>{{end}}
  </ul>
  <form method="POST" action="">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <button type="submit" name="decision" value="approve">Approve</button>
    <button type="submit" name="decision" value="deny">Deny</button>
  </form>
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
