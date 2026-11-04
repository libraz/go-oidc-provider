//go:build example

// Example 37 demonstrates [op.HTMLUI] with a Login [op.PageTemplate]: one HTML template the
// library renders for every sign-in prompt (password, TOTP, email OTP,
// recovery code, factor choice, captcha, custom steps) instead of the
// built-in screens. The library passes a canonical
// [interaction.LoginTemplateData] context (Type, Data, Fields,
// FactorField, Error, StateRef, CSRFToken, SubmitMethod, SubmitAction)
// to the template; the embedder controls branding, layout and copy.
//
// Consent, the account chooser and passkey prompts are not part of
// this template; consent keeps the built-in screen here, and
// [op.HTMLUI]'s Consent page customises it (example 11).
//
// Run with the example build tag:
//
//	(cd examples/37-custom-login-ui && GOWORK=off go run -tags example .)
//
// One demo account is seeded with a password: demo / demo-password.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:8080/.well-known/openid-configuration
//     to confirm the OP is serving.
//  2. Open http://127.0.0.1:8080/oidc/auth?client_id=demo-rp&response_type=code&redirect_uri=http://localhost:8081/callback&scope=openid&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
//     The branded sign-in page renders with the stylesheet applied.
//  3. Sign in as demo / demo-password. The browser moves on to the
//     built-in consent screen.
//
// The contract the template has to honour is its submission shape: it
// must post state_ref and csrf_token back to SubmitAction together with
// the fields it was handed, and guard Data with {{with .Data}} because
// prompts from custom steps carry no typed payload.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Login flow: one [op.PrimaryPassword] step over the demo user seed. Production embedders compose their own primary factor and MFA rules; the same template then renders each of those prompts, branching on .Type.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - Login template: inline and minimal; a production embedder uses a real template directory with parsed-once startup. The stylesheet is served by this example so the page's Content-Security-Policy can name "style-src 'self'"; in production it is whatever origin the asset pipeline publishes to.
//   - Shared policy: the Content-Security-Policy applies to every login prompt, so relaxing script-src for a captcha widget relaxes the password page too; name hosts only, never 'unsafe-inline'.
package main

import (
	"context"
	"html/template"
	"io"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// loginStylesheetPath is served by this example on the same origin as
// the OP, which is what lets the login page's Content-Security-Policy
// name "style-src 'self'" instead of allowing inline styles.
const loginStylesheetPath = "/assets/login.css"

const loginStylesheet = `body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; color: #1b1b1f; }
h1 { font-size: 1.4rem; }
label { display: block; margin-top: 1rem; }
input { width: 100%; padding: .5rem; box-sizing: border-box; }
button { margin-top: 1.5rem; padding: .6rem 1.4rem; font-size: 1rem; }
.error { color: #a4262c; }
`

// The template renders whatever fields the prompt carries, so the same
// markup serves the password step and any step added later. Data is nil
// for custom steps, so typed access sits inside {{with .Data}} after a
// .Type check; the factor-choice prompt has no fields, only Data.Options.
const loginTemplateSrc = `<!doctype html>
<html lang="{{.Locale}}">
<head><meta charset="utf-8"><title>Sign in</title>
<link rel="stylesheet" href="` + loginStylesheetPath + `"></head>
<body>
  <h1>Sign in to Example Corp</h1>
  {{with .Error}}<p class="error" role="alert">{{if .Message}}{{.Message}}{{else}}{{.Code}}{{end}}</p>{{end}}
  <form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">
    <input type="hidden" name="state_ref" value="{{.StateRef}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    {{range .Fields}}<label>{{.LabelText}}
      <input name="{{.Name}}" type="{{inputType .Kind}}" autocomplete="off">
    </label>
    {{end}}
    {{if eq .Type "auth.choose_factor"}}{{with .Data}}{{range .Options}}<label>
      <input type="radio" name="{{$.FactorField}}" value="{{.Kind}}"> {{.LabelText}}
    </label>
    {{end}}{{end}}{{end}}
    <button type="submit">Continue</button>
  </form>
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
	tmpl, err := template.New("login").Funcs(template.FuncMap{"inputType": inputType}).Parse(loginTemplateSrc)
	if err != nil {
		log.Fatalf("parse login template: %v", err)
	}

	keys := devkeys.MustEphemeral("login-ui-1")

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
		op.WithAllowLocalhostRedirectURIs(),
		op.WithProfile(profile.OAuth21),
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: memStore.UserPasswords()}}),
		// Without a policy the login page inherits the one the built-in
		// driver uses, which forbids every subresource: the stylesheet
		// below would be fetched, blocked by the browser, and dropped
		// with no server-side signal. The policy covers every login
		// prompt, so keep it to the origins the template loads from.
		op.WithUI(op.HTMLUI{Login: op.PageTemplate{
			Template:              tmpl,
			ContentSecurityPolicy: "default-src 'none'; style-src 'self'; img-src 'self' data:",
		}}),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-rp",
				RedirectURIs: []string{"http://localhost:8081/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(loginStylesheetPath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		if _, err := io.WriteString(w, loginStylesheet); err != nil {
			log.Printf("write stylesheet: %v", err)
		}
	}))
	mux.Handle("/", provider)

	log.Printf("custom-login-ui example listening on %s (issuer %s)", opAddr, issuer)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux, provider); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedUser materialises the demo subject the walkthrough signs in as.
// In a real deployment the user record comes from the embedder's
// identity backend.
func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name": "Demo User",
		},
	}, demoUsername, hash)
	return nil
}

// inputType maps a field's kind to the HTML input type; the template
// cannot compare against the interaction.Field* constants itself.
func inputType(k interaction.FieldKind) string {
	switch k {
	case interaction.FieldPassword:
		return "password"
	case interaction.FieldEmail:
		return "email"
	case interaction.FieldHidden:
		return "hidden"
	default:
		return "text"
	}
}
