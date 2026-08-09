//go:build example

// Example 14 demonstrates how to expose the OP's token, userinfo,
// and JWKS endpoints to a Single Page Application served from a
// different origin. The CORS allowlist is the union of two sources:
//
//  1. Every redirect_uri origin the OP knows about (from registered
//     clients) — added automatically.
//  2. Extra origins passed to op.WithCORSOrigins — used for admin
//     SPAs or management consoles whose origin does not appear in
//     a redirect_uri.
//
// Run with the example build tag:
//
//	(cd examples/14-cors-spa && GOWORK=off go run -tags example .)
//
// Then verify the preflight from the SPA origin:
//
//	curl -sS -i -X OPTIONS http://127.0.0.1:8080/oidc/token \
//	  -H 'Origin: https://spa.example.com' \
//	  -H 'Access-Control-Request-Method: POST' \
//	  -H 'Access-Control-Request-Headers: Authorization,Content-Type' \
//	  | grep -i '^Access-Control'
//
// The response carries Access-Control-Allow-Origin and
// Access-Control-Allow-Headers that include Authorization and
// Content-Type, and a 204 status. A request from any other origin
// is silently dropped from CORS headers (no allowlist match), so the
// browser blocks the call before it reaches the OP.
//
// SPAs use grant_type=authorization_code with PKCE; client_secret is
// not used. The single registered SPA client below has AuthMethod
// AuthNone — confidential credentials are not transmitted from the
// browser. The OP seeds one password user (demo / demo-password) so
// that code flow has a way to authenticate somebody; the allowlist is
// what this example is about, but an OP that cannot serve the grant
// its SPA client is registered for would be demonstrating CORS on a
// dead endpoint.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Login flow: one [op.PrimaryPassword] step over the demo user seed. Production embedders compose their own primary factor and MFA rules; the CORS allowlist is unaffected by that choice.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr

	demoUsername = "demo"
	demoPassword = "demo-password"
	demoSubject  = "demo-user"
)

func main() {
	keys := devkeys.MustEphemeral("cors-spa-1")

	memStore := inmem.New()
	if err := seedUser(memStore); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	// The SPA client's redirect_uri origin (https://spa.example.com)
	// is added to the CORS allowlist automatically. The admin console
	// at https://admin.example.com has no redirect_uri here (it talks
	// to /userinfo only), so its origin must be added explicitly via
	// WithCORSOrigins.
	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// The SPA runs authorization_code + PKCE, which starts with a
		// login. One password step is the smallest flow that can serve
		// it; the CORS wiring below is independent of the choice.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
		op.WithCORSOrigins("https://admin.example.com"),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "spa",
				RedirectURIs: []string{"https://spa.example.com/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Printf("cors-spa example listening on %s (issuer %s)", opAddr, issuer)
	log.Println("CORS allowlist: https://spa.example.com (from redirect_uri) + https://admin.example.com (explicit)")
	log.Printf("try: curl -sS -i -X OPTIONS %s/oidc/token \\", issuer)
	log.Println("         -H 'Origin: https://spa.example.com' \\")
	log.Println("         -H 'Access-Control-Request-Method: POST'")
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedUser materialises the demo subject the SPA's authorization_code
// flow signs in as. In a real deployment the user record comes from the
// embedder's identity backend.
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
