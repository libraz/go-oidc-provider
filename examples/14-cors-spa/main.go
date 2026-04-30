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
//	go run -tags example ./examples/14-cors-spa
//
// Then verify the preflight from the SPA origin:
//
//	curl -sS -i -X OPTIONS http://localhost:8080/oidc/token \
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
// browser.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("cors-spa-1")

	// The SPA client's redirect_uri origin (https://spa.example.com)
	// is added to the CORS allowlist automatically. The admin console
	// at https://admin.example.com has no redirect_uri here (it talks
	// to /userinfo only), so its origin must be added explicitly via
	// WithCORSOrigins.
	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
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

	log.Println("cors-spa example listening on :8080")
	log.Println("CORS allowlist: https://spa.example.com (from redirect_uri) + https://admin.example.com (explicit)")
	log.Println("try: curl -sS -i -X OPTIONS http://localhost:8080/oidc/token \\")
	log.Println("         -H 'Origin: https://spa.example.com' \\")
	log.Println("         -H 'Access-Control-Request-Method: POST'")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
