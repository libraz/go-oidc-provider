//go:build example

// Example 15 demonstrates the [op.WithOpenIDScopeOptional] seam, which
// lets the same OP serve plain OAuth 2.0 authorization_code flows
// alongside (or instead of) OIDC. Without the option the OP rejects
// any /authorize request whose scope omits "openid", per OIDC Core
// 1.0 §3.1.2.1. With the option set, the OP accepts both shapes:
//
//   - scope=openid profile email — full OIDC: id_token + userinfo +
//     refresh_token (when refresh is enabled).
//   - scope=api:read              — plain OAuth 2.0: access_token only,
//     no id_token. /userinfo still works against the access token but
//     emits no claims a non-OIDC client did not request.
//
// The choice is per-request: the option is a relaxation of the
// validator, not a global switch. A client whose registered scopes
// include "openid" can still request it; a client whose registered
// scopes omit "openid" stays in OAuth-only mode.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/15-oauth2-only
//
// Drive the OAuth-only path end-to-end:
//
//	# 1) start the example, then visit
//	open 'http://localhost:8080/oidc/auth?client_id=oauth-cli&response_type=code&redirect_uri=http://localhost:5173/cb&scope=api:read&state=xyz&code_challenge=E9Melhoa2OoLrgRBe5dh8nlEpV-vH4qlHWAHfsmrCzs&code_challenge_method=S256'
//
//	# 2) after the consent screen, exchange the returned code:
//	curl -u oauth-cli:oauth2-only-demo-secret-rotate-me \
//	     -d 'grant_type=authorization_code&code=<CODE>&redirect_uri=http://localhost:5173/cb&code_verifier=<VERIFIER>' \
//	     http://localhost:8080/oidc/token | jq
//
// The /token response carries access_token but NOT id_token because
// the granted scope (api:read) does not include "openid".
//
// # When this option is appropriate
//
// OAuth 2.0-only mode is for deployments that intentionally serve
// non-OIDC clients — typically internal API consumers or third-party
// integrations that only need an access token. If every client of
// the OP is an OIDC RP, leave the option absent so requests missing
// "openid" surface a clear configuration error.
//
// The option is incompatible with the FAPI 2.0 profile (which
// presupposes OIDC semantics); op.New rejects the combination at
// construction time.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Client secrets: hardcoded for the demo; rotate confidential secrets through the embedder's secret manager.
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
	keys := devkeys.MustEphemeral("oauth2-only-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// The single option that flips the OIDC default. With it
		// absent, the second client below would fail at /authorize
		// with invalid_scope (missing openid).
		op.WithOpenIDScopeOptional(),
		// Register a resource scope so the OAuth-only client can
		// request something meaningful. Public scopes appear in
		// discovery; the consent UI surfaces the description.
		op.WithScope(op.PublicScope("api:read", "Read your API resources")),
		op.WithStaticClients(
			// OIDC client: scope includes "openid", so /token still
			// emits an id_token. Same OP, same option set.
			op.ConfidentialClient{
				ID:           "oidc-rp",
				Secret:       "oauth2-only-demo-secret-rotate-me",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{"http://localhost:5173/cb"},
				GrantTypes:   []string{"authorization_code", "refresh_token"},
				Scopes:       []string{"openid", "profile", "email"},
			},
			// OAuth-only client: registered scopes do not include
			// "openid". Authorization requests carrying scope=api:read
			// pass; the /token response omits id_token.
			op.ConfidentialClient{
				ID:           "oauth-cli",
				Secret:       "oauth2-only-demo-secret-rotate-me",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{"http://localhost:5173/cb"},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"api:read"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("oauth2-only example listening on :8080 (issuer https://op.example.com)")
	log.Println("OIDC client:   oidc-rp   (scope=openid profile email → id_token issued)")
	log.Println("OAuth client:  oauth-cli (scope=api:read              → no id_token)")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
