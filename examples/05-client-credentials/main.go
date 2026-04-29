//go:build example

// Example 05 demonstrates the OAuth 2.0 client_credentials grant
// (RFC 6749 §4.4) — machine-to-machine token issuance with no end
// user, no /authorize round-trip, no consent prompt. The OP signs the
// access token directly from the client's confidential credential.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/05-client-credentials
//
// Then exchange the credential for an access token:
//
//	curl -u backend-service:rotate-me-via-secret-manager \
//	     -d 'grant_type=client_credentials&scope=api:read' \
//	     http://localhost:8080/oidc/token | jq
//
// The "openid" scope is absent on purpose: client_credentials has no
// authenticated user, so there is no id_token and no userinfo. The
// scope catalogue therefore registers a custom resource scope
// ("api:read") for the access-token claims to carry.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, an in-memory
// store, and a hardcoded client secret. Production embedders read
// keys from a vault / KMS, persist client records in a real backend,
// and rotate confidential secrets through their secret manager.
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("client-credentials-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		// The default grant set is {authorization_code, refresh_token};
		// adding ClientCredentials extends it. Embedders that ONLY
		// need machine-to-machine tokens can pass just the one grant.
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials),
		op.WithStaticClients(
			op.ConfidentialClient{
				ID:         "backend-service",
				Secret:     "rotate-me-via-secret-manager",
				AuthMethod: op.AuthClientSecretBasic,
				// client_credentials clients do not visit /authorize;
				// RedirectURIs may be empty. The grant set is overridden
				// to remove authorization_code (which the client cannot
				// use) and add client_credentials.
				GrantTypes: []string{"client_credentials"},
				Scopes:     []string{"api:read"},
			},
		),
		op.WithScope(op.PublicScope("api:read", "Read your API resources")),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("client-credentials example listening on :8080")
	log.Println("try: curl -u backend-service:rotate-me-via-secret-manager \\")
	log.Println("         -d 'grant_type=client_credentials&scope=api:read' \\")
	log.Println("         http://localhost:8080/oidc/token | jq")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
