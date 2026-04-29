//go:build example

// Example 41 demonstrates Dynamic Client Registration (RFC 7591 /
// RFC 7592 / OpenID Connect Dynamic Client Registration 1.0). The OP
// mounts /oidc/register, advertises registration_endpoint in
// discovery, and seeds an Initial Access Token (IAT) at startup so an
// RP can register itself programmatically.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/41-dynamic-registration
//
// The startup log prints the IAT bearer secret (it is returned by
// IssueInitialAccessToken exactly once — there is no way to recover
// it after the process restarts). Use it to register a client:
//
//	IAT='<paste from log>'
//	curl -sX POST http://localhost:8080/oidc/register \
//	  -H "Authorization: Bearer $IAT" \
//	  -H 'Content-Type: application/json' \
//	  -d '{
//	        "client_name":"demo-rp",
//	        "redirect_uris":["http://localhost:5173/callback"],
//	        "grant_types":["authorization_code","refresh_token"],
//	        "response_types":["code"]
//	      }' | jq
//
// The 201 response carries client_id, client_secret (when the chosen
// auth method needs one), the registration_access_token (RAT, RFC 7592
// §2.1), and registration_client_uri. Use the RAT to read / update /
// delete the registration:
//
//	RAT='<from response>'
//	CID='<from response>'
//	curl -s "http://localhost:8080/oidc/register/$CID" \
//	  -H "Authorization: Bearer $RAT" | jq
//	curl -X DELETE "http://localhost:8080/oidc/register/$CID" \
//	  -H "Authorization: Bearer $RAT" -i
//
// Deletion fires the OnClientDeleted hook below so the embedder can
// cascade access_token / refresh_token / session purges through its
// own data layer (the v1.0 store interfaces do not publish "by client"
// enumeration in-tree per docs/plans/002-product-design.md §A.6.2).
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, an in-memory
// store, and a public HTTP listener. Production embedders run this
// behind TLS, persist the IAT / RAT / client records in a real
// backend, and rotate the IAT on a short cadence.
//
// The startup log line that prints the IAT bearer secret is DEMO-ONLY.
// The library returns the secret exactly once (see
// op.InitialAccessTokenIssued.Value godoc) and there is no recovery
// path; production code MUST hand it to the operator's secret manager
// or to the registering RP through an out-of-band channel (invitation
// email, RP intake form) and MUST NOT log, audit-emit, or persist it
// anywhere besides the credential store. This example logs it so the
// reader can paste it into the curl call below; remove that log line
// before adapting any of this to production.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "dcr-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithDynamicRegistration(op.RegistrationOption{
			// Open=false (the default) requires every POST /register
			// to carry an Initial Access Token. Open=true is for
			// invitation-less onboarding and writes a WARN log per
			// registration; production deployments leave it false.
			Open: false,

			// IAT lifecycle. The defaults (24 h TTL, single-use)
			// match the production-grade baseline; tighten or loosen
			// for the embedder's flow.
			IATTTL:  1 * time.Hour,
			IATUses: 5,

			// OnClientDeleted fires after the client and its RAT have
			// been removed and before the 204 is written. Cascade any
			// per-client state the OP cannot see.
			OnClientDeleted: func(_ context.Context, clientID string) error {
				log.Printf("registration deleted: %s — embedder cascade goes here", clientID)
				return nil
			},
		}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	// Issue an IAT once at startup so the demo curl call has a
	// credential to present. The bearer secret is only returned now;
	// the line that logs iat.Value below is DEMO-ONLY (see the package
	// godoc) — production code routes Value to a secret manager and
	// never to a log.
	iat, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{
		Tag: "example-41-startup",
	})
	if err != nil {
		log.Fatalf("IssueInitialAccessToken: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("dcr example listening on :8080")
	log.Printf("Initial Access Token (single-use, 1 h TTL) [DEMO-ONLY, do not log in production]: %s", iat.Value)
	log.Printf("IAT id: %s  expires: %s", iat.ID, iat.ExpiresAt.Format(time.RFC3339))
	log.Println("try: curl -sX POST http://localhost:8080/oidc/register \\")
	log.Println("         -H \"Authorization: Bearer $IAT\" \\")
	log.Println("         -H 'Content-Type: application/json' \\")
	log.Println("         -d '{\"client_name\":\"demo-rp\",\"redirect_uris\":[\"http://localhost:5173/callback\"]}'")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
