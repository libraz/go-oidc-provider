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
// enumeration in-tree).
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - IAT bearer secret: returned by IssueInitialAccessToken exactly once (see op.InitialAccessTokenIssued.Value godoc) with no recovery path. Production code MUST hand it to the operator's secret manager or to the registering RP through an out-of-band channel (invitation email, RP intake form) and MUST NOT log, audit-emit, or persist it anywhere besides the credential store. The example's startup log of iat.Value is DEMO-ONLY — remove it before adapting to production.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("dcr-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		op.WithDynamicRegistration(op.RegistrationOption{
			// Open=false (the default) requires every POST /register
			// to carry an Initial Access Token. Open=true is for
			// invitation-less onboarding and writes a WARN log per
			// registration; production deployments leave it false.
			Open: false,

			// IAT lifecycle. The library defaults are 24 h TTL,
			// single-use; this example shortens the TTL and
			// authorises five uses so an operator can drive the
			// curl probes below without re-issuing on every call.
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
	log.Printf("Initial Access Token (1 h TTL, 5 uses) [DEMO-ONLY, do not log in production]: %s", iat.Value)
	log.Printf("IAT id: %s  expires: %s", iat.ID, iat.ExpiresAt.Format(time.RFC3339))
	log.Println("try: curl -sX POST http://localhost:8080/oidc/register \\")
	log.Println("         -H \"Authorization: Bearer $IAT\" \\")
	log.Println("         -H 'Content-Type: application/json' \\")
	log.Println("         -d '{\"client_name\":\"demo-rp\",\"redirect_uris\":[\"http://localhost:5173/callback\"]}'")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
