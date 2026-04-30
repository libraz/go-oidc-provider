//go:build example

// Example 17 demonstrates the OIDC Core 1.0 §5.5 "claims" request
// parameter. The OP advertises claims_parameter_supported in
// discovery, parses the JSON object on /authorize and /par, and
// projects requested claims onto the issued id_token / userinfo
// response when the user store returns matching values.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/17-claims-request
//
// Inspect the discovery advertisement:
//
//	curl -s http://localhost:8080/.well-known/openid-configuration \
//	  | jq '{claims_parameter_supported, claims_supported}'
//
// Drive an authorize request with a claims payload that asks for
// email as essential and locale as voluntary:
//
//	CLAIMS='{"id_token":{"email":{"essential":true}},"userinfo":{"locale":null}}'
//	# RFC 7636 §4.1 mandates a verifier of 43..128 chars; §4.2 derives
//	# the challenge as base64url(SHA256(verifier)) without padding.
//	VERIFIER='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
//	CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | basenc --base64url -w0 | tr -d '=')
//	open "http://localhost:8080/oidc/auth?\
//	client_id=demo&response_type=code&\
//	redirect_uri=http://localhost:5173/callback&\
//	scope=openid&state=s&\
//	code_challenge=${CHALLENGE}&\
//	code_challenge_method=S256&\
//	claims=$(printf %s \"$CLAIMS\" | jq -sRr @uri)"
//
// Behaviour summary:
//
//   - The library default is claims_parameter_supported = true.
//     [op.WithClaimsParameterSupported] flips the discovery bit and
//     the parser; the parser still rejects malformed JSON either way
//     so the wire shape stays consistent across the FAPI 2.0 path.
//   - Essential claims that the [store.UserStore] does not return are
//     omitted from the response, not surfaced as an error.
//   - Voluntary requests (JSON null on the wire) layer onto the
//     existing scope-driven release; the parser does not narrow the
//     claim set, only widens it.
//   - [op.WithClaimsSupported] populates the discovery document's
//     claims_supported field so RPs can introspect the closed claim
//     universe before issuing a §5.5 request. The library leaves the
//     field omitted by default because what an embedder actually
//     surfaces depends on the user store; the example publishes the
//     standard set the inmem catalogue serves.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User catalogue: hard-coded for the demo; resolve claims through the embedder's identity database via [store.UserStore.FindBySubject].
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
	keys := devkeys.MustEphemeral("claims-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		// The toggle is wired explicitly here for the demo. The
		// library default is "supported", so omitting this option
		// produces the same wire shape — pass false to make the
		// authorize parser silently drop the parameter and flip the
		// discovery bit off.
		op.WithClaimsParameterSupported(true),
		// Publish the closed claim universe in discovery. RPs that
		// inspect claims_supported can decide whether a §5.5 request
		// is worth issuing without trial-and-error against /userinfo.
		// The list mirrors the OIDC standard claims this example's
		// user store serves; an embedder backed by a richer profile
		// schema enumerates additional names here.
		op.WithClaimsSupported(
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "given_name", "family_name", "preferred_username",
			"email", "email_verified",
			"locale",
		),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo",
				RedirectURIs: []string{"http://localhost:5173/callback"},
				Scopes:       []string{"openid", "profile", "email"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("claims-request example listening on :8080")
	log.Println("verify discovery: curl -s http://localhost:8080/.well-known/openid-configuration | jq .claims_parameter_supported")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
