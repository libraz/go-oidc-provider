//go:build example

// Example 51 demonstrates the RFC 9449 §8 / §9 server-supplied DPoP
// nonce flow. The /token and /userinfo handlers reject any DPoP
// proof whose "nonce" claim is missing or stale, returning the
// "use_dpop_nonce" challenge along with a fresh value in the
// DPoP-Nonce response header. The client retries with the new nonce.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/51-dpop-nonce
//
// Trigger the challenge from a no-nonce DPoP proof (the RP would
// normally produce this on the first call, observe the challenge,
// and retry):
//
//	# Build a DPoP proof JWT without a nonce claim — see
//	# https://datatracker.ietf.org/doc/html/rfc9449#section-4.2 for
//	# the unsigned shape. The OP returns a 400 / use_dpop_nonce error
//	# and stamps the next acceptable nonce into DPoP-Nonce.
//	curl -sS -i -X POST http://localhost:8080/oidc/token \
//	  -H 'DPoP: <proof-without-nonce>' \
//	  -d 'grant_type=authorization_code&code=...' | head -20
//
// Wiring details:
//
//   - WithFeature(feature.DPoP) enables the DPoP verifier on /token
//     and /userinfo. Without it the nonce source is a no-op.
//   - WithDPoPNonceSource installs the issuance / validation halves.
//     This example uses op.NewInMemoryDPoPNonceSource — the project's
//     reference implementation — which rotates a 128-bit value every
//     60 seconds and accepts the current plus the immediately
//     preceding nonce so an in-flight RP retry that straddles a
//     rotation is not rejected.
//   - The constructor takes a context: when the supplied context is
//     canceled the rotation goroutine exits cleanly. main here passes
//     context.Background so rotation runs for the lifetime of the
//     process; an embedder with a shutdown signal would supply a
//     cancellable one.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, a
// process-local nonce ring (forgets all values on restart), and a
// public HTTP listener. NewInMemoryDPoPNonceSource is unsuitable for
// horizontally scaled OPs — two replicas issue from independent rings
// and reject each other's nonces, generating a thrash of
// use_dpop_nonce challenges. Production multi-replica deployments
// supply a DPoPNonceSource backed by a shared cache (Redis /
// memcached); see the v1.x Wave L3 outlook.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("dpop-nonce-1")

	nonces, err := op.NewInMemoryDPoPNonceSource(context.Background(), 60*time.Second)
	if err != nil {
		log.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(nonces),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"http://localhost:5173/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("dpop-nonce example listening on :8080")
	log.Println("DPoP feature enabled; nonces rotate every 60s")
	log.Println("a DPoP proof without a 'nonce' claim now triggers RFC 9449 use_dpop_nonce")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
