//go:build example

// Example fapi2 demonstrates the FAPI 2.0 Baseline wiring shape for
// an OP. A single [op.WithProfile] call activates the profile and
// auto-enables the three features the spec requires (PAR / JAR /
// DPoP); the example pre-registers a confidential client whose
// authentication method is private_key_jwt with inline JWKs. The
// example exists to make the constraint set the library imposes
// auditable as docs-as-code: running the example and curling the
// discovery document is the fastest way to confirm the OP advertises
// the FAPI 2.0 surface.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/fapi2
//
// Then inspect:
//
//	curl http://localhost:8080/.well-known/openid-configuration | jq
//
// You should see:
//
//   - "token_endpoint_auth_methods_supported" limited to private_key_jwt
//     (FAPI 2.0 §3.1.3 allow-list intersected with the OP's enabled
//     methods; the example does not enable mTLS so tls_client_auth /
//     self_signed_tls_client_auth are filtered out).
//   - "dpop_signing_alg_values_supported": ["ES256", "EdDSA", "PS256"]
//     (DPoP feature on, RFC 9449 §5.1).
//   - "request_parameter_supported": true and the request-object alg
//     advertisement (JAR feature on).
//   - "pushed_authorization_request_endpoint" present (PAR feature on).
//
// And POSTing to /oidc/token without a DPoP proof returns 400
// invalid_request, even with a perfectly-formed private_key_jwt
// assertion. FAPI 2.0 Baseline §5.3 requires sender-constrained
// access tokens via DPoP **or** mTLS; this example enables only DPoP,
// so DPoP is the OP-side choice that satisfies the rule. An embedder
// who prefers mTLS leaves the DPoP wiring out and configures
// [op.WithMTLSCertHeader] / [op.WithTrustedProxies] instead.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Private-key emission to stdout: replace with an out-of-band delivery channel (operator paste, secret manager) before adapting to production.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	demoIssuer      = "https://op.example.com"
	demoClientID    = "fapi2-example-client"
	demoListen      = ":8080"
	demoRedirectURI = "https://rp.example.com/callback"
	demoClientKID   = "fapi2-example-client-1"
)

func main() {
	keys := devkeys.MustEphemeral("fapi2-example-1")
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate client private key: %v", err)
	}

	clientJWKs, err := publicJWKSetJSON(&clientPriv.PublicKey)
	if err != nil {
		log.Fatalf("encode client JWKs: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(demoIssuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		// WithProfile(FAPI2Baseline) auto-enables PAR / JAR / DPoP per
		// the spec's required feature set; embedders do NOT need to
		// call WithFeature(...) for them. A profile is one option.
		op.WithProfile(profile.FAPI2Baseline),
		// PrivateKeyJWTClient is the typed seam for FAPI 2.0 clients:
		// it pins TokenEndpointAuthMethod to private_key_jwt and
		// embeds the inline JWKS the OP uses to verify assertions.
		// Bypassing the seam (a raw store.Client + store.RegisterClient)
		// works but loses the compile-time guarantees the type carries.
		op.WithStaticClients(op.PrivateKeyJWTClient{
			ID:            demoClientID,
			JWKS:          clientJWKs,
			RedirectURIs:  []string{demoRedirectURI},
			Scopes:        []string{"openid", "profile", "email"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
		}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	clientPrivPEM, err := encodeECPrivateKeyPEM(clientPriv)
	if err != nil {
		log.Fatalf("encode client private key: %v", err)
	}

	log.Println("FAPI 2.0 Baseline example OP listening on", demoListen)
	log.Println("issuer:", demoIssuer)
	log.Println("client_id:", demoClientID)
	log.Println("client kid:", demoClientKID)
	log.Println("client private key (PKCS#8 PEM, sign private_key_jwt assertions with this):")
	log.Print("\n" + string(clientPrivPEM))
	log.Println("try: curl http://localhost" + demoListen + "/.well-known/openid-configuration | jq")

	if err := serve.Listen(demoListen, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
