//go:build example

// Example 50 demonstrates the FAPI helper functions [op.FAPITLSConfig]
// and [op.LoadPublicJWKS]. Together they replace the per-deployment
// boilerplate every FAPI 2.0 OP would otherwise rewrite by hand:
// TLS 1.2 with the FAPI 1.0 RW cipher allowlist, and a JWKS loader
// that strips the private "d" parameter so the OP only ever holds
// public material.
//
// Run with the example build tag:
//
//	(cd examples/50-fapi-tls-jwks && GOWORK=off go run -tags example .)
//
// The example expects a JWKS file at ./client.jwks.json (or the path in
// FAPI_JWKS; any
// well-formed RFC 7517 set will do — the loader strips "d" if
// present). The OP listens on TLS 1.2 only because Go's TLS 1.3
// cipher list is not configurable from crypto/tls — pinning to
// TLS 1.2 is what lets [op.FAPITLSConfig] pass through the FAPI 1.0
// Read-Write cipher allowlist. CHACHA20_POLY1305 is excluded from
// the allowlist for the same reason. This is a Go-runtime constraint,
// not a FAPI rejection of TLS 1.3 — operators wanting TLS 1.3 build
// their own *tls.Config and forfeit the cipher pinning.
//
// Manual verification:
//
//  1. Place a JWKS at ./client.jwks.json and start the example. If
//     the set contains private "d" parameters, LoadPublicJWKS strips
//     them before the bytes would be registered on a client.
//  2. Set FAPI_ISSUER to the public HTTPS origin the listener answers
//     on, and FAPI_CERT / FAPI_KEY to a certificate and key for it.
//     All three are required; set FAPI_ADDR when :8443 is unsuitable.
//  3. Run `openssl s_client -connect 127.0.0.1:8443 -tls1_2` and
//     inspect the negotiated TLS 1.2 cipher.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: TLS 1.2 with the operator-supplied FAPI_CERT / FAPI_KEY pair; a self-signed pair is fine for a local run, production replaces it with a chain the RPs trust.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("fapi-1")

	const (
		clientID    = "fapi-tls-jwks-client"
		defaultAddr = ":8443"
	)
	jwksPath := envOr("FAPI_JWKS", "client.jwks.json")
	pub, err := op.LoadPublicJWKS(jwksPath)
	if err != nil {
		// In a real deployment the JWKS comes from the operator's
		// configuration; the example exits early to keep the
		// failure mode actionable.
		log.Fatalf("LoadPublicJWKS(%s): %v (place a JWKS at that path)", jwksPath, err)
	}
	if len(pub) == 0 {
		log.Fatalf("LoadPublicJWKS returned empty bytes")
	}
	// The issuer has no usable default. Every endpoint URL in the
	// discovery document is built from it, so a placeholder host would
	// publish a document whose contents resolve nowhere, and an RP
	// comparing the issuer against the address it fetched from would
	// reject the document outright. The operator supplies the public
	// HTTPS origin their TLS listener actually answers on — the same
	// reason FAPI_CERT and FAPI_KEY are required below.
	issuer := os.Getenv("FAPI_ISSUER")
	if issuer == "" {
		log.Fatal("FAPI_ISSUER is required; it must name the public HTTPS origin this listener serves")
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// The client below authenticates with private_key_jwt and asks
		// only for client_credentials, so the default
		// {authorization_code, refresh_token} pair is replaced by the one
		// grant this OP serves. Nothing here authenticates an end user.
		op.WithGrants(grant.ClientCredentials),
		// FAPI 2.0 Baseline mandates a sender-constrained access token,
		// satisfied here by DPoP. WithProfile auto-enables PAR / JAR
		// (RequiredFeatures) and picks DPoP as the default sender-binding
		// mechanism (RequiredAnyOf {DPoP, MTLS} → first member). An
		// embedder who instead terminates mTLS at the OP opts in via
		// op.WithFeature(feature.MTLS) and the DPoP default steps aside.
		op.WithProfile(profile.FAPI2Baseline),
		// Register the public JWKS as the verifier key material for the
		// client that authenticates at /token with private_key_jwt. The
		// loader above strips private JWK members before this value reaches
		// the OP, so the signing key stays exclusively with the RP.
		op.WithStaticClients(op.PrivateKeyJWTClient{
			ID:         clientID,
			JWKS:       pub,
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{"api:read"},
		}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	srv := &http.Server{
		Addr:              envOr("FAPI_ADDR", defaultAddr),
		Handler:           provider,
		TLSConfig:         op.FAPITLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// In a real run the operator supplies a cert/key matching the
	// allowlisted RSA-keyed AEAD ciphers FAPITLSConfig advertises.
	cert := os.Getenv("FAPI_CERT")
	key := os.Getenv("FAPI_KEY")
	if cert == "" || key == "" {
		log.Fatal("FAPI_CERT and FAPI_KEY are required; TLS must be exercised by this example")
	}
	log.Printf("FAPI TLS example listening on %s (issuer %s; TLS 1.2 only, RSA-keyed AEAD allowlist)", srv.Addr, issuer)
	// TLS listener; serve.Listen does not handle TLS termination.
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
