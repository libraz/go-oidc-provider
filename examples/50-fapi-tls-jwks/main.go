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
//	go run -tags example ./examples/50-fapi-tls-jwks
//
// The example expects a JWKS file at ./client.jwks.json (any
// well-formed RFC 7517 set will do — the loader strips "d" if
// present). The OP listens on TLS 1.2 only because Go's TLS 1.3
// cipher list is not configurable from crypto/tls — pinning to
// TLS 1.2 is what lets [op.FAPITLSConfig] pass through the FAPI 1.0
// Read-Write cipher allowlist. CHACHA20_POLY1305 is excluded from
// the allowlist for the same reason. This is a Go-runtime constraint,
// not a FAPI rejection of TLS 1.3 — operators wanting TLS 1.3 build
// their own *tls.Config and forfeit the cipher pinning.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: TLS 1.2 with self-signed cert generated at startup; production replaces the cert chain with a CA the RPs trust.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("fapi-1")

	const jwksPath = "client.jwks.json"
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
	_ = pub // would be passed to op.PrivateKeyJWTClient.JWKS

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// WithProfile(FAPI2Baseline) auto-enables PAR / JAR / DPoP.
		op.WithProfile(profile.FAPI2Baseline),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	srv := &http.Server{
		Addr:              ":8443",
		Handler:           provider,
		TLSConfig:         op.FAPITLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// In a real run the operator supplies a cert/key matching the
	// allowlisted RSA-keyed AEAD ciphers FAPITLSConfig advertises.
	cert := os.Getenv("FAPI_CERT")
	key := os.Getenv("FAPI_KEY")
	if cert == "" || key == "" {
		log.Println("FAPI_CERT / FAPI_KEY not set; skipping TLS listen — try `FAPI_CERT=cert.pem FAPI_KEY=key.pem go run -tags example ./examples/50-fapi-tls-jwks`")
		return
	}
	log.Println("FAPI TLS example listening on :8443 (TLS 1.2 only, RSA-keyed AEAD allowlist)")
	// TLS listener; serve.Listen does not handle TLS termination.
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
