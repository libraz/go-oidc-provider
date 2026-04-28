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
// present). The OP listens on TLS 1.2 only; CHACHA20_POLY1305 and
// TLS 1.3 are rejected by design to match the OFCS
// DisallowInsecureCipher condition.
//
// PRODUCTION CAVEATS: this example uses an ephemeral signing key and
// a self-signed TLS cert generated at startup. Production FAPI 2.0
// deployments terminate TLS at the OP itself or behind a trusted
// proxy whose Forwarded handling is configured via
// [op.WithTrustedProxies]; the cert chain comes from a CA the RP's
// truststore knows.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
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
		op.WithKeyset(op.Keyset{{KeyID: "fapi-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
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
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
