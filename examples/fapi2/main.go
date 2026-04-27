//go:build example

// Example fapi2 demonstrates the FAPI 2.0 Baseline wiring shape for an
// OP. It enables the profile, the three required features
// (PAR / JAR / DPoP), and pre-registers a confidential client whose
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
//   - "dpop_signing_alg_values_supported": ["ES256", "EdDSA"] (DPoP
//     feature on, RFC 9449 §5.1).
//   - "request_parameter_supported": true and the request-object alg
//     advertisement (JAR feature on).
//   - "pushed_authorization_request_endpoint" present (PAR feature on).
//
// And POSTing to /oidc/token without a DPoP proof returns 400
// invalid_request, even with a perfectly-formed private_key_jwt
// assertion — that is the FAPI 2.0 §3.1.4 sender-constrained
// access-token rule the OP enforces unconditionally when the profile
// is active.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, a public HTTP
// listener, an in-memory store, and prints the client's private key
// to stdout. None of those are appropriate for production. The
// example exists to illustrate library wiring, not deployment
// topology. A production FAPI 2.0 OP terminates TLS at the OP
// itself or behind a trusted proxy whose XFF / Forwarded handling
// is configured via [op.WithTrustedProxies].
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
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
	opSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate OP signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate client private key: %v", err)
	}

	clientJWKs, err := publicJWKSetJSON(&clientPriv.PublicKey)
	if err != nil {
		log.Fatalf("encode client JWKs: %v", err)
	}
	st := inmem.New()
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      demoClientID,
		RedirectURIs:            []string{demoRedirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs:                    clientJWKs,
		Source:                  store.ClientSourceStatic,
	}); err != nil {
		log.Fatalf("register client: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(demoIssuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "fapi2-example-1", Signer: opSigningKey}}),
		op.WithCookieKey(cookieKey),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.DPoP),
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

	srv := &http.Server{
		Addr:              demoListen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// publicJWKSetJSON encodes pub as the inline JWK Set JSON the OIDC
// Dynamic Client Registration 1.0 §2 "jwks" field accepts. The set
// carries a single entry whose "kid" matches [demoClientKID] so the
// JAR / private_key_jwt verifiers can discriminate when a client
// rotates keys later.
func publicJWKSetJSON(pub *ecdsa.PublicKey) ([]byte, error) {
	type jwk struct {
		KTY string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Use string `json:"use"`
		KID string `json:"kid"`
		Alg string `json:"alg"`
	}
	type jwkSet struct {
		Keys []jwk `json:"keys"`
	}
	return json.Marshal(jwkSet{Keys: []jwk{{
		KTY: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		Use: "sig",
		KID: demoClientKID,
		Alg: "ES256",
	}}})
}

// encodeECPrivateKeyPEM marshals priv as a PKCS#8-shaped PEM block so
// the user can save it and feed it to a JWT signer of their choice.
// The example does not pin a specific JWT library; any ECDSA P-256
// signer reading PKCS#8 will produce assertions the OP accepts.
func encodeECPrivateKeyPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
