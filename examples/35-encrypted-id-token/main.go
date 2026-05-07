//go:build example

// Example 35-encrypted-id-token demonstrates an OP that issues
// encrypted ID Tokens (JWE-of-signed-JWT, RFC 7519 §5.2 nested) to a
// client registered with `id_token_encrypted_response_alg=RSA-OAEP-256`
// and `id_token_encrypted_response_enc=A256GCM`. The OP advertises an
// RSA `use=enc` key on its JWKS endpoint; the example RP advertises
// its own `use=enc` JWKS inline on the client metadata, drives an
// authorization_code + PKCE flow, and decrypts the five-part JWE wrap
// with the RP's private key before verifying the inner JWS against
// the OP's signing JWKS. The example exists to make the v0.9.1
// outbound id_token JWE wire shape readable end-to-end.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/35-encrypted-id-token
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with WithEncryptionKeyset registering one RSA
//     2048-bit `use=enc` key. The OP's JWKS endpoint publishes both
//     the ES256 signing key and the RSA encryption key.
//   - :9090 — a minimal inline RP. It exposes /, /login, /callback,
//     /me. The RP holds the private half of an RSA 2048-bit
//     `use=enc` key whose public half is registered with the OP via
//     the client metadata `JWKs` field.
//
// The codebase is split by role across this directory:
//
//   - main.go  — entrypoint, package godoc, the high-level run()
//     sequence (generate keys → build OP → listen → wait → build RP
//     → listen). Owns the discovery readiness probe.
//   - op.go    — OP-side wiring: buildProvider with
//     [op.WithEncryptionKeyset], the seedUser helper, and the
//     rsaPublicJWKSetJSON marshaller used to register the RP's
//     public encryption key on the client metadata.
//   - rp.go    — Relying Party: HTTP handlers (/, /login, /callback,
//     /me), discovery + JWKS fetch at startup, the
//     authorization_code + PKCE round-trip, and the response state
//     machine. The RP is intentionally minimal — see the file's role
//     comment for why rpkit cannot be reused here.
//   - jose.go  — the JWE-of-JWS decrypt-then-verify dance the example
//     exists to demonstrate. Lives in its own file so the wire shape
//     stays one Go function long and the rp.go handlers stay
//     transport-only.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  2. Click "Log in via the OP" — the browser is redirected to the
//     OP's /authorize, then to the password prompt.
//  3. Sign in as username "demo" / password "demo".
//  4. Approve the consent prompt.
//  5. The browser ends up at http://127.0.0.1:9090/me. The JSON body
//     includes "_id_token_jwe_parts": 5 (the compact JWE shape) plus
//     the decrypted ID Token claims (iss, sub, aud, iat, exp, nonce,
//     name, email).
//
// Cross-check the OP's advertised encryption key (the discovery
// document's "jwks_uri" points at /jwks by default):
//
//	curl "$(curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq -r .jwks_uri)" \
//	  | jq '.keys[] | select(.use == "enc")'
//
// You should see one RSA JWK with use=enc, alg=RSA-OAEP-256, and the
// kid the OP registered ("op-enc-1").
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production. The OP
//     signing key, the OP encryption key, and the RP encryption key
//     are all generated fresh on every restart.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress. JWE
//     protects the id_token claims at rest, but the rest of the wire
//     (cookies, /token POST, /authorize redirects) still benefits
//     from TLS.
//   - User seed: the demo username / password are hard-coded;
//     production embedders enrol users through their own management
//     plane.
//   - RP: the inline RP in this main.go is a demo, not a library.
//     Production RPs that consume encrypted ID tokens use a tested
//     client framework that handles JWKS rotation, key caching, and
//     the JWE-over-JWS verification dance correctly.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/serve"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "encrypted-id-token-example-client"
	clientKID   = "rp-enc-1"
	opEncKID    = "op-enc-1"
	redirectURI = rpBase + "/callback"
	// clientSecret is unique to this example so the cross-example
	// duplicate-secret guard stays green; it is not a security claim.
	clientSecret = "encrypted-id-token-demo-shhh"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Generate the OP's encryption keypair. The private half stays in
	// process; the public half lands in JWKS as use=enc and is the key
	// the OP would use to decrypt inbound JWE (e.g. encrypted request
	// objects). It is unrelated to the outbound id_token JWE — that
	// wraps to the RP's key, registered below.
	opEncPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate OP encryption key: %w", err)
	}

	// Generate the RP's encryption keypair. The OP wraps every
	// id_token issued to this client to the public half via JWKs on
	// the client metadata; the RP decrypts with the private half.
	rpEncPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RP encryption key: %w", err)
	}

	provider, err := buildProvider(opEncPriv, &rpEncPriv.PublicKey)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, encrypted ID tokens via RSA-OAEP-256 + A256GCM)",
			opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitForIssuer(ctx, issuer); err != nil {
		return err
	}

	rp, err := newRP(rpOptions{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"openid", "profile", "email"},
		EncPrivate:   rpEncPriv,
	})
	if err != nil {
		return err
	}

	rpMux := http.NewServeMux()
	rpMux.Handle("/", rp.Handler())

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

// waitForIssuer polls iss + "/.well-known/openid-configuration" until
// it returns 200 or ctx is cancelled. The OP boots in the same process
// as the RP, so this readiness gate runs before the RP fetches
// discovery + JWKS.
func waitForIssuer(ctx context.Context, iss string) error {
	url := iss + "/.well-known/openid-configuration"
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("waitForIssuer: timeout polling " + url)
		case <-tick.C:
		}
	}
}
