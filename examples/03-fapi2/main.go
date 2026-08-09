//go:build example

// Example 03-fapi2 demonstrates a complete FAPI 2.0 Baseline round-
// trip: an OP with the FAPI 2.0 profile activated and an in-process
// Relying Party that drives PAR + private_key_jwt + PKCE and
// presents a DPoP-bound access token. The example exists to make
// the FAPI 2.0 wire form readable end-to-end as docs-as-code:
// operators see in one screen what the OP advertises (discovery doc)
// and what an RP must send (rpkit/fapi2.go).
//
// Run with the example build tag:
//
//	(cd examples/03-fapi2 && GOWORK=off go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with WithProfile(FAPI2Baseline) plus
//     WithFeature(DPoP) for the sender-constraint binding (the
//     profile mandates DPoP or mTLS), and one client registered as
//     PrivateKeyJWTClient with an inline JWKS the RP signs against.
//   - :9090 — the FAPI 2.0 RP from examples/internal/rpkit. It
//     exposes /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  2. Click "Log in via the OP (PAR)" — the RP POSTs the
//     authorization request to /par with a private_key_jwt
//     assertion, gets a request_uri, and redirects the browser to
//     /auth?request_uri=...&client_id=...
//  3. Sign in as username "demo" / password "demo".
//  4. Approve the consent prompt.
//  5. The browser ends up at http://127.0.0.1:9090/me. The JSON body
//     includes the verified ID Token claims plus
//     "_token_type": "DPoP" and "_access_token_cnf_jkt" — the JWK
//     thumbprint the OP recorded in the access token's "cnf" claim.
//
// Cross-check the OP's advertised surface:
//
//	curl http://127.0.0.1:8080/.well-known/openid-configuration | jq
//
// You should see token_endpoint_auth_methods_supported limited to
// private_key_jwt, dpop_signing_alg_values_supported populated, and
// pushed_authorization_request_endpoint present.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - rpkit: the RP code in examples/internal/rpkit is a demo wrapper, not a library. Production FAPI 2.0 RPs use a tested client framework rather than copy-pasting the proof.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "fapi2-example-client"
	clientKID   = "fapi2-example-client-1"
	redirectURI = rpBase + "/callback"

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
	keys := devkeys.MustEphemeral("fapi2-example-1")

	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	clientJWKs, err := rpkit.PublicJWKSetJSON(&clientPriv.PublicKey, clientKID)
	if err != nil {
		return err
	}

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return err
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		// WithProfile(FAPI2Baseline) caps client-auth methods at
		// private_key_jwt and forces sender-constrained access tokens.
		// The profile requires the embedder to choose between DPoP
		// (RFC 9449) and mTLS (RFC 8705) for the constraint binding,
		// surfaced via WithFeature so the choice is auditable in the
		// op.New call.
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithStaticClients(op.PrivateKeyJWTClient{
			ID:            clientID,
			JWKS:          clientJWKs,
			RedirectURIs:  []string{redirectURI},
			Scopes:        []string{"openid", "profile", "email"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
		}),
	)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, FAPI 2.0 Baseline)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(ctx, issuer); err != nil {
		return err
	}

	rp, err := rpkit.NewFAPI2(context.Background(), rpkit.FAPI2Options{
		Issuer:           issuer,
		ClientID:         clientID,
		RedirectURL:      redirectURI,
		Scopes:           []string{"openid", "profile", "email"},
		ClientPrivateKey: clientPriv,
		ClientKeyID:      clientKID,
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

func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}
