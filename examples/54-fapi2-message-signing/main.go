//go:build example

// Example 54-fapi2-message-signing demonstrates the FAPI 2.0 Message Signing
// profile end-to-end: everything Baseline requires (PAR, private_key_jwt,
// PKCE, DPoP-bound tokens), plus a signed authorization request (JAR,
// RFC 9101), a signed authorization response (JARM) and a server-supplied
// DPoP nonce. The paired Relying Party from examples/internal/rpkit
// (FAPI2Options.MessageSigning) performs every step, so the wire form of each
// signed message is readable in one place.
//
// Run with the example build tag:
//
//	(cd examples/54-fapi2-message-signing && GOWORK=off go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with WithProfile(FAPI2MessageSigning). The profile
//     requires a signed request object on every /par and /authorize request,
//     answers /authorize with a JARM response, and, as a library choice,
//     refuses to start without WithDPoPNonceSource. One client is registered
//     as PrivateKeyJWTClient with an inline JWKS the RP signs against.
//   - :9090 — the Message Signing RP. It exposes /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  2. Click "Log in via the OP (PAR)" — the RP signs a request object,
//     POSTs it to /par with a private_key_jwt assertion, and redirects the
//     browser to /auth?request_uri=...&client_id=...
//  3. Sign in as username "demo" / password "demo" and approve the consent
//     prompt.
//  4. The OP redirects to http://127.0.0.1:9090/callback?response=<JWT>.
//     The RP verifies that JWT against the OP's JWKS, then redeems the code
//     at /token: the first request carries no DPoP nonce and draws a
//     use_dpop_nonce challenge, the retry echoes the nonce.
//  5. The browser ends up at http://127.0.0.1:9090/me. The JSON body
//     includes the verified ID Token claims plus "_token_type": "DPoP",
//     "_access_token_cnf_jkt", "_authorization_response": "JARM" and
//     "_dpop_nonce_retried": true. The RP stderr shows
//     "rpkit: DPoP nonce challenge received, retrying".
//
// Cross-check the OP's advertised surface:
//
//	curl http://127.0.0.1:8080/.well-known/openid-configuration | jq
//
// You should see require_signed_request_object true, response_modes_supported
// listing the *.jwt modes, and dpop_signing_alg_values_supported populated.
//
// Wiring details:
//
//   - WithProfile(FAPI2MessageSigning) enables PAR, JAR, JARM and
//     sender-constrained tokens by itself; WithFeature(feature.DPoP)
//     restates the sender-constraint default so the choice is visible.
//   - NewInMemoryDPoPNonceSource rotates one value every minute and accepts
//     the current and previous one. Its context ends the rotation goroutine;
//     main passes context.Background so it runs for the life of the process.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - DPoPNonceSource: process-local in-memory ring (forgets all values on restart) — unsuitable for horizontally scaled OPs because two replicas issue from independent rings and reject each other's nonces. A multi-replica deployment uses op/storeadapter/redis Store.DPoPNonceSource, which keeps the nonces in a Redis every replica shares.
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
	clientID    = "fapi2-ms-example-client"
	clientKID   = "fapi2-ms-example-client-1"
	redirectURI = rpBase + "/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"

	nonceRotation = 60 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("fapi2-ms-1")

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

	nonces, err := op.NewInMemoryDPoPNonceSource(context.Background(), nonceRotation)
	if err != nil {
		return err
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		}),
		// Message Signing builds on Baseline: private_key_jwt only, PAR,
		// PKCE and sender-constrained tokens, plus a mandatory signed
		// request object and a JARM-wrapped authorization response.
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
		// The profile refuses to start without a nonce source: every
		// DPoP proof at /token and /par must carry a server-issued nonce.
		op.WithDPoPNonceSource(nonces),
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
		log.Printf("OP listening on %s (issuer %s, FAPI 2.0 Message Signing, DPoP nonce rotation %s)",
			opAddr, issuer, nonceRotation)
		opErrCh <- serve.Listen(opAddr, opMux, provider)
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
		MessageSigning:   true,
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
