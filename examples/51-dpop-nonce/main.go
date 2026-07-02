//go:build example

// Example 51-dpop-nonce demonstrates the RFC 9449 §8 / §9 server-
// supplied DPoP nonce challenge end-to-end. The OP runs the FAPI 2.0
// Baseline profile (PAR + private_key_jwt + DPoP + PKCE) and adds
// [op.WithDPoPNonceSource], which gates every DPoP-bound request on a
// fresh server-issued nonce. The paired Relying Party from
// examples/internal/rpkit POSTs to /token without a nonce on the first
// try, observes the use_dpop_nonce challenge plus the DPoP-Nonce
// response header, and retries once with the nonce echoed inside the
// proof JWT.
//
// Run with the example build tag:
//
//	(cd examples/51-dpop-nonce && go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with WithProfile(FAPI2Baseline) and an
//     in-memory nonce source rotating every 60 seconds.
//   - :9090 — the FAPI 2.0 RP from examples/internal/rpkit.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  2. Click "Log in via the OP (PAR)" — the RP pushes the
//     authorization request and is redirected to /auth.
//  3. Sign in as username "demo" / password "demo" and approve.
//  4. Watch the RP stderr: the line
//     "rpkit: DPoP nonce challenge received, retrying"
//     confirms the OP rejected the nonce-less proof and the RP
//     retried with the echoed value. /me then renders the verified
//     ID Token claims with "_token_type":"DPoP" and the
//     RFC 7638 thumbprint under "_access_token_cnf_jkt".
//
// Trigger the challenge directly with curl (the RP path above runs
// the same handshake transparently):
//
//	curl -sS -i -X POST http://127.0.0.1:8080/oidc/token \
//	  -H 'DPoP: <proof-without-nonce>' \
//	  -d 'grant_type=authorization_code&code=...' | head -20
//
// The OP returns 400 use_dpop_nonce with the next acceptable nonce in
// the DPoP-Nonce response header.
//
// Wiring details:
//
//   - WithProfile(FAPI2Baseline) caps client-auth at private_key_jwt
//     and forces sender-constrained access tokens. The profile
//     requires the embedder to choose DPoP or mTLS for the binding;
//     this example picks DPoP via WithFeature. The baseline profile
//     does NOT mandate WithDPoPNonceSource (only the FAPI 2.0 Message
//     Signing profile does), so this example opts in explicitly to
//     surface the nonce loop.
//   - WithDPoPNonceSource installs the issuance / validation halves.
//     The constructor takes a context: when the supplied context is
//     canceled the rotation goroutine exits cleanly. main here passes
//     context.Background so rotation runs for the lifetime of the
//     process; an embedder with a shutdown signal would supply a
//     cancellable one.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - DPoPNonceSource: process-local in-memory ring (forgets all values on restart) — unsuitable for horizontally scaled OPs because two replicas issue from independent rings and reject each other's nonces. Production multi-replica deployments supply a source backed by a shared cache (Redis / memcached); a built-in distributed implementation is on the v1.x roadmap.
//   - rpkit: the RP code in examples/internal/rpkit is a demo wrapper, not a library. Production FAPI 2.0 RPs use a tested client framework rather than copy-pasting the proof.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
	clientID    = "dpop-nonce-example-client"
	clientKID   = "dpop-nonce-example-client-1"
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
	keys := devkeys.MustEphemeral("dpop-nonce-1")

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

	nonces, err := op.NewInMemoryDPoPNonceSource(context.Background(), nonceRotation)
	if err != nil {
		return err
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
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
		log.Printf("OP listening on %s (issuer %s, FAPI 2.0 Baseline + DPoP nonce, rotation %s)",
			opAddr, issuer, nonceRotation)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitForIssuer(ctx, issuer); err != nil {
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
	log.Printf("first /token POST will trigger use_dpop_nonce; rpkit retries with the echoed nonce")

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
