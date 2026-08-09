//go:build example

// Example 61-claims-request demonstrates the OIDC Core 1.0 §5.5
// "claims" request parameter end-to-end. The OP advertises
// claims_parameter_supported in discovery and projects the requested
// claim names onto the issued ID Token. The paired RP composes a
// claims object that asks for email as essential and locale as
// voluntary, so the embedder can see what survives the round-trip.
//
// Run with the example build tag:
//
//	(cd examples/61-claims-request && GOWORK=off go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with claims_parameter_supported advertised and
//     a closed claims_supported set published in discovery.
//   - :9090 — the RP from examples/internal/rpkit. Its rpkit.Options
//     carries a non-nil ClaimsRequest so the authorize redirect
//     includes a "claims" parameter alongside the standard scopes.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  2. Click "Log in via the OP" — the browser is redirected to the
//     OP's /auth, then to the password prompt.
//  3. Sign in as username "demo" / password "demo".
//  4. Approve the consent prompt.
//  5. The browser ends up at http://127.0.0.1:9090/me with the
//     verified ID Token claims rendered as JSON. The "email" claim
//     is present because the RP requested it as essential through
//     the §5.5 parameter; "name" comes from the "profile" scope.
//
// Cross-check the OP's advertised surface:
//
//	curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq '{claims_parameter_supported, claims_supported}'
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User catalogue: hard-coded for the demo; resolve claims through the embedder's identity database via [store.UserStore.FindBySubject].
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "claims-demo-rp"
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
	keys := devkeys.MustEphemeral("claims-1")

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
		op.WithClaimsParameterSupported(true),
		op.WithClaimsSupported(
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "given_name", "family_name", "preferred_username",
			"email", "email_verified",
			"locale",
		),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)
	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, claims_parameter_supported)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(ctx, issuer); err != nil {
		return err
	}

	// OIDC §5.5: ask the OP to release email as essential in the ID
	// Token and locale as voluntary in /userinfo. Voluntary claims
	// (JSON null) layer on top of the scope-driven release; essential
	// requests widen it.
	claimsRequest := map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
		"userinfo": map[string]any{
			"locale": nil,
		},
	}

	rp, err := rpkit.New(context.Background(), rpkit.Options{
		Issuer:        issuer,
		ClientID:      clientID,
		RedirectURL:   redirectURI,
		Scopes:        []string{"openid", "profile"},
		ClaimsRequest: claimsRequest,
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
			"name":           "Demo User",
			"given_name":     "Demo",
			"family_name":    "User",
			"email":          "demo@example.com",
			"email_verified": true,
			"locale":         "ja-JP",
		},
	}, demoUsername, hash)
	return nil
}
