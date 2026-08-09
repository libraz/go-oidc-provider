//go:build example

// Example 10 demonstrates [op.WithSPAUI]: the OP delegates the
// login screens to a SPA at the configured mount paths while still
// driving the OAuth + OIDC protocol surface. The SPA bundle comes
// from examples/internal/webui — hand-rolled vanilla HTML/CSS/JS with
// no build step, shared by every SPA example — so the demo runs out
// of the box.
//
// Run with the example build tag, from this directory so the shared
// SPA bundle resolves:
//
//	(cd examples/10-react-login && GOWORK=off go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with one seeded password user, one
//     statically-registered public client, and the SPA bundle
//     served at /login.
//   - :9090 — the RP, built from examples/internal/rpkit. It
//     exposes /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — the RP landing page.
//  2. Click "Log in via the OP" — the browser is redirected to the
//     OP's /authorize, then to /login/{uid} where the SPA bundle
//     loads.
//  3. The SPA fetches /login/state/{uid}, renders the password
//     prompt, and POSTs the submission. The OP completes the flow
//     and redirects back to the RP callback.
//  4. Sign in as username "demo" / password "demo".
//  5. Approve consent (the SPA renders the same prompt shape).
//  6. The browser ends up at http://127.0.0.1:9090/me with the
//     verified ID Token claims rendered as JSON.
//
// Restart the process whenever the round-trip stalls; ephemeral
// keys mean every restart invalidates every in-flight session.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - SPA bundle: vanilla JS for clarity; production embedders ship
//     their framework's build output (React/Vue/Svelte/Angular)
//     under StaticDir with the same JSON contract.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/examples/internal/webui"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "demo-rp"
	redirectURI = rpBase + "/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"

	staticDir = webui.StaticDir
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so the shared SPA bundle resolves")
	}

	keys := devkeys.MustEphemeral("react-1")

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
		op.WithSPAUI(op.SPAUI{
			LoginMount: "/login",
			StaticDir:  staticDir,
		}),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile"},
		}),
	)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, SPA at /login)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(ctx, issuer); err != nil {
		return err
	}

	rp, err := rpkit.New(context.Background(), rpkit.Options{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "profile"},
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
