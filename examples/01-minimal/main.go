//go:build example

// Example 01-minimal is the tutorial example: an OP and a paired
// Relying Party run in the same process so an embedder can drive a
// full Authorization Code + PKCE round-trip from a browser without
// any external setup.
//
// Run with the example build tag:
//
//	(cd examples/01-minimal && go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with one seeded password user and one
//     statically-registered public client whose redirect URI points
//     at the RP.
//   - :9090 — the RP, built from examples/internal/rpkit. It exposes
//     /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  2. Click "Log in via the OP" — the browser is redirected to the
//     OP's /auth, then to the password prompt.
//  3. Sign in as username "demo" / password "demo".
//  4. Approve the consent prompt.
//  5. The browser ends up at http://127.0.0.1:9090/me with the
//     verified ID Token claims rendered as JSON. The "iss" claim
//     matches http://127.0.0.1:8080.
//
// Restart the process whenever the round-trip stalls; ephemeral
// keys mean every restart invalidates every in-flight session.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - rpkit: the RP code in examples/internal/rpkit is a demo wrapper, not a library. Production RPs use golang.org/x/oauth2 + github.com/coreos/go-oidc/v3 directly.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
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
	clientID    = "demo-rp"
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
	keys := devkeys.MustEphemeral("minimal-1")

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return err
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(opkit.DefaultLoginFlow(st.UserPasswords())),
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
		log.Printf("OP listening on %s (issuer %s)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	// rpkit runs OIDC discovery synchronously, so wait until the OP
	// listener is up before constructing the RP.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitForIssuer(ctx, issuer); err != nil {
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

// waitForIssuer polls iss + "/.well-known/openid-configuration" until
// it returns 200 or ctx is cancelled. The example boots the OP and
// the RP in the same process, so the RP's OIDC discovery runs as
// soon as the OP listener is ready.
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
