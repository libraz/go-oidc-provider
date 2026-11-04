//go:build example

// Example 01-minimal is the tutorial example: an OP and a paired
// Relying Party run in the same process so an embedder can drive a
// full Authorization Code + PKCE round-trip from a browser without
// any external setup.
//
// Run with the example build tag:
//
//	(cd examples/01-minimal && GOWORK=off go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with one seeded password user and one
//     statically-registered public client whose redirect URI points
//     at the RP.
//   - :9090 — the RP, built from examples/internal/rpkit. It exposes
//     /, /login, /callback, /me.
//
// Graceful shutdown on SIGINT / SIGTERM is written out inline in run(),
// with the server timeouts and drain order an embedder should copy.
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
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
	// Ephemeral keys for the demo; production loads them with op.LoadKeyset / op.LoadSymmetricKeys.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return err
	}

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return err
	}

	// Password-only login: one Primary step, no rules.
	loginFlow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "minimal-1", Signer: priv}}),
		op.WithCookieKeys(cookieKey),
		op.WithProfile(profile.OAuth21),
		op.WithLoginFlow(loginFlow),
		op.WithLogger(slog.Default()),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile"},
		}),
	)
	if err != nil {
		return err
	}

	// SIGINT or SIGTERM cancels ctx and starts the shutdown at the end of run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)
	opSrv := &http.Server{
		Addr:              opAddr,
		Handler:           opMux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("OP listening on %s (issuer %s)", opAddr, issuer)
		if err := opSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// rpkit runs OIDC discovery synchronously, so wait until the OP
	// listener is up before constructing the RP.
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(waitCtx, issuer); err != nil {
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
	rpSrv := &http.Server{
		Addr:              rpAddr,
		Handler:           rpMux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	go func() {
		if err := rpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Block until a signal or a listener failure, then drain.
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}

	// Stop accepting first, then let the provider finish queued back-channel work.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	return errors.Join(
		runErr,
		opSrv.Shutdown(shutCtx),
		rpSrv.Shutdown(shutCtx),
		provider.Shutdown(shutCtx),
	)
}

func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: store.StandardClaims{
			Name:  "Demo User",
			Email: "demo@example.com",
		}.Map(),
	}, demoUsername, hash)
	return nil
}
