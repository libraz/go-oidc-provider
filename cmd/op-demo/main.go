// Command op-demo runs a single-process OpenID Connect Provider
// suitable for manual inspection and the OpenID Foundation
// Conformance Suite.
//
// The binary is dev-only — it generates ephemeral signing and cookie
// keys at startup, persists every record in process memory, and
// terminates the OP cleanly on SIGINT / SIGTERM. It is not intended
// for production deployments.
//
// Quick start (HTTP):
//
//	go run ./cmd/op-demo \
//	    -listen :9090 \
//	    -issuer https://localhost:9090 \
//	    -client-id demo-client \
//	    -redirect-uri https://localhost.emobix.co.uk:8443/test/a/op-demo/callback
//
// Quick start (HTTPS, required by the OpenID Foundation Conformance
// Suite because issuer URLs MUST be https://):
//
//	go run ./cmd/op-demo \
//	    -listen :9443 \
//	    -issuer https://localhost:9443 \
//	    -tls-cert ./localhost.pem \
//	    -tls-key  ./localhost-key.pem
//
// In production embedders read keys from a vault / KMS and persist
// records in a real backend; this binary deliberately wires neither
// so the moving parts stay visible.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// shutdownGrace is the deadline for in-flight requests to drain after
// the demo receives SIGINT or SIGTERM. The value is short on purpose:
// op-demo is a development binary, not a production OP, so a long
// grace period would only mask hung handlers during conformance runs.
const shutdownGrace = 5 * time.Second

// runConfig groups the demo's startup knobs so run() does not grow a
// long positional signature as flags accumulate.
type runConfig struct {
	listen       string
	issuer       string
	mount        string
	clientID     string
	redirectURIs []string
	tlsCert      string
	tlsKey       string
}

func main() {
	if err := mainErr(); err != nil {
		// mainErr handles its own logging; the bare exit code is
		// what the OS observes. Splitting main into mainErr keeps
		// every defer (signal stop, future flushes) running before
		// os.Exit terminates the process.
		os.Exit(1)
	}
}

func mainErr() error {
	var (
		listen      = flag.String("listen", ":9090", "TCP listen address (\"host:port\" or \":port\")")
		issuer      = flag.String("issuer", "https://localhost:9090", "issuer URL — MUST be https://, no query, no fragment")
		mount       = flag.String("mount", "/oidc", "URL prefix the OP handler is mounted under")
		clientID    = flag.String("client-id", "demo-client", "client_id of the seed client")
		redirectURI = flag.String("redirect-uri", "https://localhost.emobix.co.uk:8443/test/a/op-demo/callback", "comma-separated list of redirect_uri values seeded for the demo client. The OFCS routes each test plan's callback at /test/a/<alias>/callback, so a multi-plan conformance run needs every plan's URI seeded up front.")
		tlsCert     = flag.String("tls-cert", "", "path to PEM-encoded TLS certificate; empty to serve plain HTTP. Must be paired with -tls-key.")
		tlsKey      = flag.String("tls-key", "", "path to PEM-encoded TLS private key; empty to serve plain HTTP. Must be paired with -tls-cert.")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := runConfig{
		listen:       *listen,
		issuer:       *issuer,
		mount:        *mount,
		clientID:     *clientID,
		redirectURIs: parseRedirectURIs(*redirectURI),
		tlsCert:      *tlsCert,
		tlsKey:       *tlsKey,
	}
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("op-demo: fatal", "err", err)
		return err
	}
	return nil
}

func run(ctx context.Context, cfg runConfig, logger *slog.Logger) error {
	// One-of TLS configuration is almost always a typo: a half-set
	// pair would silently fall back to plain HTTP and surprise the
	// operator at the first OFCS run. Reject it before we touch
	// anything else.
	if (cfg.tlsCert == "") != (cfg.tlsKey == "") {
		return errors.New("op-demo: -tls-cert and -tls-key must be provided together")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return fmt.Errorf("generate cookie key: %w", err)
	}

	if len(cfg.redirectURIs) == 0 {
		return errors.New("op-demo: -redirect-uri must list at least one URI")
	}

	st := inmem.New()
	if err := seedClient(st, cfg.clientID, cfg.redirectURIs); err != nil {
		return fmt.Errorf("seed demo client: %w", err)
	}

	provider, err := op.New(
		op.WithIssuer(cfg.issuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "op-demo-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithMountPrefix(cfg.mount),
		op.WithLogger(logger),
	)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           provider,
		ReadHeaderTimeout: 5 * time.Second,
	}

	idleClosed := make(chan struct{})
	// Shutdown deliberately uses a fresh background context: by the
	// time this goroutine wakes, the parent ctx is already done, so
	// reusing it would deny the server its drain window. The 5-second
	// grace is a server drain budget, not a request-scoped deadline.
	//nolint:gosec // G118: deliberate background ctx — see comment above.
	go func() {
		<-ctx.Done()
		logger.Info("op-demo: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("op-demo: shutdown", "err", err)
		}
		close(idleClosed)
	}()

	tlsEnabled := cfg.tlsCert != ""
	logger.Info("op-demo: listening",
		"addr", cfg.listen,
		"issuer", cfg.issuer,
		"mount", cfg.mount,
		"client_id", cfg.clientID,
		"tls", tlsEnabled,
	)

	var listenErr error
	if tlsEnabled {
		listenErr = srv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
	} else {
		listenErr = srv.ListenAndServe()
	}
	if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
		return fmt.Errorf("listen: %w", listenErr)
	}
	<-idleClosed
	return nil
}

// seedClient registers the single demo client used by manual flows
// and the OFCS test plans. The library has no implicit clients, so
// without this seed the /authorize endpoint would reject every
// request as unknown_client.
func seedClient(st *inmem.Store, clientID string, redirectURIs []string) error {
	return st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		RedirectURIs:            redirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceStatic,
	})
}

// parseRedirectURIs splits the -redirect-uri flag on commas and trims
// whitespace so a multi-plan conformance run can seed every plan's
// callback path in one invocation. Empty entries (from a stray
// trailing comma) are dropped.
func parseRedirectURIs(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
