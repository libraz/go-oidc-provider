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
	listen        string
	issuer        string
	mount         string
	clientID      string
	redirectURIs  []string
	confClientID  string
	confClientSec string
	tlsCert       string
	tlsKey        string
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
		// confClientID / confClientSec back the second (confidential)
		// seed client. The OIDC Basic certification plan and the
		// FAPI 2.0 client_secret_basic test rows expect a client that
		// authenticates with a shared secret; the public client driven
		// by -client-id alone is incompatible with those plans by
		// design. Override either flag to reseed at startup.
		confClientID  = flag.String("confidential-client-id", "demo-confidential", "client_id of the confidential seed client (client_secret_basic auth). Empty disables the confidential seed.")
		confClientSec = flag.String("confidential-client-secret", "demo-confidential-secret", "client_secret for the confidential seed client. Empty disables the confidential seed.")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := runConfig{
		listen:        *listen,
		issuer:        *issuer,
		mount:         *mount,
		clientID:      *clientID,
		redirectURIs:  parseRedirectURIs(*redirectURI),
		confClientID:  *confClientID,
		confClientSec: *confClientSec,
		tlsCert:       *tlsCert,
		tlsKey:        *tlsKey,
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

	st, err := bootstrapStore(cfg)
	if err != nil {
		return err
	}

	provider, err := op.New(
		op.WithIssuer(cfg.issuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "op-demo-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithMountPrefix(cfg.mount),
		op.WithLogger(logger),
		op.WithInteraction(htmlDriver{}),
		op.WithAuthenticators(stubAuthenticator{}),
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

// bootstrapStore returns the in-memory store seeded with the public
// client, the optional confidential client, and the demo user. The
// helper exists so [run] stays under the gocognit budget; the seed
// branches are intentionally split out rather than inlined.
func bootstrapStore(cfg runConfig) (*inmem.Store, error) {
	st := inmem.New()
	if err := seedClient(st, cfg.clientID, cfg.redirectURIs); err != nil {
		return nil, fmt.Errorf("seed demo client: %w", err)
	}
	if cfg.confClientID != "" && cfg.confClientSec != "" {
		if err := seedConfidentialClient(st, cfg.confClientID, cfg.confClientSec, cfg.redirectURIs); err != nil {
			return nil, fmt.Errorf("seed confidential client: %w", err)
		}
	}
	seedDemoUser(st)
	return st, nil
}

// seedClient registers the public demo client used by manual flows
// (curl smoke tests, the OP-managed login UI). The library has no
// implicit clients, so without this seed the /authorize endpoint
// would reject every request as unknown_client.
func seedClient(st *inmem.Store, clientID string, redirectURIs []string) error {
	return st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		RedirectURIs:            redirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceStatic,
	})
}

// seedConfidentialClient registers a second client that authenticates
// with a shared secret. The OIDC Basic certification plan and the
// FAPI 2.0 client_secret_basic test rows expect this shape: a public
// client (auth_method="none") cannot satisfy those modules because
// the spec mandates confidential auth at the token endpoint. The seed
// shares the same redirect URIs so a single conformance run covers
// both client postures without restarting the binary.
//
// The library binds each Client to exactly one
// TokenEndpointAuthMethod, so a parallel registration with
// client_secret_post is needed to satisfy variants that test that
// method (oidcc-server-client-secret-post). It carries the same
// redirect URIs, scopes, and secret as the basic registration and
// shares the suffix "-post" on the client_id.
//
// The secret is hashed through [op.HashClientSecret] (argon2id with
// the library defaults) before being stored; the raw value is kept
// only for the duration of seedConfidentialClient.
func seedConfidentialClient(st *inmem.Store, clientID, clientSecret string, redirectURIs []string) error {
	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		return fmt.Errorf("hash client secret: %w", err)
	}
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		RedirectURIs:            redirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
		Source:                  store.ClientSourceStatic,
	}); err != nil {
		return err
	}
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID + "-post",
		RedirectURIs:            redirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_post",
		SecretHash:              hash,
		Source:                  store.ClientSourceStatic,
	}); err != nil {
		return err
	}
	// A third basic-auth client distinct from clientID so OFCS modules
	// that exercise "second client must NOT be able to refresh first
	// client's token" (oidcc-refresh-token) can pin client2 to a
	// genuinely different client_id without changing auth method.
	return st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID + "-2",
		RedirectURIs:            redirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
		Source:                  store.ClientSourceStatic,
	})
}

// seedDemoUser populates the user record [stubAuthenticator] binds
// every successful login to. /userinfo and id_token claim assembly
// look up the subject through [store.UserStore.FindBySubject]; without
// this seed the openid scope would yield a token whose subject does
// not resolve and the conformance run would surface "unknown subject".
//
// The claim values are deliberately conventional ("name", "email",
// "email_verified") so OFCS profile_response checks pass with no
// further wiring. UpdatedAt uses a fixed date rather than [time.Now]
// because internal/timex is the canonical clock source for production
// code and a dev-only seed has no need to participate in that
// machinery — the value just feeds the "updated_at" claim, which OFCS
// only checks for shape, not freshness.
func seedDemoUser(st *inmem.Store) {
	updatedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st.PutUser(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			// profile (OIDC Core 1.0 §5.4)
			"name":               "Demo User",
			"family_name":        "User",
			"given_name":         "Demo",
			"middle_name":        "Q.",
			"nickname":           "demo",
			"preferred_username": "demo",
			"profile":            "https://example.com/demo",
			"picture":            "https://example.com/demo.jpg",
			"website":            "https://example.com",
			"gender":             "other",
			"birthdate":          "2000-01-01",
			"zoneinfo":           "UTC",
			"locale":             "en-US",
			"updated_at":         updatedAt.Unix(),
			// email
			"email":          "demo-user@example.com",
			"email_verified": true,
			// address — OIDC §5.1.1 structured value
			"address": map[string]any{
				"formatted":      "123 Demo Street\nDemo City DC 12345\nUS",
				"street_address": "123 Demo Street",
				"locality":       "Demo City",
				"region":         "DC",
				"postal_code":    "12345",
				"country":        "US",
			},
			// phone
			"phone_number":          "+1-555-0100",
			"phone_number_verified": true,
		},
		UpdatedAt: updatedAt,
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
