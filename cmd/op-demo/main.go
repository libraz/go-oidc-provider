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
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
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
	// profile selects the OP security posture. "" / "basic" leaves
	// the OP vanilla (OIDC Core only); "fapi2-baseline" /
	// "fapi2-message-signing" activate the matching profile and the
	// features the profile mandates (PAR, DPoP). The flag exists so
	// the conformance harness can run the same op-demo binary against
	// every plan in plans/ without rebuilding.
	profile string
	// fapiClient1JWKS / fapiClient2JWKS are paths to JWK Set files
	// containing the PUBLIC half of the FAPI test client keys. They
	// are only consulted when profile is fapi2-*. The matching
	// private halves live in conformance/plans/fapi2-*.json so the
	// OFCS instance can sign private_key_jwt assertions; this binary
	// strips the "d" parameter at registration time.
	fapiClient1JWKS string
	fapiClient2JWKS string
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
		profileFlag   = flag.String("profile", "", "security profile to activate. One of: \"\" (no profile, vanilla OIDC Core), \"fapi2-baseline\", \"fapi2-message-signing\". Profiles auto-enable the features they require (PAR, DPoP).")
		// FAPI test client JWKS paths. Each file holds the PUBLIC
		// half (kty/crv/x/y/kid only — "d" is stripped if present)
		// of one OFCS test client. The matching private halves live
		// in conformance/plans/fapi2-*.json so OFCS can sign
		// private_key_jwt assertions.
		fapiClient1JWKS = flag.String("fapi-client-jwks", "conformance/keys/fapi-client.jwks.json", "path to JWKS file for the primary FAPI test client (demo-fapi). Only consulted when -profile=fapi2-*.")
		fapiClient2JWKS = flag.String("fapi-client-2-jwks", "conformance/keys/fapi-client-2.jwks.json", "path to JWKS file for the secondary FAPI test client (demo-fapi-2). Only consulted when -profile=fapi2-*.")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := runConfig{
		listen:          *listen,
		issuer:          *issuer,
		mount:           *mount,
		clientID:        *clientID,
		redirectURIs:    parseRedirectURIs(*redirectURI),
		confClientID:    *confClientID,
		confClientSec:   *confClientSec,
		tlsCert:         *tlsCert,
		tlsKey:          *tlsKey,
		profile:         *profileFlag,
		fapiClient1JWKS: *fapiClient1JWKS,
		fapiClient2JWKS: *fapiClient2JWKS,
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
	if err := seedDemoUser(st); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}
	opts, err := buildOptions(ctx, cfg, st, priv, cookieKey, logger)
	if err != nil {
		return err
	}

	provider, err := op.New(opts...)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           provider,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if isFAPIProfile(cfg.profile) {
		srv.TLSConfig = op.FAPITLSConfig()
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
		"fapi_tls", srv.TLSConfig != nil,
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

// buildOptions assembles the [op.Option] slice [run] hands to op.New.
// The helper exists so [run] stays under the gocognit budget; the
// branch points (profile selection, FAPI-only DPoP enable, optional
// confidential client seeding) live here, not inline.
func buildOptions(ctx context.Context, cfg runConfig, st *inmem.Store, priv *ecdsa.PrivateKey, cookieKey []byte, logger *slog.Logger) ([]op.Option, error) {
	seeds, err := buildClientSeeds(cfg)
	if err != nil {
		return nil, err
	}
	prof, err := profileFor(cfg.profile)
	if err != nil {
		return nil, err
	}
	opts := []op.Option{
		op.WithIssuer(cfg.issuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "op-demo-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithMountPrefix(cfg.mount),
		op.WithLogger(logger),
		op.WithStaticClients(seeds...),
		// LoginFlow with the built-in PrimaryPassword Step. The
		// orchestrator's default HTMLDriver renders the password
		// prompt; demo seeds username "demo" / password "demo" so the
		// OFCS scripts (which default to OFCS_DEMO_USER=demo /
		// OFCS_DEMO_PASS=demo) complete the chain end-to-end.
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: st.UserPasswords()}}),
		// JAR (RFC 9101) is opt-in for non-FAPI profiles. Enabling
		// it makes discovery advertise
		// request_object_signing_alg_values_supported (without
		// "none"), which lets the OFCS unsigned-request-object
		// module skip cleanly while keeping the signed path live
		// for the redirect-uri-in-request-object module. WithProfile
		// auto-enables JAR for FAPI 2.0; calling WithFeature here is
		// idempotent under the auto-enable contract.
		op.WithFeature(feature.JAR),
		// Advertise the standard OIDC Core 1.0 §5 claims that
		// seedDemoUser fills in. OFCS's claims-parameter test skips
		// when claims_supported lists no standard claims, so listing
		// them here keeps the test runnable. The set mirrors the user
		// store seed; if a deployment serves a smaller set, this list
		// must shrink to match — the option is not a stand-in for
		// what the projector actually emits.
		op.WithClaimsSupported(
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website", "gender",
			"birthdate", "zoneinfo", "locale", "updated_at",
			"email", "email_verified",
			"address",
			"phone_number", "phone_number_verified",
		),
	}
	if prof != 0 {
		opts = append(opts, op.WithProfile(prof))
	}
	if isFAPIProfile(cfg.profile) {
		// FAPI 2.0 mandates sender-constrained access tokens (DPoP
		// or mTLS); op-demo selects DPoP. WithProfile does not
		// auto-enable DPoP because mTLS satisfies the same
		// requirement and which one to choose is a deployment call.
		opts = append(opts, op.WithFeature(feature.DPoP))
	}
	if cfg.profile == "fapi2-message-signing" {
		// FAPI 2.0 Message Signing §5.3.4 requires the AS to issue a
		// server-supplied DPoP nonce (RFC 9449 §8/§9). The option
		// layer rejects op.New without a source under this profile,
		// so wire the in-memory rotator that ships with the library.
		nonces, err := op.NewInMemoryDPoPNonceSource(ctx, time.Minute,
			op.WithInMemoryDPoPNonceLogger(logger))
		if err != nil {
			return nil, fmt.Errorf("dpop nonce source: %w", err)
		}
		opts = append(opts, op.WithDPoPNonceSource(nonces))
	}
	return opts, nil
}

// profileFor translates the -profile flag into a [profile.Profile] the
// op.WithProfile option accepts. Returns 0 (the "no profile" sentinel)
// for the empty/"basic" case so the OP runs vanilla OIDC Core.
func profileFor(name string) (profile.Profile, error) {
	switch name {
	case "", "basic":
		return 0, nil
	case "fapi2-baseline":
		return profile.FAPI2Baseline, nil
	case "fapi2-message-signing":
		return profile.FAPI2MessageSigning, nil
	default:
		return 0, fmt.Errorf("op-demo: unknown -profile %q (expected one of: basic, fapi2-baseline, fapi2-message-signing)", name)
	}
}

// isFAPIProfile reports whether the profile name selects a FAPI 2.0
// posture, which is the trigger for seeding the private_key_jwt FAPI
// test clients and the FAPI TLS allowlist.
func isFAPIProfile(name string) bool {
	return name == "fapi2-baseline" || name == "fapi2-message-signing"
}

// scopeCatalog is the OIDC Core scope set every demo client is
// registered to request. The list is shared rather than duplicated so
// a future scope addition lands across all seeds in one place.
//
//nolint:gochecknoglobals // immutable demo seed; no per-instance tuning.
var scopeCatalog = []string{"openid", "profile", "email", "address", "phone", "offline_access"}

// fapiScopeCatalog drops the address/phone scopes from [scopeCatalog]:
// the FAPI 2.0 conformance plans never request them, and trimming
// keeps the registered scope set consistent with the plan templates.
//
//nolint:gochecknoglobals // immutable demo seed; no per-instance tuning.
var fapiScopeCatalog = []string{"openid", "profile", "email", "offline_access"}

// buildClientSeeds projects the runConfig onto the typed
// [op.ClientSeed] slice [op.WithStaticClients] consumes. The function
// is the H2 replacement for the per-client seedXxx helpers: the typed
// builders enforce the per-shape invariants (auth method, secret
// hashing, JWKS handling) so this layer only assembles the data.
func buildClientSeeds(cfg runConfig) ([]op.ClientSeed, error) {
	seeds := []op.ClientSeed{
		// Public demo client used by manual flows (curl smoke
		// tests, the OP-managed login UI). The library has no
		// implicit clients, so without this seed /authorize would
		// reject every request as unknown_client.
		op.PublicClient{
			ID:           cfg.clientID,
			RedirectURIs: cfg.redirectURIs,
			Scopes:       scopeCatalog,
		},
	}
	if cfg.confClientID != "" && cfg.confClientSec != "" {
		// The OIDC Basic certification plan and the FAPI 2.0
		// client_secret_basic test rows expect a confidential
		// client; the public client cannot satisfy those modules.
		// Three registrations cover the three auth-method
		// variants OFCS exercises (basic / post, plus a distinct
		// second basic client for the cross-client refresh test).
		seeds = append(seeds,
			op.ConfidentialClient{
				ID:           cfg.confClientID,
				Secret:       cfg.confClientSec,
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: cfg.redirectURIs,
				Scopes:       scopeCatalog,
			},
			op.ConfidentialClient{
				ID:           cfg.confClientID + "-post",
				Secret:       cfg.confClientSec,
				AuthMethod:   op.AuthClientSecretPost,
				RedirectURIs: cfg.redirectURIs,
				Scopes:       scopeCatalog,
			},
			op.ConfidentialClient{
				ID:           cfg.confClientID + "-2",
				Secret:       cfg.confClientSec,
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: cfg.redirectURIs,
				Scopes:       scopeCatalog,
			},
		)
	}
	if isFAPIProfile(cfg.profile) {
		fapiURIs := withFAPIDummyRedirectURIs(cfg.redirectURIs)
		for _, entry := range []struct {
			id   string
			path string
		}{
			{"demo-fapi", cfg.fapiClient1JWKS},
			{"demo-fapi-2", cfg.fapiClient2JWKS},
		} {
			pub, err := op.LoadPublicJWKS(entry.path)
			if err != nil {
				return nil, fmt.Errorf("load JWKS %s: %w", entry.path, err)
			}
			seeds = append(seeds, op.PrivateKeyJWTClient{
				ID:           entry.id,
				JWKS:         pub,
				RedirectURIs: fapiURIs,
				Scopes:       fapiScopeCatalog,
			})
		}
	}
	return seeds, nil
}

// withFAPIDummyRedirectURIs returns base extended with the dummy-query
// variants the OFCS happy-flow appends via AddDummyValuesToRedirectUri.
// FAPI 2.0 / OAuth 2.1 require exact-string redirect_uri match, but the
// OFCS happy-flow exercises a "second client with extra query params"
// path that the AS is expected to accept. Pre-registering the variants
// lets exact-match succeed without weakening the matcher.
func withFAPIDummyRedirectURIs(base []string) []string {
	const (
		twoDummies   = "?dummy1=lorem&dummy2=ipsum"
		threeDummies = "?dummy1=lorem&dummy2=ipsum&dummy3=dolor"
	)
	out := make([]string, 0, len(base)*3)
	for _, u := range base {
		out = append(out, u, u+twoDummies, u+threeDummies)
	}
	return out
}

// demoSubject is the single subject every successful login binds to.
// op-demo seeds one user with username "demo" and password "demo"; the
// OFCS scripts (OFCS_DEMO_USER / OFCS_DEMO_PASS env defaults) drive
// the same credentials so a multi-plan run completes without an
// embedder-supplied user database.
const demoSubject = "demo-user"

// demoUsername / demoPassword are the credentials seedDemoUser
// registers. The library's PrimaryPassword Step verifies the password
// at runtime through Argon2id; the cleartext lives only in this
// dev binary's seed path.
const (
	demoUsername = "demo"
	demoPassword = "demo"
)

// seedDemoUser populates the user record the PrimaryPassword Step
// resolves on a successful login. /userinfo and id_token claim assembly
// look up the subject through [store.UserStore.FindBySubject], and the
// password ceremony resolves [demoUsername] → demoSubject through
// [store.UserPasswordStore.FindByUsername]. The hash is produced via
// [op.HashPassword] so it slots into the library verifier without
// special handling.
//
// The claim values are deliberately conventional ("name", "email",
// "email_verified") so OFCS profile_response checks pass with no
// further wiring. UpdatedAt uses a fixed date rather than [time.Now]
// because internal/timex is the canonical clock source for production
// code and a dev-only seed has no need to participate in that
// machinery — the value just feeds the "updated_at" claim, which OFCS
// only checks for shape, not freshness.
func seedDemoUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return fmt.Errorf("hash demo password: %w", err)
	}
	updatedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st.PutUserWithPassword(context.Background(), &store.User{
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
	}, demoUsername, hash)
	return nil
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
