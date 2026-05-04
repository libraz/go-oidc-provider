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
	opgrant "github.com/libraz/go-oidc-provider/op/grant"
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
	// "fapi2-message-signing" / "fapi-ciba" activate the matching
	// profile and the features the profile mandates (PAR, DPoP, JAR).
	// The flag exists so the conformance harness can run the same
	// op-demo binary against every plan in plans/ without rebuilding.
	profile string
	// fapiClient1JWKS / fapiClient2JWKS are paths to JWK Set files
	// containing the PUBLIC half of the FAPI test client keys. They
	// are only consulted when profile is fapi2-* or fapi-ciba. The
	// matching private halves live in conformance/plans/fapi2-*.json
	// so the OFCS instance can sign private_key_jwt assertions; this
	// binary strips the "d" parameter at registration time.
	fapiClient1JWKS string
	fapiClient2JWKS string
	// enableDCR opts the OP into RFC 7591 / RFC 7592 / OIDC Dynamic
	// Client Registration. When true, /register is mounted, an
	// Initial Access Token is minted at startup and printed to
	// stdout, and discovery advertises registration_endpoint. The
	// flag is off by default so non-DCR conformance plans run with
	// the smaller surface.
	enableDCR bool
	// cibaAutoApproveDelay is how long the auto-approving CIBA
	// substore waits before flipping a Pending record to Approved.
	// The default (3 s) is long enough that the first /token poll
	// lands authorization_pending under the 1 s default poll
	// interval — the shape the OFCS fapi-ciba plan asserts on.
	cibaAutoApproveDelay time.Duration
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
		profileFlag   = flag.String("profile", "", "security profile to activate. One of: \"\" (no profile, vanilla OIDC Core), \"fapi2-baseline\", \"fapi2-message-signing\", \"fapi-ciba\". Profiles auto-enable the features they require (PAR, DPoP, JAR).")
		// FAPI test client JWKS paths. Each file holds the PUBLIC
		// half (kty/crv/x/y/kid only — "d" is stripped if present)
		// of one OFCS test client. The matching private halves live
		// in conformance/plans/fapi2-*.json so OFCS can sign
		// private_key_jwt assertions.
		fapiClient1JWKS = flag.String("fapi-client-jwks", "conformance/keys/fapi-client.jwks.json", "path to JWKS file for the primary FAPI test client (demo-fapi). Only consulted when -profile=fapi2-* or -profile=fapi-ciba.")
		fapiClient2JWKS = flag.String("fapi-client-2-jwks", "conformance/keys/fapi-client-2.jwks.json", "path to JWKS file for the secondary FAPI test client (demo-fapi-2). Only consulted when -profile=fapi2-*.")
		// DCR opt-in. Off by default so non-DCR plans run with the
		// smaller surface; turning it on mounts /register and prints
		// a fresh Initial Access Token to stdout at startup so OFCS's
		// oidcc-dynamic plan can register a client without manual
		// IAT issuance.
		enableDCR = flag.Bool("enable-dcr", false, "enable Dynamic Client Registration (RFC 7591/7592). When set, the OP mounts /register, advertises registration_endpoint, and prints a fresh Initial Access Token to stdout at startup.")
		// CIBA auto-approve delay. Long enough that the first /token
		// poll observes authorization_pending under the 1 s poll
		// interval the OFCS fapi-ciba plan drives.
		cibaAutoApproveDelay = flag.Duration("ciba-autoapprove-delay", 3*time.Second, "delay before the auto-approving CIBA substore flips a Pending record to Approved. Only consulted when -profile=fapi-ciba; production embedders trigger Approve from the user's authentication device callback, never from inside the OP.")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := runConfig{
		listen:               *listen,
		issuer:               *issuer,
		mount:                *mount,
		clientID:             *clientID,
		redirectURIs:         parseRedirectURIs(*redirectURI),
		confClientID:         *confClientID,
		confClientSec:        *confClientSec,
		tlsCert:              *tlsCert,
		tlsKey:               *tlsKey,
		profile:              *profileFlag,
		fapiClient1JWKS:      *fapiClient1JWKS,
		fapiClient2JWKS:      *fapiClient2JWKS,
		enableDCR:            *enableDCR,
		cibaAutoApproveDelay: *cibaAutoApproveDelay,
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
	if len(cfg.redirectURIs) == 0 {
		return errors.New("op-demo: -redirect-uri must list at least one URI")
	}

	provider, err := buildProvider(ctx, cfg, logger)
	if err != nil {
		return err
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

// buildProvider performs every construction step run() needs before
// it can hand the resulting handler to net/http: ephemeral key
// generation, in-memory store seeding, optional CIBA store wrapping,
// op.New invocation, and the optional Initial Access Token mint when
// -enable-dcr is set. Split out of run() so the parent stays under
// the gocognit budget.
func buildProvider(ctx context.Context, cfg runConfig, logger *slog.Logger) (*op.Provider, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return nil, fmt.Errorf("generate cookie key: %w", err)
	}

	st := inmem.New()
	if err := seedDemoUser(st); err != nil {
		return nil, fmt.Errorf("seed demo user: %w", err)
	}
	opStore := buildOPStore(ctx, cfg, st, logger)
	opts, err := buildOptions(ctx, cfg, st, opStore, priv, cookieKey, logger)
	if err != nil {
		return nil, err
	}
	provider, err := op.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("op.New: %w", err)
	}
	if cfg.enableDCR {
		if err := mintInitialAccessToken(ctx, provider, logger); err != nil {
			return nil, fmt.Errorf("mint initial access token: %w", err)
		}
	}
	return provider, nil
}

// buildOptions assembles the [op.Option] slice [run] hands to op.New.
// The helper exists so [run] stays under the gocognit budget; the
// branch points (profile selection, FAPI-only DPoP enable, optional
// confidential client seeding) live here, not inline.
//
// opStore is the [store.Store] passed to [op.WithStore] — typically
// the in-memory store, optionally wrapped by [cibaAutoApproveStore]
// when -profile=fapi-ciba is active. st is the underlying
// [*inmem.Store], retained because [op.PrimaryPassword] needs the
// concrete UserPasswords accessor (UserPasswords is not on the
// store.Store interface).
func buildOptions(ctx context.Context, cfg runConfig, st *inmem.Store, opStore store.Store, priv *ecdsa.PrivateKey, cookieKey []byte, logger *slog.Logger) ([]op.Option, error) {
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
		op.WithStore(opStore),
		op.WithKeyset(op.Keyset{{KeyID: "op-demo-1", Signer: priv}}),
		op.WithCookieKeys(cookieKey),
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
	if needsDPoPNonceSource(cfg.profile) {
		// FAPI 2.0 Message Signing §5.3.4 and FAPI-CIBA both require
		// the AS to issue a server-supplied DPoP nonce (RFC 9449
		// §8/§9). The option layer rejects op.New without a source
		// under these profiles, so wire the in-memory rotator that
		// ships with the library.
		nonces, err := op.NewInMemoryDPoPNonceSource(ctx, time.Minute,
			op.WithInMemoryDPoPNonceLogger(logger))
		if err != nil {
			return nil, fmt.Errorf("dpop nonce source: %w", err)
		}
		opts = append(opts, op.WithDPoPNonceSource(nonces))
	}
	if isCIBAProfile(cfg.profile) {
		opts = append(opts, op.WithCIBA(
			op.WithCIBAHintResolver(demoHintResolver(st)),
			// 1 s poll interval keeps the OFCS fapi-ciba plan moving;
			// the auto-approve delay (default 3 s) is intentionally
			// longer so the first poll lands authorization_pending.
			op.WithCIBAPollInterval(time.Second),
		))
	}
	if cfg.enableDCR {
		// 24 h IAT TTL, 1-use cap — the production-grade default that
		// op.RegistrationOption's zero value already encodes. Made
		// explicit here so the demo's startup behaviour is obvious
		// from the code without cross-referencing the registration
		// option's godoc.
		opts = append(opts, op.WithDynamicRegistration(op.RegistrationOption{
			IATTTL:  24 * time.Hour,
			IATUses: 1,
		}))
	}
	return opts, nil
}

// buildOPStore returns the [store.Store] handed to [op.WithStore].
// For non-CIBA profiles this is the bare [*inmem.Store]; for the
// fapi-ciba profile it is a [cibaAutoApproveStore] that wraps
// CIBARequests so Save schedules an out-of-band approval after
// cfg.cibaAutoApproveDelay. The wrapper exists because OFCS drives
// the fapi-ciba plan without a real authentication device — the
// approval has to come from inside op-demo to make the flow
// progress.
func buildOPStore(ctx context.Context, cfg runConfig, st *inmem.Store, logger *slog.Logger) store.Store {
	if !isCIBAProfile(cfg.profile) {
		return st
	}
	return &cibaAutoApproveStore{
		Store: st,
		auto: &autoApprovingCIBA{
			inner: st.CIBARequests(),
			delay: cfg.cibaAutoApproveDelay,
			ctx:   ctx,
			log:   logger,
		},
	}
}

// mintInitialAccessToken issues a single Initial Access Token and
// prints it to stdout so the OFCS oidcc-dynamic plan can register a
// client without a separate IAT issuance step. The full bearer value
// is printed because op-demo is a development binary; production
// callers MUST hand the value to a secret manager and never log it.
func mintInitialAccessToken(ctx context.Context, p *op.Provider, logger *slog.Logger) error {
	iat, err := p.IssueInitialAccessToken(ctx, op.InitialAccessTokenSpec{
		Tag: "op-demo-startup",
	})
	if err != nil {
		return err
	}
	// Print to stdout (operator-facing) rather than the structured
	// log so a `tee` or `grep IAT` over op-demo.log surfaces the
	// value without parsing JSON.
	fmt.Printf("[op-demo] DCR Initial Access Token: %s (id=%s expires=%s)\n",
		iat.Value, iat.ID, iat.ExpiresAt.UTC().Format(time.RFC3339))
	logger.Info("dcr initial access token issued",
		slog.String("id", iat.ID),
		slog.String("expires_at", iat.ExpiresAt.UTC().Format(time.RFC3339)))
	return nil
}

// demoHintResolver returns a [op.HintResolver] that maps the
// well-known login_hint "demo" (and the seed user's username) to the
// seed subject. Any other hint resolves to op.ErrUnknownCIBAUser so
// the OP returns the unknown_user_id wire code.
func demoHintResolver(_ *inmem.Store) op.HintResolver {
	return op.HintResolverFunc(func(_ context.Context, _ op.HintKind, value string) (string, error) {
		switch value {
		case demoUsername, demoSubject, "demo-user@example.com":
			return demoSubject, nil
		}
		return "", op.ErrUnknownCIBAUser
	})
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
	case "fapi-ciba":
		return profile.FAPICIBA, nil
	default:
		return 0, fmt.Errorf("op-demo: unknown -profile %q (expected one of: basic, fapi2-baseline, fapi2-message-signing, fapi-ciba)", name)
	}
}

// isFAPIProfile reports whether the profile name selects a FAPI 2.0
// posture (any of the three), which is the trigger for seeding the
// private_key_jwt FAPI test clients and the FAPI TLS allowlist.
func isFAPIProfile(name string) bool {
	return name == "fapi2-baseline" || name == "fapi2-message-signing" || name == "fapi-ciba"
}

// isCIBAProfile reports whether the profile name selects FAPI-CIBA,
// the trigger for seeding the CIBA-only client and the
// auto-approving CIBARequestStore wrapper.
func isCIBAProfile(name string) bool {
	return name == "fapi-ciba"
}

// needsDPoPNonceSource reports whether the profile requires a
// server-supplied DPoP nonce (RFC 9449 §8/§9). FAPI 2.0 Message
// Signing §5.3.4 mandates one, and FAPI-CIBA inherits the
// requirement through its baseline sender-constraint.
func needsDPoPNonceSource(name string) bool {
	return name == "fapi2-message-signing" || name == "fapi-ciba"
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
	postLogoutURIs := derivePostLogoutURIs(cfg.redirectURIs)
	seeds := []op.ClientSeed{
		// Public demo client used by manual flows (curl smoke
		// tests, the OP-managed login UI). The library has no
		// implicit clients, so without this seed /authorize would
		// reject every request as unknown_client.
		op.PublicClient{
			ID:                     cfg.clientID,
			RedirectURIs:           cfg.redirectURIs,
			Scopes:                 scopeCatalog,
			PostLogoutRedirectURIs: postLogoutURIs,
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
				ID:                     cfg.confClientID,
				Secret:                 cfg.confClientSec,
				AuthMethod:             op.AuthClientSecretBasic,
				RedirectURIs:           cfg.redirectURIs,
				Scopes:                 scopeCatalog,
				PostLogoutRedirectURIs: postLogoutURIs,
			},
			op.ConfidentialClient{
				ID:                     cfg.confClientID + "-post",
				Secret:                 cfg.confClientSec,
				AuthMethod:             op.AuthClientSecretPost,
				RedirectURIs:           cfg.redirectURIs,
				Scopes:                 scopeCatalog,
				PostLogoutRedirectURIs: postLogoutURIs,
			},
			op.ConfidentialClient{
				ID:                     cfg.confClientID + "-2",
				Secret:                 cfg.confClientSec,
				AuthMethod:             op.AuthClientSecretBasic,
				RedirectURIs:           cfg.redirectURIs,
				Scopes:                 scopeCatalog,
				PostLogoutRedirectURIs: postLogoutURIs,
			},
		)
	}
	if isFAPIProfile(cfg.profile) {
		fapiSeeds, err := buildFAPIClientSeeds(cfg, postLogoutURIs)
		if err != nil {
			return nil, err
		}
		seeds = append(seeds, fapiSeeds...)
	}
	return seeds, nil
}

// buildFAPIClientSeeds returns the FAPI test-client seeds (and, for
// the fapi-ciba profile, a CIBA-only PrivateKeyJWTClient with no
// redirect URIs). Split out of [buildClientSeeds] so the parent stays
// under the gocognit budget.
func buildFAPIClientSeeds(cfg runConfig, postLogoutURIs []string) ([]op.ClientSeed, error) {
	fapiURIs := withFAPIDummyRedirectURIs(cfg.redirectURIs)
	seeds := make([]op.ClientSeed, 0, 3)
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
			ID:                     entry.id,
			JWKS:                   pub,
			RedirectURIs:           fapiURIs,
			Scopes:                 fapiScopeCatalog,
			PostLogoutRedirectURIs: postLogoutURIs,
		})
	}
	if isCIBAProfile(cfg.profile) {
		// CIBA clients never visit /authorize; redirect_uri MUST be
		// empty. The grant set is overridden so the registration
		// only carries the CIBA URN. Two clients are seeded so the
		// OFCS fapi-ciba "another-client-cannot-poll" / "another-
		// client-cannot-token" tests have a distinct second identity
		// to drive against; each reuses the matching FAPI JWKS so
		// OFCS can sign with the same private_key_jwt material.
		for _, entry := range []struct {
			id   string
			path string
		}{
			{"demo-fapi-ciba", cfg.fapiClient1JWKS},
			{"demo-fapi-ciba-2", cfg.fapiClient2JWKS},
		} {
			pub, err := op.LoadPublicJWKS(entry.path)
			if err != nil {
				return nil, fmt.Errorf("load JWKS %s: %w", entry.path, err)
			}
			seeds = append(seeds, op.PrivateKeyJWTClient{
				ID:         entry.id,
				JWKS:       pub,
				Scopes:     fapiScopeCatalog,
				GrantTypes: []string{opgrant.CIBA.String()},
			})
		}
	}
	return seeds, nil
}

// derivePostLogoutURIs maps each redirect_uri ending in "/callback"
// to the matching "/post_logout_redirect" URI and returns the
// resulting list. Inputs that do not end in "/callback" are dropped:
// they are not OFCS plan callbacks, so the OP has nothing principled
// to register for RP-initiated logout.
func derivePostLogoutURIs(redirectURIs []string) []string {
	const callbackSuffix = "/callback"
	const logoutSuffix = "/post_logout_redirect"
	out := make([]string, 0, len(redirectURIs))
	for _, u := range redirectURIs {
		if !strings.HasSuffix(u, callbackSuffix) {
			continue
		}
		out = append(out, strings.TrimSuffix(u, callbackSuffix)+logoutSuffix)
	}
	return out
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
