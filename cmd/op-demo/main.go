// Command op-demo runs a single-process OpenID Connect Provider
// suitable for manual inspection and the OpenID Foundation
// Conformance Suite.
//
// The binary is dev-only — it generates ephemeral signing and cookie
// keys at startup and terminates the OP cleanly on SIGINT / SIGTERM.
// It is not intended for production deployments.
//
// Storage is selected with -store. The default keeps every record in
// process memory, which needs nothing running alongside the binary and
// is what the automated conformance gate uses. -store=composite routes
// the durable substores to MySQL and the volatile ones to Redis, so a
// conformance run can also be captured against the storage shape a
// deployment actually runs rather than only against the in-memory
// reference implementation. See storage.go.
//
// Quick start (HTTP):
//
//	go run ./cmd/op-demo \
//	    -listen 127.0.0.1:9090 \
//	    -issuer http://127.0.0.1:9090 \
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
// To run a specific OFCS plan, pair the binary with the matching
// -profile flag. The wiring each profile activates lives in its own
// file so an implementer reproducing OFCS reads one place per plan:
//
//	-profile=fapi2-baseline         → cmd/op-demo/profile_fapi2.go
//	-profile=fapi2-message-signing  → cmd/op-demo/profile_fapi2.go
//	-profile=fapi-ciba              → cmd/op-demo/profile_fapi_ciba.go
//
// The reproduce recipe (which OFCS test plan, which alias, which
// op-demo flags) lives at
// https://go-oidc-provider.libraz.net/compliance/ofcs-reproduce.
//
// In production embedders read keys from a vault / KMS; this binary
// generates them at startup so the moving parts stay visible.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

// shutdownGrace is the deadline for in-flight requests to drain after
// the demo receives SIGINT or SIGTERM. The value is short on purpose:
// op-demo is a development binary, not a production OP, so a long
// grace period would only mask hung handlers during conformance runs.
const shutdownGrace = 5 * time.Second

const defaultListenAddr = "127.0.0.1:9090"

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
	// storeBackend selects the storage the OP runs on: "inmem" (the
	// default) or "composite" (durable substores on MySQL, volatile ones
	// on Redis). The flag exists so a conformance run can be captured
	// against the storage shape a deployment runs rather than only
	// against the in-memory reference implementation. See storage.go.
	storeBackend string
	// mysqlDSN / redisDSN are consulted only when storeBackend is
	// "composite".
	mysqlDSN string
	redisDSN string
	// extraCAs is the trust pool the JWKS fetcher uses for outbound
	// HTTPS to RP-controlled jwks_uri endpoints. Nil means "use the
	// Go default system trust store"; embedders running against the
	// OFCS conformance harness or behind an internal CA load PEM
	// bundles via -extra-ca-bundle so the fetcher accepts those
	// certs without disabling chain validation.
	extraCAs *x509.CertPool
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
		listen      = flag.String("listen", defaultListenAddr, "TCP listen address (\"host:port\" or \":port\")")
		issuer      = flag.String("issuer", "http://127.0.0.1:9090", "issuer URL — use http:// only for a loopback IP listener without TLS; otherwise use https://")
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
		confClientSec = flag.String("confidential-client-secret", "demo-confidential-secret-32-bytes-min", "client_secret for the confidential seed client. Empty disables the confidential seed. The default is sized at 36 bytes (>= 32) so OFCS modules that derive an HS256-signed JWT from the secret (e.g. oidcc-rp-initiated-logout-bad-id-token-hint, which signs an id_token_hint with HS256) can satisfy RFC 7518 §3.2's 256-bit key requirement.")
		profileFlag   = flag.String("profile", "", "security profile to activate. One of: \"\" (no profile, vanilla OIDC Core), \"baseline\" (OAuth 2.1, PKCE required), \"fapi2-baseline\", \"fapi2-message-signing\", \"fapi-ciba\". Profiles auto-enable the features they require (PAR, DPoP, JAR).")
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
		cibaAutoApproveDelay = flag.Duration("ciba-autoapprove-delay", 15*time.Second, "delay before the auto-approving CIBA substore flips a Pending record to Approved. Only consulted when -profile=fapi-ciba; production embedders trigger Approve from the user's authentication device callback, never from inside the OP. The default is sized so the OFCS fapi-ciba poll loop sees authorization_pending on at least three consecutive polls before the flip — the test plan asserts on that intermediate state explicitly.")
		// extraCABundle is a colon-separated list of PEM files merged
		// into the JWKS fetcher's trust pool. Empty leaves Go's system
		// trust store untouched.
		extraCABundle = flag.String("extra-ca-bundle", "", "colon-separated PEM file paths merged into the JWKS fetcher's TLS trust pool. Empty leaves Go's system trust store untouched. Used to reach RP JWKS endpoints behind an internal CA, or — under the OFCS conformance harness — to admit the runner's self-signed cert without disabling chain validation.")

		// -store selects the storage the OP runs on. The in-memory
		// default needs nothing running alongside the binary; the
		// composite backend exists so a conformance run can be captured
		// against the MySQL + Redis split a deployment actually runs.
		storeBackend = flag.String("store", storeInmem, "storage backend: \"inmem\" (in-process, nothing to run alongside) or \"composite\" (durable substores on MySQL, volatile ones on Redis). The composite backend exists so a conformance run can be captured against deployment-shaped storage; it consults -mysql-dsn and -redis-dsn.")
		mysqlDSN     = flag.String("mysql-dsn", "opdemo:opdemo@tcp(127.0.0.1:3306)/opdemo?parseTime=true&charset=utf8mb4&loc=UTC", "MySQL DSN for -store=composite. Only consulted when -store=composite.")
		redisDSN     = flag.String("redis-dsn", "redis://127.0.0.1:6379/0", "Redis DSN for -store=composite. Only consulted when -store=composite. A plaintext redis:// DSN is admitted only for a loopback engine, which is the development arrangement this binary is for; anything further away must use rediss://.")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := loadCABundles(*extraCABundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "op-demo: %v\n", err)
		return err
	}

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
		storeBackend:         *storeBackend,
		mysqlDSN:             *mysqlDSN,
		redisDSN:             *redisDSN,
		extraCAs:             pool,
	}
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("op-demo: fatal", "err", err)
		return err
	}
	return nil
}

func run(ctx context.Context, cfg runConfig, logger *slog.Logger) error {
	if err := validateRunConfig(cfg); err != nil {
		return err
	}

	provider, closeBackend, err := buildProvider(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closeBackend()

	// Non-CIBA profiles serve the bare provider so the listener layout
	// is the minimal shape an embedder would copy. Under -profile=fapi-ciba
	// the OFCS runner needs the /_test/ciba-mode override (see
	// profile_fapi_ciba_testmode.go) so a thin mux wraps the provider
	// just for that case. The /_test/ surface is dev-only — production
	// embedders MUST NOT mount it.
	var handler http.Handler = provider
	if isCIBAProfile(cfg.profile) {
		mux := http.NewServeMux()
		mux.Handle("/_test/ciba-mode", CIBATestModeHandler())
		mux.Handle("/", provider)
		handler = mux
	}

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if isFAPIProfile(cfg.profile) {
		srv.TLSConfig = op.FAPITLSConfig()
		// RequestClientCert (not RequireAndVerifyClientCert) so the OP
		// admits requests without a cert — discovery / interaction
		// pages stay accessible. RFC 8705 §3 binding fires only when a
		// cert IS presented; the OFCS fapi-ciba plan presents one on
		// every backchannel and token request, while bearer-only
		// flows (oidcc-* plans sharing the same listener) keep working.
		// Chain validation is intentionally skipped: the binding path
		// only needs the leaf for the x5t#S256 thumbprint.
		srv.TLSConfig.ClientAuth = tls.RequestClientCert
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

// validateRunConfig rejects listener and issuer combinations that would make
// the discovery document advertise a transport the server does not provide.
// The Provider validates the issuer's full OIDC shape later; this check owns
// only the demo server's TLS/listener coherence.
func validateRunConfig(cfg runConfig) error {
	if (cfg.tlsCert == "") != (cfg.tlsKey == "") {
		return errors.New("op-demo: -tls-cert and -tls-key must be provided together")
	}
	if len(cfg.redirectURIs) == 0 {
		return errors.New("op-demo: -redirect-uri must list at least one URI")
	}
	issuerURL, err := url.Parse(cfg.issuer)
	if err != nil || issuerURL.Scheme == "" {
		return errors.New("op-demo: -issuer must be an absolute http:// or https:// URL")
	}
	tlsEnabled := cfg.tlsCert != ""
	switch {
	case tlsEnabled && issuerURL.Scheme != "https":
		return errors.New("op-demo: an HTTPS issuer is required when -tls-cert and -tls-key are set")
	case !tlsEnabled && issuerURL.Scheme != "http":
		return errors.New("op-demo: an HTTP issuer is required when serving without TLS")
	}
	return nil
}

// buildProvider performs every construction step run() needs before
// it can hand the resulting handler to net/http: ephemeral key
// generation, store connection and seeding, optional CIBA store
// wrapping, op.New invocation, and the optional Initial Access Token
// mint when -enable-dcr is set. Split out of run() so the parent stays
// under the gocognit budget.
//
// The returned close function releases whatever the backend holds. It
// is a no-op for the in-memory default and closes the MySQL and Redis
// connections under -store=composite, so the caller defers it without
// having to know which backend it got.
func buildProvider(ctx context.Context, cfg runConfig, logger *slog.Logger) (*op.Provider, func(), error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing key: %w", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return nil, nil, fmt.Errorf("generate cookie key: %w", err)
	}

	backend, err := openBackend(ctx, cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	provider, err := buildProviderOn(ctx, cfg, backend, priv, cookieKey, logger)
	if err != nil {
		backend.close()
		return nil, nil, err
	}
	return provider, backend.close, nil
}

// buildProviderOn is the part of construction that runs once storage is
// live. It is separate so buildProvider owns the backend's lifetime and
// this half can return an error without repeating the teardown.
func buildProviderOn(
	ctx context.Context,
	cfg runConfig,
	backend demoBackend,
	priv *ecdsa.PrivateKey,
	cookieKey []byte,
	logger *slog.Logger,
) (*op.Provider, error) {
	if err := seedDemoUser(ctx, backend.seed); err != nil {
		return nil, fmt.Errorf("seed demo user: %w", err)
	}
	opStore, err := buildOPStore(ctx, cfg, backend.store, logger)
	if err != nil {
		return nil, err
	}
	opts, err := buildOptions(ctx, cfg, backend.users, opStore, priv, cookieKey, logger)
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
// The shape is "common base + profile-specific extras + DCR opt-in".
// Profile-specific wiring is dispatched to per-profile files so each
// plan's full configuration is readable in one place:
//
//   - fapi2-baseline / fapi2-message-signing → profile_fapi2.go
//   - fapi-ciba → profile_fapi_ciba.go
//
// opStore is the [store.Store] passed to [op.WithStore] — the backend's
// store, optionally wrapped by [cibaAutoApproveStore] when
// -profile=fapi-ciba is active. users is carried alongside it because
// [op.PrimaryPassword] needs a [store.UserPasswordStore] and that
// accessor is deliberately absent from the store.Store interface.
func buildOptions(ctx context.Context, cfg runConfig, users store.UserPasswordStore, opStore store.Store, priv *ecdsa.PrivateKey, cookieKey []byte, logger *slog.Logger) ([]op.Option, error) {
	seeds, err := buildClientSeeds(cfg)
	if err != nil {
		return nil, err
	}
	opts := commonOptions(cfg, opStore, users, priv, cookieKey, logger, seeds)
	profileOpts, err := profileOptions(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	opts = append(opts, profileOpts...)
	if cfg.enableDCR {
		// Open registration is required because the OFCS oidcc-dynamic
		// and oidcc-back-channel-rp-initiated-logout plans POST to
		// /register without supplying an Initial Access Token; OFCS
		// itself has no slot in the plan template for one. Op-demo is
		// a developer binary, not a production deployment, so the
		// open-registration trade-off (higher pre-auth surface, audit
		// log noise) is acceptable here. Production embedders MUST
		// leave [op.RegistrationOption.Open] at false and gate
		// registration with the [Provider.IssueInitialAccessToken]
		// flow op-demo prints to stdout below; the 24 h TTL and
		// single-use cap keep that path usable for manual operator
		// testing of the IAT-required dialect.
		opts = append(opts, op.WithDynamicRegistration(op.RegistrationOption{
			Open:    true,
			IATTTL:  24 * time.Hour,
			IATUses: 1,
			// OFCS oidcc-dynamic POSTs to /register without a scope
			// field and then runs /authorize with the OP's full
			// catalog. Mirror op-demo's published scope set here so
			// the conformance plan keeps working without the RP
			// having to spell scopes out at register time.
			// Production embedders SHOULD leave this empty and
			// either issue IATs (whose AllowedScopes restriction
			// wins over the open default) or instruct RPs to
			// request scopes explicitly during DCR.
			OpenRegistrationDefaultScopes: append([]string(nil), scopeCatalog...),
		}))
	}
	return opts, nil
}

// commonOptions returns the [op.Option] slice every profile shares —
// issuer, store, keyset, cookie key, mount prefix, logger, the static
// client seeds, the LoginFlow with PrimaryPassword, JAR, and the
// claims_supported list. Profile-specific options are appended on top
// in [buildOptions].
func commonOptions(cfg runConfig, opStore store.Store, users store.UserPasswordStore, priv *ecdsa.PrivateKey, cookieKey []byte, logger *slog.Logger, seeds []op.ClientSeed) []op.Option {
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
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: users}}),
		// JAR (RFC 9101) is opt-in for non-FAPI profiles. Enabling
		// it makes discovery advertise
		// request_object_signing_alg_values_supported (without
		// "none"), which lets the OFCS unsigned-request-object
		// module skip cleanly while keeping the signed path live
		// for the redirect-uri-in-request-object module. WithProfile
		// auto-enables JAR for FAPI 2.0; calling WithFeature here is
		// idempotent under the auto-enable contract.
		op.WithFeature(feature.JAR),
		// OFCS hosts the runner-side JWKS / request_uri endpoints at
		// localhost.emobix.co.uk, which resolves to 127.0.0.1 via the
		// OFCS-provided /etc/hosts entry. The JWKS fetcher's default
		// posture rejects loopback / RFC 1918 hosts to neutralise SSRF
		// attacks via attacker-controlled jwks_uri values; the
		// conformance harness is the documented exception, so the
		// demo opts in to the relaxed deny-list. A production OP MUST
		// NOT enable this.
		op.WithAllowPrivateNetworkJWKS(),
		op.WithAllowPrivateNetworkJAR(),
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
	if cfg.extraCAs != nil {
		// The transport is constructed locally so the dial-time SSRF
		// gate the JWKS fetcher relies on can rewire DialContext on a
		// fresh *http.Transport rather than mutating
		// http.DefaultTransport.
		//
		// OFCS publishes its RP-side jwks_uri / request_uri endpoints at
		// https://localhost.emobix.co.uk:8443, but the runner's nginx
		// serves a self-signed certificate whose subject is CN=localhost
		// with no subjectAltName. A default TLS dial therefore fails
		// hostname verification ("localhost" != "localhost.emobix.co.uk")
		// before the OP can fetch a dynamically registered client's keys,
		// and the oidcc-registration-jwks-uri /
		// oidcc-refresh-token-rp-key-rotation modules surface only as a
		// token-endpoint 401. chainOnlyTLSConfig keeps full chain
		// validation against the pinned OFCS CA and drops just the DNS
		// name match — a dev-only accommodation for the conformance rig.
		opts = append(opts, op.WithJWKSHTTPTransport(&http.Transport{
			TLSClientConfig: chainOnlyTLSConfig(cfg.extraCAs),
		}))
	}
	return opts
}

// chainOnlyTLSConfig returns a client TLS config that verifies the peer
// certificate chain against pool but skips the DNS hostname match. It
// exists solely for the OFCS conformance harness, whose nginx serves a
// SAN-less CN=localhost certificate on the localhost.emobix.co.uk vhost
// (see the call site). InsecureSkipVerify disables Go's built-in
// verification — which bundles the hostname check — and
// VerifyPeerCertificate reinstates full chain validation against pool
// without a DNSName, so trust stays anchored to the pinned CA. A
// production OP MUST verify the hostname and MUST NOT set this.
func chainOnlyTLSConfig(pool *x509.CertPool) *tls.Config {
	// VerifyConnection (rather than VerifyPeerCertificate) so the manual
	// chain check also runs on a resumed TLS session — a resumed handshake
	// would otherwise skip VerifyPeerCertificate and bypass the pin.
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("op-demo: no peer certificate presented")
		}
		intermediates := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
		})
		return err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            pool,
		InsecureSkipVerify: true, //nolint:gosec // chain verified in VerifyConnection; only the hostname match is dropped for the dev-only OFCS rig
		VerifyConnection:   verify,
	}
}

// profileOptions dispatches to the per-profile helper that returns the
// options that profile activates. Returns nil for the empty / "basic"
// profile (the common base IS the basic configuration).
func profileOptions(ctx context.Context, cfg runConfig, logger *slog.Logger) ([]op.Option, error) {
	switch cfg.profile {
	case "", "basic":
		return nil, nil
	case "baseline":
		// The OAuth 2.1 posture needs no supporting wiring: its only
		// mandate is PKCE on every authorization-code request, which
		// the common base already satisfies for the demo clients.
		return []op.Option{op.WithProfile(profile.Baseline)}, nil
	case "fapi2-baseline":
		return fapi2BaselineOptions(), nil
	case "fapi2-message-signing":
		return fapi2MessageSigningOptions(ctx, logger)
	case "fapi-ciba":
		return fapiCIBAOptions(), nil
	default:
		return nil, fmt.Errorf("op-demo: unknown -profile %q (expected one of: basic, baseline, fapi2-baseline, fapi2-message-signing, fapi-ciba)", cfg.profile)
	}
}

// buildOPStore returns the [store.Store] handed to [op.WithStore].
// For non-CIBA profiles this is the bare [*inmem.Store]; for the
// fapi-ciba profile it is wrapped so Save schedules an out-of-band
// approval — see [wrapStoreForCIBA] in profile_fapi_ciba.go.
func buildOPStore(
	ctx context.Context,
	cfg runConfig,
	base store.Store,
	logger *slog.Logger,
) (store.Store, error) {
	if !isCIBAProfile(cfg.profile) {
		return base, nil
	}
	return wrapStoreForCIBA(ctx, cfg, base, logger)
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

// profileFor translates the -profile flag into a [profile.Profile] the
// op.WithProfile option accepts. Returns 0 (the "no profile" sentinel)
// for the empty/"basic" case so the OP runs vanilla OIDC Core. Used
// only by tests; the runtime path goes through profileOptions, which
// builds the option directly from the per-profile helper.
func profileFor(name string) (profile.Profile, error) {
	switch name {
	case "", "basic":
		return 0, nil
	case "baseline":
		return profile.Baseline, nil
	case "fapi2-baseline":
		return profile.FAPI2Baseline, nil
	case "fapi2-message-signing":
		return profile.FAPI2MessageSigning, nil
	case "fapi-ciba":
		return profile.FAPICIBA, nil
	default:
		return 0, fmt.Errorf("op-demo: unknown -profile %q (expected one of: basic, baseline, fapi2-baseline, fapi2-message-signing, fapi-ciba)", name)
	}
}

// scopeCatalog is the OIDC Core scope set every demo client is
// registered to request. The list is shared rather than duplicated so
// a future scope addition lands across all seeds in one place.
//
//nolint:gochecknoglobals // immutable demo seed; no per-instance tuning.
var scopeCatalog = []string{"openid", "profile", "email", "address", "phone", "offline_access"}

// buildClientSeeds projects the runConfig onto the typed
// [op.ClientSeed] slice [op.WithStaticClients] consumes. The function
// returns the common seeds (public + confidential trio) and dispatches
// to per-profile helpers for FAPI / CIBA additions.
func buildClientSeeds(cfg runConfig) ([]op.ClientSeed, error) {
	postLogoutURIs := derivePostLogoutURIs(cfg.redirectURIs)
	seeds := commonClientSeeds(cfg, postLogoutURIs)
	extras, err := profileClientSeeds(cfg, postLogoutURIs)
	if err != nil {
		return nil, err
	}
	return append(seeds, extras...), nil
}

// commonClientSeeds returns the public demo client and (when
// configured) the confidential client trio that the non-FAPI profiles
// share. FAPI profiles get nothing here: their only conformant auth
// methods are private_key_jwt and mTLS, so a public (none) or
// client_secret_* static seed is rejected by op.New at construction
// under an active FAPI profile. The FAPI plans drive the dedicated
// confidential clients from fapi2ClientSeeds instead.
func commonClientSeeds(cfg runConfig, postLogoutURIs []string) []op.ClientSeed {
	if isFAPIProfile(cfg.profile) {
		return nil
	}
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
	return seeds
}

// profileClientSeeds dispatches to the per-profile seed helper so
// FAPI / CIBA additions live with their respective profile wiring.
// The FAPI 2.0 plans (Baseline + Message Signing) share the same
// client set; FAPI-CIBA layers two CIBA-only clients on top.
func profileClientSeeds(cfg runConfig, postLogoutURIs []string) ([]op.ClientSeed, error) {
	switch cfg.profile {
	case "fapi2-baseline", "fapi2-message-signing":
		return fapi2ClientSeeds(cfg, postLogoutURIs)
	case "fapi-ciba":
		fapiSeeds, err := fapi2ClientSeeds(cfg, postLogoutURIs)
		if err != nil {
			return nil, err
		}
		cibaSeeds, err := fapiCIBAClientSeeds(cfg)
		if err != nil {
			return nil, err
		}
		return append(fapiSeeds, cibaSeeds...), nil
	}
	return nil, nil
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
// put writes the seed through whichever backend is live. A durable
// backend re-seeds the same subject on every start, which is why the
// closure is an upsert on both sides rather than an insert.
func seedDemoUser(ctx context.Context, put func(context.Context, *store.User, string, []byte) error) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return fmt.Errorf("hash demo password: %w", err)
	}
	updatedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return put(ctx, &store.User{
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
}

// loadCABundles merges the system trust store with every PEM file in
// raw (colon-separated, mirroring SSL_CERT_FILE conventions). Empty
// raw returns nil so the OP keeps the package-default behaviour
// (system trust store via [crypto/tls]'s lazy initialisation). Each
// supplied path MUST contain at least one PEM-encoded certificate; a
// silent miss would defeat the whole point of the flag.
func loadCABundles(raw string) (*x509.CertPool, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil //nolint:nilnil // documented "no extra CAs" signal.
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// SystemCertPool returns (nil, error) on Windows pre-Go 1.18;
		// fall back to a fresh pool so the embedder's bundle is still
		// honoured without crashing op-demo.
		pool = x509.NewCertPool()
	}
	for _, path := range strings.Split(raw, ":") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		pem, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied dev flag.
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %q: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA bundle %q contained no valid PEM certificates", path)
		}
	}
	return pool, nil
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
