package oidcredis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/libraz/go-oidc-provider/op/store"
)

// MaxValueBytes is the upper bound the adapter enforces on serialised
// payload size. The cap protects the cache from an attacker pinning
// unbounded memory through interaction state or oversized JTIs. The
// limit is generous compared to typical payloads (PAR records and
// interaction state are well under 8 KiB in practice) but bounded so a
// runaway client cannot starve the tier.
const MaxValueBytes = 64 * 1024

// DefaultKeyPrefix is the namespace every key is rooted under unless
// the embedder supplies [WithKeyPrefix]. The prefix gives operators a
// single grep target when sharing a Redis instance with unrelated
// workloads and keeps the surface area for accidental key collisions
// minimal.
const DefaultKeyPrefix = "oidc:"

// Clock returns the wall-clock time the adapter uses to evaluate
// record expiry. It mirrors the inmem and SQL adapter's Clock interface
// so the three backends can be swapped without re-wiring construction.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// Now is the wall-clock fallback when no [WithClock] override is
// supplied. The forbidigo allow-list lives here because the adapter is
// a sub-module without access to internal/timex; embedders inject
// internal/timex.Clock through [WithClock].
//
//nolint:forbidigo // sub-module fallback; embedders override via WithClock(clock).
func (systemClock) Now() time.Time { return time.Now() }

// Option configures a [Store] at construction time. Options are
// applied in the order supplied; later calls take precedence.
type Option func(*config)

type config struct {
	dsn               string
	username          string
	password          string
	clock             Clock
	prefix            string
	tlsConfig         *tls.Config
	allowPlaintext    bool
	maxValueBytes     int
	plaintextWarnSink func(string)
}

// WithDSN supplies the Redis connection string. The scheme MUST be
// rediss:// (TLS) unless [WithDevModeAllowPlaintext] is also supplied.
// The DSN MAY embed a username and password, but [WithRedisAuth] takes
// precedence when both are present.
func WithDSN(dsn string) Option {
	return func(cfg *config) { cfg.dsn = dsn }
}

// WithRedisAuth injects the username and password the adapter uses to
// authenticate. Pass an empty username for password-only AUTH. At least
// one of (username, password) MUST be non-empty unless
// [WithDevModeAllowPlaintext] is enabled.
func WithRedisAuth(username, password string) Option {
	return func(cfg *config) {
		cfg.username = username
		cfg.password = password
	}
}

// WithClock injects the wall-clock implementation used to evaluate
// record expiry. The default is the system wall clock.
func WithClock(c Clock) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.clock = c
		}
	}
}

// WithKeyPrefix overrides the namespace prefix every key lives under.
// The default is [DefaultKeyPrefix]. Use this option when multiple OPs
// share a single Redis instance so their keyspaces remain disjoint.
// The prefix MUST end with a separator (typically ':') the embedder
// chooses; the adapter does not rewrite the supplied value.
func WithKeyPrefix(prefix string) Option {
	return func(cfg *config) {
		if prefix != "" {
			cfg.prefix = prefix
		}
	}
}

// WithTLSConfig overrides the *tls.Config the adapter uses for the
// rediss:// connection. The default is &tls.Config{MinVersion: TLS12}
// which trusts the system certificate pool. Embedders that pin a
// specific CA, present client certificates, or use SNI must supply
// their own *tls.Config here.
func WithTLSConfig(c *tls.Config) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.tlsConfig = c
		}
	}
}

// WithDevModeAllowPlaintext is the documented escape hatch that lets
// the adapter accept a redis:// (plaintext) DSN and start without
// authentication credentials. The option is named verbosely on purpose
// so it is impossible to enable accidentally; embedders that pass it
// receive a loud warning on the supplied sink (typically log.Default()).
//
// The option is intended for local development against a sandbox
// Redis. Production deployments MUST NOT supply it; CI configurations
// MAY supply it when targeting a throwaway container that is
// firewall-isolated from the rest of the network.
func WithDevModeAllowPlaintext(warnSink func(string)) Option {
	return func(cfg *config) {
		cfg.allowPlaintext = true
		if warnSink != nil {
			cfg.plaintextWarnSink = warnSink
		}
	}
}

// WithMaxValueBytes overrides the serialised-payload cap. The default
// is [MaxValueBytes] (64 KiB). Setting the cap below 1 KiB or above
// 1 MiB is rejected so embedders cannot accidentally remove the
// protection.
func WithMaxValueBytes(n int) Option {
	return func(cfg *config) {
		if n >= 1024 && n <= 1024*1024 {
			cfg.maxValueBytes = n
		}
	}
}

// Store is the Redis adapter. It satisfies [store.Store] for the
// volatile substores ([store.InteractionStore], [store.ConsumedJTIStore],
// and [store.SessionStore]); every other accessor returns
// a stub that panics on first call so misconfiguration surfaces loudly.
// The adapter is intended to be composed with
// [github.com/libraz/go-oidc-provider/op/storeadapter/composite] so
// that out-of-scope substores resolve to a different backend.
type Store struct {
	client        *redis.Client
	clock         Clock
	prefix        string
	maxValueBytes int

	interactionsImpl *interactionStore
	jtisImpl         *jtiStore
	sessionsImpl     *sessionStore
}

// New constructs a Store from the supplied options. New fails when:
//   - WithDSN is missing or supplies an unparseable URI;
//   - the DSN scheme is plaintext redis:// and dev mode is not enabled;
//   - WithRedisAuth is missing and dev mode is not enabled;
//   - the underlying redis client fails to PING within five seconds.
func New(ctx context.Context, opts ...Option) (*Store, error) {
	cfg := buildConfig(opts)
	parsed, err := validateConfig(cfg)
	if err != nil {
		return nil, err
	}
	rawOpts, err := buildClientOptions(cfg, parsed)
	if err != nil {
		return nil, err
	}
	if cfg.allowPlaintext && parsed.Scheme == "redis" {
		emitPlaintextWarning(cfg)
	}

	client := redis.NewClient(rawOpts)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("oidcredis: ping: %w", err)
	}

	s := &Store{
		client:        client,
		clock:         cfg.clock,
		prefix:        cfg.prefix,
		maxValueBytes: cfg.maxValueBytes,
	}
	s.interactionsImpl = newInteractionStore(s)
	s.jtisImpl = newJTIStore(s)
	s.sessionsImpl = newSessionStore(s)
	return s, nil
}

func buildConfig(opts []Option) *config {
	cfg := &config{
		clock:         systemClock{},
		prefix:        DefaultKeyPrefix,
		maxValueBytes: MaxValueBytes,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return cfg
}

func validateConfig(cfg *config) (*url.URL, error) {
	if cfg.dsn == "" {
		return nil, errors.New("oidcredis: WithDSN is required")
	}
	parsed, err := url.Parse(cfg.dsn)
	if err != nil {
		return nil, fmt.Errorf("oidcredis: parse DSN: %w", err)
	}
	if err := validateScheme(parsed.Scheme, cfg.allowPlaintext); err != nil {
		return nil, err
	}
	if !cfg.allowPlaintext && cfg.username == "" && cfg.password == "" {
		return nil, errors.New("oidcredis: WithRedisAuth is required (or supply WithDevModeAllowPlaintext)")
	}
	return parsed, nil
}

func buildClientOptions(cfg *config, parsed *url.URL) (*redis.Options, error) {
	rawOpts, err := redis.ParseURL(cfg.dsn)
	if err != nil {
		return nil, fmt.Errorf("oidcredis: parse DSN: %w", err)
	}
	// WithRedisAuth takes precedence over credentials embedded in the
	// DSN; supplying both is unusual and the option-supplied value is
	// the explicit one.
	if cfg.username != "" || cfg.password != "" {
		rawOpts.Username = cfg.username
		rawOpts.Password = cfg.password
	}
	if parsed.Scheme == "rediss" {
		if cfg.tlsConfig != nil {
			rawOpts.TLSConfig = cfg.tlsConfig
		} else if rawOpts.TLSConfig == nil {
			rawOpts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
	}
	return rawOpts, nil
}

func emitPlaintextWarning(cfg *config) {
	warn := cfg.plaintextWarnSink
	if warn == nil {
		warn = func(string) {}
	}
	warn("oidcredis: WithDevModeAllowPlaintext is enabled; AUTH and TLS are NOT being enforced. " +
		"This MUST NOT be used in production.")
}

// Close closes the underlying redis client connection pool.
func (s *Store) Close() error { return s.client.Close() }

// Client exposes the underlying *redis.Client for advanced operations
// such as health probes or custom Lua scripts. Embedders SHOULD treat
// this as a read-only handle: the adapter assumes ownership of the
// connection and will close it via [Store.Close].
func (s *Store) Client() *redis.Client { return s.client }

func validateScheme(scheme string, allowPlaintext bool) error {
	switch strings.ToLower(scheme) {
	case "rediss":
		return nil
	case "redis":
		if allowPlaintext {
			return nil
		}
		return errors.New("oidcredis: DSN scheme must be rediss:// (TLS); " +
			"set WithDevModeAllowPlaintext for local development only")
	default:
		return fmt.Errorf("oidcredis: unsupported DSN scheme %q (want rediss://)", scheme)
	}
}

// --- store.Store -------------------------------------------------------------

// Interactions returns the [store.InteractionStore] handle.
func (s *Store) Interactions() store.InteractionStore { return s.interactionsImpl }

// ConsumedJTIs returns the [store.ConsumedJTIStore] handle.
func (s *Store) ConsumedJTIs() store.ConsumedJTIStore { return s.jtisImpl }

// The accessors below return nil for substores the Redis adapter
// does not implement. Composite never calls them for a Kind routed
// elsewhere; embedders that wire Redis directly into [op.WithStore]
// rely on op.New's substore validation to surface a fail-fast
// configuration error rather than a runtime panic on the first
// request. Returning a "no-op" substore is intentionally avoided —
// silently issuing tokens that nothing remembers would be far
// worse than the construction-time rejection.
//
// The unified nil-return policy mirrors the existing
// InitialAccessTokens / RegistrationAccessTokens / OpaqueAccessTokens
// / GrantRevocations behaviour: every nil return surfaces at
// op.New through a substore presence check tied to the active
// grant / feature set.

// Clients implements [store.Store]; out-of-scope on Redis. Returns
// nil so op.New surfaces "ClientStore not implemented by store
// backend" before the first request lands.
func (s *Store) Clients() store.ClientStore { return nil }

// AuthorizationCodes implements [store.Store]; out-of-scope on
// Redis. Returns nil; op.New rejects the config when
// [grant.AuthorizationCode] is active without a backing substore.
func (s *Store) AuthorizationCodes() store.AuthorizationCodeStore { return nil }

// RefreshTokens implements [store.Store]; out-of-scope on Redis.
// Returns nil; op.New rejects the config when [grant.RefreshToken]
// (or any flow that issues refresh tokens) is active without a
// backing substore.
func (s *Store) RefreshTokens() store.RefreshTokenStore { return nil }

// Grants implements [store.Store]; out-of-scope on Redis. Returns
// nil; op.New rejects the config because every interactive grant
// type requires the substore.
func (s *Store) Grants() store.GrantStore { return nil }

// Metadata implements [store.Store] against a Redis hash. The
// substore is the persistence path for coarse construction-time
// decisions (subject_mode in v0.9.1; future keys compose on the
// same surface without further interface change).
func (s *Store) Metadata() store.MetadataStore { return newMetadataStore(s) }

// DeviceCodes implements [store.Store]; out-of-scope on Redis.
// Returns nil; op.New rejects the config when
// [grant.DeviceCode] is active without a backing substore.
func (s *Store) DeviceCodes() store.DeviceCodeStore { return nil }

// CIBARequests implements [store.Store]; out-of-scope on Redis.
// Returns nil; op.New rejects the config when [grant.CIBA] is
// active without a backing substore.
func (s *Store) CIBARequests() store.CIBARequestStore { return nil }

// Sessions returns the [store.SessionStore] handle. Sessions are an
// in-scope substore for the Redis adapter: the OP does not
// coordinate Session writes with token-endpoint commits, so a volatile
// cache is the appropriate backend. Embedders compose this accessor
// with the other Kinds via op/storeadapter/composite.
func (s *Store) Sessions() store.SessionStore { return s.sessionsImpl }

// PushedAuthRequests implements [store.Store]; out-of-scope on
// Redis. Returns nil; op.New rejects the config when [feature.PAR]
// is active without a backing substore.
func (s *Store) PushedAuthRequests() store.PushedAuthRequestStore { return nil }

// Users implements [store.Store]; out-of-scope on Redis. Returns
// nil; op.New rejects the config when an authenticator that needs
// the substore is wired without a backing implementation.
func (s *Store) Users() store.UserStore { return nil }

// InitialAccessTokens returns nil. See the accessor block doc.
func (s *Store) InitialAccessTokens() store.InitialAccessTokenStore { return nil }

// RegistrationAccessTokens returns nil. See the accessor block doc.
func (s *Store) RegistrationAccessTokens() store.RegistrationAccessTokenStore { return nil }

// AccessTokens implements [store.Store]; out-of-scope on Redis.
// Returns nil; op.New rejects the config when the JWT-AT registry
// or JWT revocation strategy is active without a backing substore.
func (s *Store) AccessTokens() store.AccessTokenRegistry { return nil }

// OpaqueAccessTokens implements [store.Store] (ADR 0024). Redis cannot
// host the transactional cluster on its own — the opaque-AT save must
// commit atomically alongside the grant write — so the accessor returns
// nil. The library detects the nil at op.New time when an embedder
// enables [op.WithAccessTokenFormat] (.../Opaque) without routing the
// substore to a transactional backend through composite, and surfaces
// a fail-fast configuration error instead of crashing on the first
// issuance. Embedders that want opaque tokens compose this adapter
// with op/storeadapter/composite + a SQL anchor.
func (s *Store) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return nil }

// GrantRevocations implements [store.Store] (ADR 0025). Redis cannot
// host the transactional cluster on its own — the tombstone /
// denylist write must commit atomically alongside the matching grant
// or refresh-token write — so the accessor returns nil. The library
// detects the nil at op.New time when an embedder selects the
// grant-tombstone strategy without routing the substore to a
// transactional backend through composite, and surfaces a fail-fast
// configuration error instead of crashing on the first revocation.
// Embedders that want JWT access-token revocation under the grant-
// tombstone strategy compose this adapter with
// op/storeadapter/composite + a SQL anchor.
func (s *Store) GrantRevocations() store.GrantRevocationStore { return nil }
