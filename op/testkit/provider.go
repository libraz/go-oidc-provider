package testkit

import (
	"crypto"
	"crypto/rand"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// cookieKeyLen is the AES-256-GCM key length the cookie codec expects. The
// constant is duplicated here so the testkit need not import the internal
// cookie package.
const cookieKeyLen = 32

// DefaultIssuer is the issuer URL the testkit advertises in the discovery
// document when the caller does not override it. It is a fixed RFC 2606
// reserved hostname so RP test fixtures depending on the issuer string
// remain stable across test runs.
const DefaultIssuer = "https://op.testkit.invalid"

// DefaultKeyID is the kid stamped on the testkit's signing key when the
// caller does not override it. Tests that hard-code a kid for verifying
// id_tokens or signed assertions can rely on this value.
const DefaultKeyID = "testkit-active"

// Provider bundles the [op.Provider] under test with the supporting
// infrastructure tests usually need: the [httptest.Server] hosting it, the
// in-memory [inmem.Store] tests use to seed clients and sessions, and the
// active signing key so tests can verify [op.Provider]-emitted tokens.
//
// All fields are exported so tests can reach the underlying machinery
// directly. Provider is owned by the test that calls [NewProvider]; the
// httptest server is closed automatically via [testing.TB.Cleanup].
type Provider struct {
	// OP is the wired provider returned by [op.New]. It is also the
	// [http.Handler] backing [Provider.Server].
	OP *op.Provider

	// Server is an [httptest.Server] that ServeHTTPs against [Provider.OP].
	// Tests should issue HTTP requests against [Provider.Server.URL]; the
	// server is torn down by the cleanup registered in [NewProvider].
	Server *httptest.Server

	// Store is the in-memory store wired into [Provider.OP]. Tests may
	// register clients and seed sessions on it directly.
	Store *inmem.Store

	// Issuer is the discovery document issuer the OP advertises. It is
	// always an absolute https:// URL; defaults to [DefaultIssuer].
	Issuer string

	// SigningKey is the active ECDSA P-256 signer the OP uses for
	// id_tokens and other JWS output. The same key is exposed through
	// the JWKS endpoint so RP test code can verify what the OP signed.
	SigningKey op.SigningKey
}

// providerConfig is the testkit-side configuration assembled by [Option]
// values before construction. It is intentionally tiny: the testkit does
// not try to mirror every [op.Option]; instead it composes a sensible
// default set and lets callers append their own options through
// [WithOptions].
type providerConfig struct {
	issuer string
	kid    string
	clock  op.Clock
	extra  []op.Option
}

// Option configures a [NewProvider] call.
type Option func(*providerConfig)

// WithIssuer overrides the default issuer URL the testkit advertises.
// The supplied value MUST satisfy the [op.WithIssuer] requirements
// (absolute https URL, no query, no fragment).
func WithIssuer(issuer string) Option {
	return func(c *providerConfig) { c.issuer = issuer }
}

// WithKeyID overrides the kid stamped on the testkit's generated signing
// key. Tests that hard-code a kid for verification can use this to keep
// their fixtures stable across testkit revisions.
func WithKeyID(kid string) Option {
	return func(c *providerConfig) { c.kid = kid }
}

// WithClock injects a deterministic clock so the OP's expiry calculations
// share the test's notion of "now". Without this the OP uses a real wall
// clock, which is fine for assertions about endpoint shape but flaky for
// assertions that involve token lifetimes.
func WithClock(clock op.Clock) Option {
	return func(c *providerConfig) { c.clock = clock }
}

// WithOptions appends extra [op.Option] values to the ones the testkit
// passes to [op.New]. The supplied options are applied AFTER the defaults
// the testkit installs, so they can override any of them.
func WithOptions(opts ...op.Option) Option {
	return func(c *providerConfig) {
		c.extra = append(c.extra, opts...)
	}
}

// NewProvider builds a fully wired [Provider] for use in tests. It registers
// a cleanup that closes the underlying [httptest.Server] when the test
// finishes. The returned Provider is non-nil; failures fail the test via
// [testing.TB.Fatalf] before returning.
func NewProvider(tb testing.TB, opts ...Option) *Provider {
	tb.Helper()
	cfg := &providerConfig{
		issuer: DefaultIssuer,
		kid:    DefaultKeyID,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	signKey := generateSigningKey(tb, cfg.kid)
	var storeOpts []inmem.Option
	if cfg.clock != nil {
		storeOpts = append(storeOpts, inmem.WithClock(cfg.clock))
	}
	store := inmem.New(storeOpts...)

	baseOpts := []op.Option{
		op.WithIssuer(cfg.issuer),
		op.WithStore(store),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKey(generateCookieKey(tb)),
		op.WithInteraction(AutoConsentDriver{}),
		op.WithAuthenticators(SubjectAuthenticator{}),
	}
	if cfg.clock != nil {
		baseOpts = append(baseOpts, op.WithClock(cfg.clock))
	}
	// cfg.extra is appended last so caller-supplied options can override
	// any default the testkit installed (cookie keys, driver, clock, ...).
	baseOpts = append(baseOpts, cfg.extra...)

	provider, err := op.New(baseOpts...)
	if err != nil {
		tb.Fatalf("testkit: op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	tb.Cleanup(srv.Close)

	return &Provider{
		OP:         provider,
		Server:     srv,
		Store:      store,
		Issuer:     cfg.issuer,
		SigningKey: signKey,
	}
}

// generateSigningKey returns a fresh ECDSA P-256 signer wrapped in
// [op.SigningKey]. It exists so the testkit can stay in the public op/
// namespace without importing crypto/rand directly (the linter restricts
// crypto/rand to a small allow-list).
func generateSigningKey(tb testing.TB, kid string) op.SigningKey {
	tb.Helper()
	entry, err := keys.GenerateES256(kid)
	if err != nil {
		tb.Fatalf("testkit: generate signing key: %v", err)
	}
	return op.SigningKey{KeyID: entry.KeyID, Signer: entry.Signer}
}

// generateCookieKey returns a fresh 32-byte cookie key suitable for
// satisfying [op.WithCookieKey]. The key is generated per [NewProvider]
// call so parallel tests do not share secret material.
func generateCookieKey(tb testing.TB) []byte {
	tb.Helper()
	key := make([]byte, cookieKeyLen)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("testkit: generate cookie key: %v", err)
	}
	return key
}

// Signer returns the [crypto.Signer] backing the active signing key.
// Tests that need to construct test JWTs (for example, to feed back into
// the OP as a signed request object) can call [Signer] to obtain the
// private key.
func (p *Provider) Signer() crypto.Signer { return p.SigningKey.Signer }
