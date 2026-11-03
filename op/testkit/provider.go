package testkit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// trustOnce adds the testkit's TLS certificate to [http.DefaultTransport]'s
// root pool once per test process, so helpers calling [http.DefaultClient.Do]
// reach the HTTPS server. Later [NewProvider] calls find the pool in place.
var trustOnce sync.Once //nolint:gochecknoglobals // testkit-internal one-shot trust install; safe by sync.Once.

func ensureTrust(srv *httptest.Server) {
	trustOnce.Do(func() {
		cert := srv.Certificate()
		if cert == nil {
			return
		}
		rt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return
		}
		// Force net/http's internal nextProtoOnce to fire before we
		// mutate TLSClientConfig. CloseIdleConnections triggers
		// http2configureTransports through that once, which itself
		// writes TLSClientConfig.NextProtos. Without this nudge, a
		// parallel httptest.Server.Close (which also calls
		// http.DefaultTransport.CloseIdleConnections) can race with
		// the trust install: both code paths mutate the same struct
		// without a shared happens-before edge. Running the once
		// inside trustOnce.Do establishes that edge so all subsequent
		// CloseIdleConnections calls observe the same NextProtos
		// state and skip the inner once.
		rt.CloseIdleConnections()
		if rt.TLSClientConfig == nil {
			rt.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if rt.TLSClientConfig.RootCAs == nil {
			rt.TLSClientConfig.RootCAs = x509.NewCertPool()
		}
		rt.TLSClientConfig.RootCAs.AddCert(cert)
	})
}

// cookieKeyLen is the AES-256-GCM key length the cookie codec expects.
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
	alg    op.SigningAlgorithm
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

// WithSigningAlgorithm selects the algorithm the provider signs with.
// [op.AlgRS256] makes the testkit keyset an RSA 2048 key (generated once
// per process) and passes [op.WithSigningAlgorithm] to [op.New]; the
// default stays ES256.
//
// Stable since v1.5.
func WithSigningAlgorithm(alg op.SigningAlgorithm) Option {
	return func(c *providerConfig) { c.alg = alg }
}

// WithOptions appends extra [op.Option] values to the ones the testkit
// passes to [op.New]. The testkit passes its own settings through
// [op.WithDefaults], so a supplied option replaces the matching default.
func WithOptions(opts ...op.Option) Option {
	return func(c *providerConfig) {
		c.extra = append(c.extra, opts...)
	}
}

// MinimalOptions returns the smallest [op.Option] slice that satisfies
// the constructor's required-field gates (Issuer / Store / Keyset /
// CookieKeys / InteractionDriver / LoginFlow) plus any extras the
// caller appends. The helper is the construction-time analog of
// [NewProvider] for tests that exercise [op.New]'s rejection paths
// directly: pass a deliberately invalid extra and assert the returned
// error type. The signing key is generated freshly on every call so
// parallel tests do not share secret material.
func MinimalOptions(tb testing.TB, extra ...op.Option) []op.Option {
	tb.Helper()
	defaults := defaultOptions(tb, DefaultIssuer, inmem.New(), generateSigningKey(tb, DefaultKeyID), SubjectAuthenticator{})
	out := make([]op.Option, 0, 1+len(extra))
	out = append(out, op.WithDefaults(defaults...))
	return append(out, extra...)
}

// defaultOptions is the required-field option list shared by
// [MinimalOptions] and [NewProvider]; callers wrap it in [op.WithDefaults]
// so a caller-supplied option replaces the matching one.
func defaultOptions(tb testing.TB, issuer string, st *inmem.Store, signKey op.SigningKey, auth op.Authenticator) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithUserStore(st.Users()),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKeys(generateCookieKey(tb)),
		op.WithInteractionDriver(AutoConsentDriver{}),
		subjectLoginFlow(auth),
	}
}

// subjectLoginFlow is the [op.WithLoginFlow] option whose only step is
// auth, the testkit's subject-echoing authenticator.
func subjectLoginFlow(auth op.Authenticator) op.Option {
	return op.WithLoginFlow(op.LoginFlow{Primary: op.ExternalStep{
		Authenticator: auth,
		KindLabel:     op.StepKind(auth.Type()),
	}})
}

// NewProvider builds a fully wired [Provider] for use in tests. It registers
// a cleanup that closes the underlying [httptest.Server] when the test
// finishes. Its [SubjectAuthenticator] puts each subject it logs in into
// [Provider.Store] as a minimal user record unless the test already
// seeded that subject, because the token endpoint refuses to redeem for
// a subject the user store cannot find. A caller that replaces the store
// through [WithOptions] seeds its own users and passes op.WithUserStore. The returned Provider is non-nil; failures fail the test via
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

	var signKey op.SigningKey
	if cfg.alg == op.AlgRS256 {
		signKey = rs256SigningKey(tb, cfg.kid)
	} else {
		signKey = generateSigningKey(tb, cfg.kid)
	}
	var storeOpts []inmem.Option
	if cfg.clock != nil {
		storeOpts = append(storeOpts, inmem.WithClock(cfg.clock))
	}
	store := inmem.New(storeOpts...)

	defaults := defaultOptions(tb, cfg.issuer, store, signKey, seedingSubjectAuthenticator{users: store})
	if cfg.clock != nil {
		defaults = append(defaults, op.WithClock(cfg.clock))
	}
	// The testkit's settings are defaults, so a caller-supplied option
	// replaces the matching one (cookie keys, driver, clock, ...).
	if cfg.alg == op.AlgRS256 {
		defaults = append(defaults, op.WithSigningAlgorithm(op.AlgRS256))
	}
	provider, err := op.New(append([]op.Option{op.WithDefaults(defaults...)}, cfg.extra...)...)
	if err != nil {
		tb.Fatalf("testkit: op.New: %v", err)
	}
	// httptest.NewTLSServer (rather than NewServer) so the OP serves over
	// HTTPS: the cookie codec marks __Host- cookies Secure, which a
	// cookie jar does not store from a plain-HTTP response.
	srv := httptest.NewTLSServer(provider)
	tb.Cleanup(srv.Close)
	// Make http.DefaultClient trust the testkit cert so legacy test
	// helpers that call DefaultClient.Do continue to work.
	ensureTrust(srv)

	return &Provider{
		OP:         provider,
		Server:     srv,
		Store:      store,
		Issuer:     cfg.issuer,
		SigningKey: signKey,
	}
}

// HTTPClient returns an [*http.Client] preconfigured to call the
// testkit server: it trusts the server's self-signed certificate and
// disables redirect following so each hop can be inspected (the
// universal end-to-end pattern). Pass jar=nil to skip cookie storage.
//
// Each call returns a fresh [*http.Client] backed by the
// [httptest.Server]'s pinned Transport, so concurrent tests do not
// share Jar / CheckRedirect mutations.
func (p *Provider) HTTPClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport: p.Server.Client().Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// generateSigningKey returns a fresh ECDSA P-256 signer wrapped in
// [op.SigningKey].
func generateSigningKey(tb testing.TB, kid string) op.SigningKey {
	tb.Helper()
	entry, err := keys.GenerateES256(kid)
	if err != nil {
		tb.Fatalf("testkit: generate signing key: %v", err)
	}
	return op.SigningKey{KeyID: entry.KeyID, Signer: entry.Signer}
}

// rs256Key is the RSA 2048 key shared by every RS256 provider in the
// process; generating one per provider would dominate test runtime.
var rs256Key = sync.OnceValues(func() (*rsa.PrivateKey, error) { //nolint:gochecknoglobals // process-wide key cache; safe by sync.OnceValues.
	entry, err := keys.GenerateRS256("testkit-rs256")
	if err != nil {
		return nil, err
	}
	return entry.Signer.(*rsa.PrivateKey), nil //nolint:forcetypeassert // GenerateRS256 always returns *rsa.PrivateKey.
})

// rs256SigningKey wraps the shared RSA key under the supplied kid.
func rs256SigningKey(tb testing.TB, kid string) op.SigningKey {
	tb.Helper()
	k, err := rs256Key()
	if err != nil {
		tb.Fatalf("testkit: generate rs256 signing key: %v", err)
	}
	return op.SigningKey{KeyID: kid, Signer: k}
}

// NewSigningKey returns a fresh ECDSA P-256 [op.SigningKey] stamped
// with the supplied kid. Tests that build [op.New] option lists by
// hand (for example, to drive [op.New]'s rejection paths with a
// specific signing kid) call this instead of going through
// [NewProvider]; the helper fails the test fast on key-generation
// fault.
func NewSigningKey(tb testing.TB, kid string) op.SigningKey {
	return generateSigningKey(tb, kid)
}

// NewCookieKey returns a fresh 32-byte cookie key suitable for
// [op.WithCookieKeys]. Mirrors [NewSigningKey]: tests assembling
// option slices by hand use this to satisfy the cookie-key gate
// without re-implementing the [crypto/rand] dance.
func NewCookieKey(tb testing.TB) []byte {
	return generateCookieKey(tb)
}

// generateCookieKey returns a fresh 32-byte cookie key suitable for
// satisfying [op.WithCookieKeys]. The key is generated per [NewProvider]
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
