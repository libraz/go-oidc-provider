package op

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Option configures a [Provider] passed to [New]. Options compose: the order
// in which they appear in the New call determines the order in which they
// are applied. Where two options set the same field, the later one wins.
//
// Implementors of new options should construct an [Option] via the
// unexported optionFunc type below; users of the package do not implement
// the Option interface directly.
type Option interface {
	apply(*config) error
}

type optionFunc func(*config) error

func (f optionFunc) apply(c *config) error { return f(c) }

// config holds the validated configuration of a [Provider]. It is private so
// that callers can only build it through [Option] values, which lets us
// preserve invariants (no zero-value Provider, type-driven enums, etc.).
type config struct {
	issuer       string
	store        store.Store
	clock        Clock
	logger       *slog.Logger
	keyset       Keyset
	mountPrefix  string
	endpoints    Endpoints
	grants       []grant.Type
	features     []feature.Flag
	profiles     []profile.Profile
	interactionD interaction.Driver

	// cookieKeys carries the AES-256-GCM keys used by the Cookie codec.
	// The first entry is the active encryption key; the remainder are
	// rotation slots tried in order on decryption only. Length 32 bytes
	// each; validation runs in [validate].
	cookieKeys [][]byte

	// trustedProxies holds the CIDRs from [WithTrustedProxies]. Empty
	// means "no proxy trusted"; X-Forwarded-* headers are ignored.
	trustedProxies []string

	// corsOrigins holds the explicit cross-origin entries from
	// [WithCORSOrigins]. The full allowlist is the union of these plus
	// every redirect_uri origin registered via the [store.ClientStore].
	corsOrigins []string

	// crossSiteFlow is the §F.3 opt-in for SameSite=None on session
	// cookies. Off by default per the production-grade posture.
	crossSiteFlow bool
}

// newConfig applies opts in order to a fresh config and returns the result
// or the first option error encountered. After every option has been
// applied, defaults are filled in for fields the caller chose to omit.
func newConfig(opts []Option) (*config, error) {
	c := &config{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt.apply(c); err != nil {
			return nil, err
		}
	}
	c.applyDefaults()
	return c, nil
}

// applyDefaults fills in optional fields with their library defaults.
func (c *config) applyDefaults() {
	if c.clock == nil {
		c.clock = timex.SystemClock
	}
	if c.logger == nil {
		c.logger = slog.New(discardHandler{})
	}
	if c.mountPrefix == "" {
		c.mountPrefix = "/oidc"
	}
	defaults := defaultEndpoints()
	c.endpoints = defaults.merge(c.endpoints)
	if c.interactionD == nil {
		c.interactionD = interaction.NoopDriver{}
	}
	if len(c.grants) == 0 {
		c.grants = []grant.Type{grant.AuthorizationCode, grant.RefreshToken}
	}
}

// validate checks that required fields are set and that combinations of
// options are internally consistent. It runs after applyDefaults so that
// "missing required" errors are not masked by a default value.
func (c *config) validate() error {
	if c.issuer == "" {
		return ErrIssuerRequired
	}
	if c.store == nil {
		return ErrStoreRequired
	}
	if len(c.keyset) == 0 {
		return ErrKeysetRequired
	}
	if err := validateKeyset(c.keyset); err != nil {
		return err
	}
	if err := validateCookieKeys(c.cookieKeys); err != nil {
		return err
	}
	if err := validateCookieKeysRequired(c.grants, c.cookieKeys); err != nil {
		return err
	}
	if _, err := proxy.NewTrust(c.trustedProxies); err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithTrustedProxies rejected by parser",
			Cause:       err,
		}
	}
	if _, err := csrf.NewAllowlist(c.corsOrigins); err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithCORSOrigins rejected by parser",
			Cause:       err,
		}
	}
	return nil
}

// validateCookieKeys runs the same shape checks as [cookie.NewCodec] but
// without instantiating the codec — startup validation must surface every
// wrong-length key with a stable [*Error] code regardless of order.
func validateCookieKeys(keys [][]byte) error {
	for i, k := range keys {
		if len(k) != cookieKeyLen {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCookieKey/WithCookieKeys: entry " + strconv.Itoa(i) + " is not 32 bytes",
			}
		}
	}
	return nil
}

// cookieKeyLen mirrors the AES-256-GCM key length expected by the cookie
// codec. The value is duplicated here so option-level validation can return
// a stable [*Error] without instantiating the codec.
const cookieKeyLen = 32

// validateCookieKeysRequired enforces the rule that any grant which depends
// on the authorize endpoint setting encrypted cookies (interaction binding,
// session resumption) MUST be paired with at least one cookie key. The
// authorization_code grant is the only one in v0.x that imposes the
// requirement; the rule is centralised here so future grants can opt in by
// adding themselves to the switch.
func validateCookieKeysRequired(grants []grant.Type, keys [][]byte) error {
	if len(keys) > 0 {
		return nil
	}
	for _, g := range grants {
		if g == grant.AuthorizationCode {
			return ErrCookieKeysRequired
		}
	}
	return nil
}

// validateKeyset enforces the v1.0 alg policy: every entry MUST be ECDSA on
// curve P-256 (so the OP can sign ES256). It also rejects empty key IDs
// and duplicates within the same keyset.
func validateKeyset(ks Keyset) error {
	seen := make(map[string]struct{}, len(ks))
	for i, k := range ks {
		if k.KeyID == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "keyset entry " + strconv.Itoa(i) + " is missing KeyID",
			}
		}
		if _, dup := seen[k.KeyID]; dup {
			return &Error{
				Code:        codeConfiguration,
				Description: "duplicate KeyID " + k.KeyID,
			}
		}
		seen[k.KeyID] = struct{}{}
		if k.Signer == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "keyset entry " + k.KeyID + " has nil Signer",
			}
		}
		pub, ok := k.Signer.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return &Error{
				Code:        codeConfiguration,
				Description: "keyset entry " + k.KeyID + " is not ECDSA P-256 (ES256 required)",
			}
		}
	}
	return nil
}

// WithIssuer sets the OP issuer URL. The value MUST be an absolute https URL
// with no query or fragment, per OpenID Connect Discovery 1.0 §3. The URL is
// parsed eagerly; malformed values fail [New] rather than the first request.
//
// Stable since v0.1.
func WithIssuer(issuer string) Option {
	return optionFunc(func(c *config) error {
		if issuer == "" {
			return ErrIssuerRequired
		}
		u, err := url.Parse(issuer)
		if err != nil || !u.IsAbs() || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" {
			return ErrIssuerInvalid
		}
		c.issuer = issuer
		return nil
	})
}

// WithStore registers the storage backend the [Provider] uses to persist
// authorization codes, refresh tokens, grants, sessions, and other records.
// Callers MUST supply a non-nil [store.Store]; the library does not provide a
// default backend at this layer because the choice of persistence is part of
// the deployment shape rather than the library configuration.
//
// Stable since v0.1.
func WithStore(s store.Store) Option {
	return optionFunc(func(c *config) error {
		if s == nil {
			return ErrStoreRequired
		}
		c.store = s
		return nil
	})
}

// WithKeyset registers the OP signing keys. The first entry is the active
// signer; subsequent entries are kept in JWKS so RPs can verify tokens
// issued under previous keys during a rotation window.
//
// Every entry MUST be ECDSA on curve P-256 (the v1.0 ES256 policy from
// docs/plans/002-product-design.md §J.5 / §K.3). Supplying any other key
// shape causes [New] to fail at construction time.
//
// Stable since v0.1.
func WithKeyset(ks Keyset) Option {
	return optionFunc(func(c *config) error {
		if len(ks) == 0 {
			return ErrKeysetRequired
		}
		c.keyset = ks
		return nil
	})
}

// WithClock injects the wall-clock implementation used for token expiry,
// audit timestamps, and rate-limit windows. If unset, the [Provider] uses a
// real wall clock backed by [time.Now]. Tests SHOULD inject a deterministic
// clock so the whole flow shares the same fake time.
//
// Stable since v0.1.
func WithClock(clock Clock) Option {
	return optionFunc(func(c *config) error {
		c.clock = clock
		return nil
	})
}

// WithLogger injects the [*slog.Logger] the library uses for structured
// diagnostics. If unset, the [Provider] discards every record. Callers
// SHOULD pass a logger backed by their service's slog handler so OP events
// appear in the same stream as the rest of the application.
//
// Stable since v0.1.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *config) error {
		c.logger = logger
		return nil
	})
}

// WithMountPrefix sets the URL prefix under which the [Provider] mounts its
// HTTP endpoints. The default is "/oidc". The discovery document is always
// served under /.well-known regardless of this value (per OpenID Connect
// Discovery 1.0 §4); every other endpoint is routed under prefix.
//
// The supplied prefix MUST start with "/" and MUST NOT end with "/". Empty
// values reject; the empty-prefix case (mounting at root) is supported by
// passing "/" explicitly.
//
// Stable since v0.1.
func WithMountPrefix(prefix string) Option {
	return optionFunc(func(c *config) error {
		if prefix == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMountPrefix prefix must not be empty (use \"/\" for root)",
			}
		}
		if !strings.HasPrefix(prefix, "/") {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMountPrefix prefix must start with \"/\"",
			}
		}
		if prefix != "/" && strings.HasSuffix(prefix, "/") {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMountPrefix prefix must not end with \"/\"",
			}
		}
		c.mountPrefix = prefix
		return nil
	})
}

// WithEndpoints overrides individual endpoint paths. Empty fields in e
// retain the library default; populated fields replace the corresponding
// path. The discovery document reflects every override automatically.
//
// Stable since v0.1.
func WithEndpoints(e Endpoints) Option {
	return optionFunc(func(c *config) error {
		c.endpoints = c.endpoints.merge(e)
		return nil
	})
}

// WithGrants selects the grant_type values the [Provider] accepts at the
// token endpoint. Calling this option replaces the default
// (authorization_code + refresh_token) entirely; pass every grant the
// deployment needs in a single call.
//
// Stable since v0.1.
func WithGrants(grants ...grant.Type) Option {
	return optionFunc(func(c *config) error {
		if len(grants) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithGrants requires at least one grant type",
			}
		}
		seen := make(map[grant.Type]struct{}, len(grants))
		for _, g := range grants {
			if !g.IsValid() {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithGrants received an unknown grant type",
				}
			}
			if _, dup := seen[g]; dup {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithGrants received duplicate grant type " + g.String(),
				}
			}
			seen[g] = struct{}{}
		}
		c.grants = append([]grant.Type(nil), grants...)
		return nil
	})
}

// WithFeature enables an optional protocol extension. The option may be
// repeated; each call adds to the enabled set. Duplicate enables are
// rejected to surface configuration mistakes.
//
// Stable since v0.1.
func WithFeature(f feature.Flag) Option {
	return optionFunc(func(c *config) error {
		if !f.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFeature received an unknown feature flag",
			}
		}
		for _, existing := range c.features {
			if existing == f {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithFeature received duplicate flag " + f.String(),
				}
			}
		}
		c.features = append(c.features, f)
		return nil
	})
}

// WithProfile activates an industry security profile. Profiles compose
// multiplicatively: enabling FAPI2Baseline implies its underlying features
// and policies. Repeated profiles are rejected.
//
// Stable since v0.1.
func WithProfile(p profile.Profile) Option {
	return optionFunc(func(c *config) error {
		if !p.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithProfile received an unknown profile",
			}
		}
		for _, existing := range c.profiles {
			if existing == p {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithProfile received duplicate profile " + p.String(),
				}
			}
		}
		c.profiles = append(c.profiles, p)
		return nil
	})
}

// WithInteraction registers the [interaction.Driver] that bridges the OP
// state machine to the user-facing UI. If unset, the [Provider] uses
// [interaction.NoopDriver], which fails closed: every interactive request
// is rejected with the "no_driver_configured" reason so a misconfigured
// deployment surfaces the missing UI rather than silently looping.
//
// Stable since v0.1.
func WithInteraction(d interaction.Driver) Option {
	return optionFunc(func(c *config) error {
		if d == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithInteraction received nil Driver",
			}
		}
		c.interactionD = d
		return nil
	})
}

// WithCookieKey registers a single AES-256-GCM key (32 bytes) for cookie
// encryption. It is a convenience wrapper over [WithCookieKeys] for the
// common single-key case.
//
// Stable since v0.1.
func WithCookieKey(key []byte) Option {
	return WithCookieKeys(key)
}

// WithCookieKeys registers the AES-256-GCM keys used for cookie encryption.
// The first key is the active encryption key; remaining keys are accepted on
// decryption only, supporting graceful rotation per
// docs/plans/002-product-design.md §F.2. Every key MUST be 32 bytes; an
// empty list is rejected so the misconfiguration surfaces at startup.
//
// Each call replaces any keys configured by a previous WithCookieKeys/
// [WithCookieKey] call. Pass every active and rotated key in a single call.
//
// Stable since v0.1.
func WithCookieKeys(keys ...[]byte) Option {
	return optionFunc(func(c *config) error {
		if len(keys) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCookieKeys requires at least one key",
			}
		}
		// Defensive copy so a later mutation of the caller's slice does
		// not silently change the OP's keys at runtime.
		cp := make([][]byte, len(keys))
		for i, k := range keys {
			b := make([]byte, len(k))
			copy(b, k)
			cp[i] = b
		}
		c.cookieKeys = cp
		return nil
	})
}

// WithTrustedProxies declares the CIDRs from which the [Provider] should
// honour [X-Forwarded-*] headers. When a request arrives from outside these
// ranges the headers are ignored, preventing IP / scheme spoofing
// (docs/plans/002-product-design.md §F.5).
//
// CIDRs may be IPv4 or IPv6; both notations are accepted. Each call
// replaces the previous list — pass every trusted CIDR in a single call.
//
// Stable since v0.1.
func WithTrustedProxies(cidrs ...string) Option {
	return optionFunc(func(c *config) error {
		if len(cidrs) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithTrustedProxies requires at least one CIDR",
			}
		}
		// Validate eagerly so misconfiguration surfaces at New time
		// rather than the first cross-proxy request.
		if _, err := proxy.NewTrust(cidrs); err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithTrustedProxies CIDR rejected",
				Cause:       err,
			}
		}
		c.trustedProxies = append([]string(nil), cidrs...)
		return nil
	})
}

// WithCORSOrigins adds explicit cross-origin entries to the CORS allowlist.
// The full allowlist is the union of these origins plus every redirect_uri
// origin the [store.ClientStore] returns; this option only handles entries
// that cannot be derived from a registered redirect_uri (admin SPAs,
// management consoles, etc.) per §F.4.
//
// Origins MUST be absolute URLs with non-empty scheme and host. The path,
// query, and fragment are stripped. Each call appends to the configured
// list; duplicates are deduplicated at allowlist build time.
//
// Stable since v0.1.
func WithCORSOrigins(origins ...string) Option {
	return optionFunc(func(c *config) error {
		if len(origins) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCORSOrigins requires at least one origin",
			}
		}
		for _, o := range origins {
			if _, err := csrf.CanonicalOrigin(o); err != nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithCORSOrigins origin rejected: " + o,
					Cause:       err,
				}
			}
		}
		c.corsOrigins = append(c.corsOrigins, origins...)
		return nil
	})
}

// WithCrossSiteFlow opts the [Provider] into [SameSite=None] cookies so the
// authorization endpoint can be embedded across origins (iframe / external
// SPA) per docs/plans/002-product-design.md §F.3. The default is off
// because cross-site cookies have a higher CSRF blast radius; enable only
// when the deployment requires the embedded flow.
//
// Experimental: the flag is wired through configuration but the cross-site
// flow surface is still being designed; the option name and semantics may
// change before v1.0.
//
// [SameSite=None]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#none
func WithCrossSiteFlow() Option {
	return optionFunc(func(c *config) error {
		c.crossSiteFlow = true
		return nil
	})
}
