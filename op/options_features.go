package op

import (
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
)

// WithFeature enables an optional protocol extension. The option may be
// repeated; each call adds to the enabled set.
// Idempotent: enabling a flag that is already present is a silent
// no-op rather than a configuration error. This matches the
// auto-enable contract [WithProfile] introduced so an embedder may write
// `WithProfile(FAPI2Baseline)` plus `WithFeature(feature.PAR)` —
// either order, before or after — without the second call failing
// because the profile already activated the flag.
// Stable since v0.1.
func WithFeature(f feature.Flag) Option {
	return optionFunc(func(c *config) error {
		if !f.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFeature received an unknown feature flag",
			}
		}
		if featureEnabled(c.features, f) {
			return nil
		}
		c.features = append(c.features, f)
		return nil
	})
}

// MaxAccessTokenTTL is the implementation-defined upper bound the
// option layer enforces on [WithAccessTokenTTL]. The value (24 hours)
// is intentionally generous — long enough that an embedder running an
// internal API behind the OP can pick a TTL that aligns with their
// session lifetime — while still rejecting the obviously-wrong inputs
// (multi-day or multi-year) that produce tokens whose practical
// invalidation requires the per-grant revocation pathway. The bound
// composes with profile-supplied caps: a configured FAPI profile pulls
// the bound down to its 10-minute limit ([profile.MaxAccessTokenTTL]),
// and the more-restrictive value wins.
//
// The canonical value lives in [timex.AccessTokenTTLMax]; this name is
// preserved for embedders that already reference the constant.
//
//nolint:gochecknoglobals // re-export of the canonical timex value; var is required for cross-package alias.
var MaxAccessTokenTTL = timex.AccessTokenTTLMax

// WithAccessTokenTTL overrides the lifetime applied to issued access
// tokens. Zero means "use [DefaultAccessTokenTTL]"; a negative value
// is rejected at the option site so the misconfiguration surfaces at
// startup rather than silently expiring tokens at the wrong cadence.
// Values above [MaxAccessTokenTTL] are also rejected so a typo cannot
// produce a token whose practical invalidation requires per-grant
// revocation; when [WithProfile] is also configured, the embedder's
// TTL MUST stay at or below the profile's bound (see
// [profile.MaxAccessTokenTTL] — FAPI 2.0 §3.1.9 caps at 10 minutes).
// Stricter-than-profile values are accepted; a value above the bound
// fails [New].
// Stable since v0.1.
func WithAccessTokenTTL(ttl time.Duration) Option {
	return optionFunc(func(c *config) error {
		if ttl < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenTTL requires a non-negative duration",
			}
		}
		if ttl > MaxAccessTokenTTL {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenTTL exceeds implementation-defined maximum (24h)",
			}
		}
		c.accessTokenTTL = ttl
		return nil
	})
}

// WithRefreshTokenTTL overrides the lifetime applied to issued refresh
// tokens. Zero means "use [DefaultRefreshTokenTTL]" (30 days); a
// negative value is rejected at the option site so the
// misconfiguration surfaces at startup rather than silently issuing
// tokens with the wrong cadence.
//
// Refresh tokens are issued only when the granted scope contains
// "openid" AND the client's GrantTypes includes "refresh_token"; the
// library defaults to the lax reading of OIDC Core 1.0 §11 in which
// the "offline_access" scope governs consent UX and the TTL bucket
// (see [WithRefreshTokenOfflineTTL]) but does not gate issuance.
// Embedders who want the strict §11 reading — refresh issued only
// when "offline_access" is granted — pass [WithStrictOfflineAccess].
// To disable refresh tokens entirely, remove "refresh_token" from
// the per-client GrantTypes or from the global [WithGrants] set.
// Stable since v0.2.
func WithRefreshTokenTTL(ttl time.Duration) Option {
	return optionFunc(func(c *config) error {
		if ttl < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshTokenTTL requires a non-negative duration",
			}
		}
		c.refreshTokenTTL = ttl
		return nil
	})
}

// WithRefreshTokenOfflineTTL overrides the lifetime applied to
// refresh tokens issued under the OIDC Core 1.0 §11 "offline_access"
// scope. The default zero value defers to [WithRefreshTokenTTL] so
// embedders that do not distinguish offline use see no behaviour
// change. When set to a non-zero value, refresh tokens issued
// alongside an `offline_access`-bearing grant get the offline TTL
// while conventional online refresh continues to use the refresh-
// token TTL.
//
// The split makes the discovery-advertised "offline_access" scope
// operationally observable: under the lax reading it lengthens the
// refresh-token lifetime; under [WithStrictOfflineAccess] it is the
// only path that issues a refresh token at all.
// Stable since v0.x.
func WithRefreshTokenOfflineTTL(ttl time.Duration) Option {
	return optionFunc(func(c *config) error {
		if ttl < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshTokenOfflineTTL requires a non-negative duration",
			}
		}
		c.refreshTokenOfflineTTL = ttl
		return nil
	})
}

// WithStrictOfflineAccess flips the refresh-token issuance gate to
// the strict reading of OIDC Core 1.0 §11: refresh tokens are issued
// only when the granted scope contains "offline_access" (in addition
// to the existing "openid" + per-client `refresh_token` grant
// requirement). Authorization-code exchanges that satisfy the other
// conditions but lack `offline_access` succeed with an `access_token`
// + `id_token` and no `refresh_token` field — mirroring today's
// "client lacks refresh_token grant" path.
//
// At /token (grant_type=refresh_token), a refresh request whose
// originating grant did not carry `offline_access` fails with
// `invalid_grant` ("refresh disabled by current policy"). The check
// runs after the underlying refresh-token exchange, so the presented
// token is consumed exactly once even when the policy rejects it —
// embedders flipping this flag mid-deployment must accept that
// pre-flag refresh tokens are invalidated on first use.
//
// The flag is incompatible with [WithOpenIDScopeOptional]: §11 has
// no meaning for non-OIDC requests, so combining the two would
// silently disable every refresh issuance. [op.New] returns
// `op.Error{Code: codeConfiguration}` on the conflict.
//
// Default false. The lax reading (refresh issued whenever
// `refresh_token` grant is registered and scope contains "openid")
// is the historical library posture and matches Auth0 / Okta /
// Keycloak; the strict reading matches panva/node-oidc-provider and
// ory/hydra defaults.
// Stable since v0.x.
func WithStrictOfflineAccess() Option {
	return optionFunc(func(c *config) error {
		c.strictOfflineAccess = true
		return nil
	})
}

// WithAccessTokenFormat selects the global access-token format
// (ADR 0024). Default [AccessTokenFormatJWT]; passing
// [AccessTokenFormatOpaque] switches every issued access token onto
// the opaque-bearer path described in [store.OpaqueAccessToken].
//
// When the opaque format is selected the configured [Store] MUST
// return a non-nil [store.OpaqueAccessTokenStore] from
// [store.Store.OpaqueAccessTokens]; [New] rejects the configuration
// at construction time when the substore is nil so a misconfiguration
// surfaces at startup rather than the first /token request.
//
// If [WithAccessTokenFormatPerAudience] is also set, this option
// supplies the fallback for any RFC 8707 resource indicator absent
// from the map.
//
// Stable since v0.x.
func WithAccessTokenFormat(f store.AccessTokenFormat) Option {
	return optionFunc(func(c *config) error {
		if !f.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenFormat received an unknown AccessTokenFormat value",
			}
		}
		c.accessTokenFormat = f
		return nil
	})
}

// WithAccessTokenFormatPerAudience binds an access-token format to
// each RFC 8707 resource indicator (ADR 0024). Tokens minted for a
// request whose resource value matches a key in the map use the
// mapped format; tokens for any other resource (including the empty
// default audience) fall back to [WithAccessTokenFormat] or, if that
// option is also absent, [AccessTokenFormatJWT].
//
// Map keys MUST be canonical resource indicators per RFC 3986 §6:
//   - absolute URI with a non-empty scheme and host;
//   - scheme and host in lowercase form;
//   - no fragment;
//   - empty-string keys are rejected — the global default belongs in
//     [WithAccessTokenFormat].
//
// Non-canonical keys (mixed-case scheme / host, fragment present, …)
// fail at [New] so an embedder cannot ship a typo that silently
// disables the policy. Map values MUST be one of the documented
// constants ([AccessTokenFormatJWT] or [AccessTokenFormatOpaque]);
// unknown values are rejected with the same "fail-fast at
// construction" posture as [WithAccessTokenFormat].
//
// When the map contains any [AccessTokenFormatOpaque] value the
// configured [Store] MUST return a non-nil
// [store.OpaqueAccessTokenStore]; the construction-time validator
// enforces the same rule that [WithAccessTokenFormat] applies.
//
// Calling the option more than once replaces the prior map entirely.
// The supplied map is defensive-copied so a later mutation of the
// caller's map cannot silently change the OP's policy at runtime.
//
// Stable since v0.x.
func WithAccessTokenFormatPerAudience(m map[string]store.AccessTokenFormat) Option {
	return optionFunc(func(c *config) error {
		if len(m) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenFormatPerAudience requires at least one entry",
			}
		}
		out := make(map[string]store.AccessTokenFormat, len(m))
		for raw, f := range m {
			if raw == "" {
				return &Error{
					Code: codeConfiguration,
					Description: "WithAccessTokenFormatPerAudience: empty key is " +
						"reserved; use WithAccessTokenFormat for the default audience",
				}
			}
			if !f.IsValid() {
				return &Error{
					Code: codeConfiguration,
					Description: "WithAccessTokenFormatPerAudience[" + raw +
						"]: unknown AccessTokenFormat value",
				}
			}
			if err := validateResourceIndicator(raw); err != nil {
				return err
			}
			out[raw] = f
		}
		c.accessTokenFormatPerAudience = out
		return nil
	})
}

// validateResourceIndicator enforces the canonical-form rules
// [WithAccessTokenFormatPerAudience] applies to its map keys. The
// check runs against the raw string (not the [url.URL] view) because
// the issuance path keys the per-audience map directly off the
// request's verbatim resource parameter; a key whose lowercase /
// fragment-stripped re-rendering differs from the raw bytes would
// silently miss every lookup.
//
// The helper is split out so a future option that consumes resource
// indicators (e.g. a per-audience TTL knob) can reuse the same
// invariants without re-deriving the parse.
func validateResourceIndicator(raw string) error {
	// Reject obvious non-URI / mixed-case forms before url.Parse so
	// the diagnostic points at the actual source bytes rather than
	// the normalised form Go produces.
	if raw != strings.ToLower(raw) && hasUppercaseSchemeOrHost(raw) {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: scheme and host must be lowercase",
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: not a valid URI",
			Cause: err,
		}
	}
	if !u.IsAbs() || u.Scheme == "" || u.Host == "" {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: must be an absolute URI with scheme and host",
		}
	}
	if u.Fragment != "" || u.RawFragment != "" || strings.Contains(raw, "#") {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: fragment is not permitted",
		}
	}
	return nil
}

// hasUppercaseSchemeOrHost reports whether raw carries a non-lowercase
// ASCII letter before the start of the path / query / fragment. The
// function is conservative — it triggers on any uppercase byte in the
// scheme + authority — so callers receive a clear diagnostic instead
// of the silent-canonical surprise [url.Parse] produces (Go normalises
// the scheme to lowercase at parse time, hiding caller mistakes from
// a post-parse comparison).
//
// The scan terminates at the first '/' that starts the path component
// (the boundary after "scheme://authority") or the first '?' / '#'
// that starts query / fragment; URI-path bytes can be case-sensitive,
// so they are not inspected, and a fragment-only mismatch surfaces
// through the dedicated fragment check rather than this helper.
func hasUppercaseSchemeOrHost(raw string) bool {
	end := len(raw)
	if idx := strings.Index(raw, "://"); idx >= 0 {
		// raw = "scheme://authority[/path|?query|#fragment]"; scan
		// stops at the first byte that ends the authority component.
		rest := raw[idx+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			end = idx + 3 + j
		}
	} else if j := strings.IndexAny(raw, "/?#"); j >= 0 {
		end = j
	}
	for i := range end {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}
