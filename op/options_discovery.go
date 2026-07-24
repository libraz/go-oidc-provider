package op

import (
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"

	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// WithClaimsSupported populates the discovery document's
// claims_supported field with the supplied claim names. OIDC Discovery
// 1.0 §3 lists claims_supported as RECOMMENDED — clients consult it to
// decide whether a particular claim is worth requesting via scope or
// via the §5.5 "claims" parameter — but the spec leaves the OP free to
// omit the field when the OP cannot pre-enumerate its claim universe.
//
// The library default is to omit the field. The library's claims
// projector emits OIDC Core 1.0 §5.4 standard claims when the
// configured [op/store.UserStore] returns matching values, and the
// list of which standard claims a particular embedder actually
// surfaces depends entirely on what the user store fills in; rather
// than guess, the library leaves the discovery field blank by default
// so embedders cannot accidentally advertise claims they never emit.
//
// Callers supply the closed list themselves. A typical FAPI 2.0
// deployment that exposes profile / email / phone scopes would call:
//
//	op.WithClaimsSupported(
//	    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
//	    "name", "given_name", "family_name", "preferred_username",
//	    "email", "email_verified",
//	)
//
// The supplied slice is copied defensively. Passing the option twice
// fails at construction time so the operator notices the duplicate.
// Passing a nil or empty slice records the empty list (the discovery
// document still omits the field — the omitempty JSON tag covers
// both cases) so the option doubles as an "explicitly no claims"
// declaration when an embedder needs that posture.
//
// Stable since v0.x.
func WithClaimsSupported(claims ...string) Option {
	return optionFunc(func(c *config) error {
		if c.claimsSupported != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithClaimsSupported was supplied more than once",
			}
		}
		c.claimsSupported = slices.Clone(claims)
		if c.claimsSupported == nil {
			// slices.Clone(nil) returns nil; record an empty slice so
			// the "option was supplied" signal is preserved without
			// changing the wire output (claims_supported uses
			// omitempty).
			c.claimsSupported = []string{}
		}
		return nil
	})
}

// WithACRValuesSupported populates the discovery document's
// acr_values_supported field with the supplied Authentication Context
// Class Reference values. OIDC Discovery 1.0 §3 lists the field as
// OPTIONAL — clients consult it to discover which acr_values the OP
// recognises so they can request a specific authentication strength
// up front instead of negotiating it after a failed flow.
//
// The values come from the OP's local trust framework or federation
// profile: RFC 8176 authentication-method references
// (e.g. "urn:mace:incommon:iap:silver"), NIST SP 800-63 step-up
// labels, or custom URNs the deployment has standardised on. The
// library does NOT aggregate the values from per-client
// default_acr_values metadata because a registry of N clients would
// grow the discovery document without bound; the embedder publishes
// the closed list it actually supports instead.
//
// The supplied slice is copied defensively so a later mutation of the
// caller's slice cannot silently change the wire output. Passing the
// option with no arguments records "no values supported" — the
// discovery document still omits the field via the omitempty JSON
// tag, but the option-was-set signal is preserved. Each value MUST be
// non-empty; an empty-string entry is rejected at construction time
// because OIDC Discovery 1.0 §3 leaves the value format open but an
// empty class reference cannot be matched against a request.
//
// Stable since v0.x.
func WithACRValuesSupported(values ...string) Option {
	return optionFunc(func(c *config) error {
		if c.acrValuesSupported != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithACRValuesSupported was supplied more than once",
			}
		}
		for i, v := range values {
			if v == "" {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithACRValuesSupported received an empty value at index " + strconv.Itoa(i),
				}
			}
		}
		c.acrValuesSupported = slices.Clone(values)
		if c.acrValuesSupported == nil {
			// slices.Clone(nil) returns nil; record an empty slice so
			// the "option was supplied" signal is preserved without
			// changing the wire output (acr_values_supported uses
			// omitempty).
			c.acrValuesSupported = []string{}
		}
		return nil
	})
}

// WithClaimsParameterSupported toggles the OP's handling of the OIDC
// Core 1.0 §5.5 "claims" request parameter. The library default is
// true: the parser is always wired; the discovery document advertises
// claims_parameter_supported: true; the authorize / par endpoints
// honour any incoming payload by persisting it on the originating
// grant; the userinfo and id_token issuance paths project the
// requested claims when the user store has matching values. Passing
// false flips the discovery advertisement off, makes the authorize /
// par parsers silently drop the parameter (no invalid_request), and
// disables the userinfo / id_token projection.
//
// The toggle is provided so an embedder that does not want to expose
// per-claim consent (e.g. a deployment whose RPs already negotiate
// claims out-of-band) can match the ory/hydra posture without losing
// scope-driven release. It does not affect the parser's malformed-
// JSON rejection: a payload that is genuinely malformed is still
// rejected at the wire boundary irrespective of the toggle, because
// the parser also services the FAPI 2.0 conformance flow which
// expects a uniform invalid_request shape.
//
// Stable since v0.x.
func WithClaimsParameterSupported(enabled bool) Option {
	return optionFunc(func(c *config) error {
		c.claimsParameterSupportedSet = true
		c.claimsParameterSupportedOff = !enabled
		return nil
	})
}

// DiscoveryMetadata carries the static RFC 8414 §2 metadata fields an
// embedder injects into the OP's discovery document. The fields are
// values the OP itself does not own — the human-readable URLs and the
// list of UI locales the deployment supports — so they MUST be
// supplied by the embedder rather than guessed by the library.
//
// The four named fields map 1:1 to discovery JSON keys; Extra accepts
// arbitrary additional keys (RFC 8414 §2 explicitly permits unknown
// metadata members). Keys that collide with an OP-controlled field
// name (issuer, authorization_endpoint, response_types_supported, …)
// are rejected at op.New construction time so embedders cannot silently
// shadow protocol-defining values.
type DiscoveryMetadata struct {
	// ServiceDocumentation is the URL of the OP's developer
	// documentation (RFC 8414 §2 "service_documentation"). The empty
	// string omits the field from the wire.
	ServiceDocumentation string

	// OPPolicyURI is the URL of the OP's privacy policy
	// (OpenID Connect Discovery 1.0 §3 / RFC 8414 §2
	// "op_policy_uri"). The empty string omits the field.
	OPPolicyURI string

	// OPTermsOfServiceURI is the URL of the OP's terms-of-service
	// page (OpenID Connect Discovery 1.0 §3 / RFC 8414 §2
	// "op_tos_uri"). The empty string omits the field.
	OPTermsOfServiceURI string

	// UILocalesSupported lists the BCP 47 language tags the OP's
	// human-facing UI supports (OpenID Connect Discovery 1.0 §3 /
	// RFC 8414 §2 "ui_locales_supported"). Nil and empty are
	// equivalent — when omitted, the discovery builder falls back to
	// every locale registered with the runtime resolver (seed
	// bundles plus [WithLocale] additions). An explicit non-empty
	// list overrides the auto-derivation, so embedders that ship a
	// bundle for internal use without exposing it to RPs can keep the
	// shorter wire-form.
	UILocalesSupported []string

	// MTLSEndpointAliases publishes alternative URLs at which the OP
	// serves its mTLS-required endpoints (RFC 8705 §5). Keys MUST
	// match discovery endpoint metadata names exactly as they appear
	// on the wire (e.g. "token_endpoint", "introspection_endpoint",
	// "revocation_endpoint", "userinfo_endpoint",
	// "registration_endpoint",
	// "device_authorization_endpoint",
	// "pushed_authorization_request_endpoint"); values are absolute
	// URLs that require client-certificate authentication.
	//
	// The field is structurally feature-gated: it is published only
	// when [feature.MTLS] is enabled. Supplying aliases without the
	// MTLS feature is a no-op so an embedder can keep the option in
	// place across feature toggles without further branching.
	//
	// Deployments that front a single hostname (the canonical
	// *_endpoint values are already mTLS-capable) leave this map nil
	// or empty so the field stays absent from the discovery
	// document — RFC 8705 §5 makes the publication MAY, not MUST.
	//
	// Spec: RFC 8705 §5.
	MTLSEndpointAliases map[string]string

	// Extra carries arbitrary embedder-defined passthrough keys. The
	// values are JSON-marshalled into the discovery document at the
	// top level. Keys MUST be valid RFC 8414 metadata names (lowercase
	// snake_case is conventional but the library does not enforce a
	// shape) and MUST NOT collide with any OP-controlled field name;
	// op.New rejects collisions at construction time so a typo cannot
	// silently shadow a protocol-defining value.
	Extra map[string]any
}

// WithDiscoveryMetadata injects static RFC 8414 §2 metadata fields into
// the OP's discovery document. The OP does not own the URLs or the
// list of UI locales the deployment supports; the embedder supplies
// them through this option, and the library merges them into the
// document at construction time.
//
// The four named [DiscoveryMetadata] fields are typed for safety;
// arbitrary additional metadata keys go into [DiscoveryMetadata.Extra]
// and are passed through verbatim. RFC 8414 §2 explicitly permits
// unknown metadata members, so embedders that publish a custom field
// (e.g. an organisation-specific extension) can do so without the
// library knowing about it.
//
// The option enforces an override-deny invariant: any [Extra] key that
// matches an OP-controlled field name (issuer, authorization_endpoint,
// response_types_supported, jwks_uri, …) is rejected at op.New, and
// the error names the offending key. The deny-list is computed via
// reflection over the discovery document shape, so it stays in sync
// with the library's wire output as new fields land.
//
// The option may be supplied at most once; a duplicate call returns
// a configuration error so an embedder notices the conflict.
//
// Spec: RFC 8414 §2.
//
// Stable since v0.x.
func WithDiscoveryMetadata(meta DiscoveryMetadata) Option {
	return optionFunc(func(c *config) error {
		if c.discoveryMetadataSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata was supplied more than once",
			}
		}
		if err := validateDiscoveryMetadataExtra(meta.Extra); err != nil {
			return err
		}
		if err := validateDiscoveryMetadataURLs(meta); err != nil {
			return err
		}
		c.discoveryMetadata = cloneDiscoveryMetadata(meta)
		c.discoveryMetadataSet = true
		return nil
	})
}

func validateDiscoveryMetadataURLs(meta DiscoveryMetadata) error {
	for field, raw := range map[string]string{
		"service_documentation": meta.ServiceDocumentation,
		"op_policy_uri":         meta.OPPolicyURI,
		"op_tos_uri":            meta.OPTermsOfServiceURI,
	} {
		if raw == "" {
			continue
		}
		if !isDiscoveryHTTPSURL(raw) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata: " + field + " must be an absolute https URL (http is allowed only for loopback development hosts)",
			}
		}
	}
	for key, raw := range meta.MTLSEndpointAliases {
		if key == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata: mtls_endpoint_aliases contains an empty key",
			}
		}
		if !isDiscoveryHTTPSURL(raw) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata: mtls_endpoint_aliases[" + key + "] must be an absolute https URL (http is allowed only for loopback development hosts)",
			}
		}
	}
	return nil
}

func isDiscoveryHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// validateDiscoveryMetadataExtra rejects empty Extra keys and any key
// that collides with an OP-controlled discovery field. The four named
// fields appearing under Extra are blocked because they already have
// typed slots on [DiscoveryMetadata]; a duplicate would create two
// sources of truth.
func validateDiscoveryMetadataExtra(extra map[string]any) error {
	if len(extra) == 0 {
		return nil
	}
	denied := opControlledKeySet()
	for key := range extra {
		if key == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata: Extra contains an empty key",
			}
		}
		if _, blocked := denied[key]; blocked {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata: Extra key " + key + " collides with an OP-controlled discovery field",
			}
		}
	}
	return nil
}

// cloneDiscoveryMetadata copies meta into a fresh [DiscoveryMetadata]
// so the option does not retain a reference to the embedder's slices /
// maps. The maps are cloned only when populated to keep the wire shape
// (omitempty) stable across nil and empty inputs.
func cloneDiscoveryMetadata(meta DiscoveryMetadata) DiscoveryMetadata {
	out := DiscoveryMetadata{
		ServiceDocumentation: meta.ServiceDocumentation,
		OPPolicyURI:          meta.OPPolicyURI,
		OPTermsOfServiceURI:  meta.OPTermsOfServiceURI,
		UILocalesSupported:   slices.Clone(meta.UILocalesSupported),
	}
	if len(meta.MTLSEndpointAliases) > 0 {
		out.MTLSEndpointAliases = maps.Clone(meta.MTLSEndpointAliases)
	}
	if len(meta.Extra) > 0 {
		out.Extra = maps.Clone(meta.Extra)
	}
	return out
}

// opControlledKeySet returns the set of discovery JSON keys the OP
// itself populates. The set is recomputed on every call from
// [discovery.OPControlledFieldNames]; the override-deny check runs only
// at op.New construction time, so the per-call cost is negligible and
// a package-level cache is unnecessary.
func opControlledKeySet() map[string]struct{} {
	names := discovery.OPControlledFieldNames()
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

// WithOpenIDScopeOptional lifts the OpenID Connect Core 1.0 §3.1.2.1
// requirement that every authorization request include the "openid"
// scope. With the option set, the OP serves both flavours from the
// same /authorize endpoint: requests carrying "openid" run the OIDC
// path (id_token + userinfo); requests omitting "openid" run as plain
// OAuth 2.0 authorization_code (access token + optional refresh token,
// no id_token). The token endpoint's id_token issuance stays
// scope-driven, so a downgrade to OAuth 2.0 never produces a stray
// id_token.
//
// Use this only when the deployment intentionally serves non-OIDC
// clients. The default posture (option absent) matches OIDC: a request
// missing "openid" is rejected before the redirect with
// invalid_scope. Discovery and userinfo are unchanged — the OP
// remains a fully-capable OIDC OP and clients that want id_tokens
// only need to keep "openid" in their scope list.
//
// The flag is incompatible with [profile.Profile] sets that mandate
// OIDC semantics (FAPI 2.0 Baseline / Message Signing); op.New
// rejects the combination at construction time.
//
// Stable since v0.x.
func WithOpenIDScopeOptional() Option {
	return optionFunc(func(c *config) error {
		c.openIDScopeOptional = true
		return nil
	})
}

// WithACRPolicy installs a custom [ACRPolicy] that decides what acr /
// amr claims the OP writes onto issued id_tokens and which acr_values
// requests the OP treats as satisfied. The library default is
// [DefaultACRPolicy] (lax: any AAL>=AAL1 satisfies any requested
// acr); embedders that need a stricter mapping (e.g. NIST SP 800-63
// binding, a configured per-acr table à la Keycloak) supply their
// own implementation. Passing nil restores the library default.
//
// The default installation is intentional: a deployment that omits
// the option gets the OFCS-passing wire shape automatically.
//
// Stable since v0.x.
func WithACRPolicy(p ACRPolicy) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(p) {
			p = nil
		}
		c.acrPolicy = p
		return nil
	})
}

// WithProfile activates an industry security profile. Profiles compose
// multiplicatively: enabling FAPI2Baseline implies its underlying features
// and policies. Repeated profiles are rejected.
// WithProfile auto-enables every flag returned by
// [profile.RequiredFeatures] for the supplied profile. The auto-enable is
// idempotent: a flag already present in the configured feature set is
// silently skipped (NOT rejected as a duplicate), so an embedder may
// layer [WithFeature] before or after [WithProfile] without surprise.
// The auto-enable is intentionally add-only: WithProfile never removes
// a flag the embedder already set.
//
// Disjunctive profile constraints ([profile.RequiredAnyOf]) are also
// fulfilled with a sensible default: when none of the listed flags is
// already enabled, the FIRST member of each set is auto-enabled. For
// the FAPI 2.0 family this means [WithProfile](FAPI2Baseline) alone
// activates DPoP — picked because it has no infrastructure
// prerequisite — while an embedder who wants mTLS opts in via
// [WithFeature](feature.MTLS) and the auto-enable steps aside (the
// AnyOf is already satisfied). The defaulting is order-independent:
// it runs after every option has been applied.
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
		// Auto-enable every required feature idempotently. The
		// duplicate check in [WithFeature] is bypassed because the
		// auto-enable contract is "silently skip", not "fail loudly":
		// embedders must remain free to call [WithFeature] explicitly
		// before or after [WithProfile].
		for _, req := range profile.RequiredFeatures(p) {
			if !req.IsValid() {
				continue
			}
			if featureEnabled(c.features, req) {
				continue
			}
			c.features = append(c.features, req)
		}
		return nil
	})
}
