package discovery

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
)

// ErrIssuerInvalid is returned by [Validate] when the issuer URL fails
// the OIDC Discovery 1.0 §3 / FAPI 2.0 §5.4 shape constraints. The
// caller wraps this into the public op.Error envelope so the op layer
// can surface a configuration error from [op.New].
var ErrIssuerInvalid = errors.New("discovery: issuer is not a valid OIDC issuer URL")

// Input is the configuration discovery needs from the [op.Provider]
// constructor in order to build the metadata document. The struct is
// internal-only; the public API is [op.WithEndpoints] and the various
// [op.WithFeature] / [op.WithGrants] options.
type Input struct {
	// Issuer is the OP's canonical issuer URL (no trailing slash).
	Issuer string

	// MountPrefix is the URL prefix under which the OP mounts its
	// endpoints (e.g. "/oidc", "/auth", "/").
	MountPrefix string

	// Endpoints carries the relative-path overrides for each endpoint.
	// Empty fields mean the spec-default path; the OP normalises that
	// before calling Build.
	Endpoints EndpointPaths

	// Features carries booleans for the optional protocol extensions.
	// Discovery emits endpoint URLs and supported-parameter flags only
	// for features that are enabled.
	Features Features

	// GrantsSupported lists the grant_type values the OP advertises.
	GrantsSupported []string

	// AuthMethodsSupported lists the token-endpoint client
	// authentication methods. Empty means the OP advertises a default
	// set (client_secret_basic, client_secret_post).
	AuthMethodsSupported []string

	// ProfileAllowedAuthMethods, when non-empty, filters the advertised
	// token_endpoint_auth_methods_supported (and the mirrored
	// introspection / revocation lists) down to the intersection of the
	// computed list and this allow-list. The op layer populates it
	// from the active [profile.Profile] set so an OP that runs FAPI 2.0
	// advertises only the methods FAPI 2.0 §3.1.3 actually permits,
	// regardless of which features are otherwise enabled.
	ProfileAllowedAuthMethods []string

	// ScopesSupported lists the scope identifiers the OP advertises
	// in the discovery document. The op layer pre-filters this list
	// (built-in standard scopes plus every registered scope whose
	// Public flag is true) so the discovery builder does not need
	// any policy of its own.
	ScopesSupported []string

	// ClaimsParameterSupported reports whether the OP honours the
	// OIDC Core 1.0 §5.5 "claims" request parameter. The library
	// defaults to true; embedders that prefer to ignore the parameter
	// supply false via op.WithClaimsParameterSupported(false).
	ClaimsParameterSupported bool

	// PairwiseEnabled reports whether the OP can issue pairwise
	// subject identifiers (i.e. op.WithPairwiseSubject is configured
	// or a custom op.WithSubjectGenerator returned a pairwise mode).
	// When true the discovery document advertises "pairwise" in
	// subject_types_supported alongside "public"; when false only
	// "public" is advertised.
	PairwiseEnabled bool

	// ClaimsSupported carries the explicit claim-name enumeration the
	// embedder supplied through op.WithClaimsSupported. Nil leaves
	// the discovery document's claims_supported field omitted, which
	// is the library default — the standard claim universe depends
	// on the configured user store and the library does not guess on
	// the embedder's behalf. A non-nil (possibly empty) slice is
	// copied verbatim onto the wire.
	ClaimsSupported []string

	// ACRValuesSupported carries the ACR class references the OP
	// advertises in acr_values_supported. The values come from the
	// OP's local trust framework or federation profile (RFC 8176
	// authentication-method references, NIST SP 800-63 step-up
	// labels, custom URNs); the library does not aggregate them
	// from per-client default_acr_values metadata because a registry
	// of N clients would grow the discovery document without bound.
	// Nil leaves the discovery document's acr_values_supported field
	// omitted, which is the library default. A non-nil slice is
	// copied verbatim onto the wire.
	ACRValuesSupported []string

	// AuthorizationDetailsTypesSupported carries the RFC 9396 §10
	// authorization_details "type" identifiers the OP accepts. Nil
	// leaves the field omitted; a non-nil slice is copied verbatim.
	AuthorizationDetailsTypesSupported []string

	// RequirePAR reports whether every authorization request must arrive
	// through the pushed authorization request endpoint. FAPI 2.0
	// Baseline requires this; vanilla OIDC leaves it false.
	RequirePAR bool

	// GrantManagementEnabled gates the OAuth 2.0 Grant Management draft
	// discovery fields. GrantManagementActions is the advertised action
	// set; GrantManagementActionRequired maps to
	// grant_management_action_required.
	GrantManagementEnabled        bool
	GrantManagementActions        []string
	GrantManagementActionRequired bool

	// EncryptionAlgsSupported lists the JWE alg values the OP
	// advertises across the *_encryption_alg_values_supported
	// fields. The op layer supplies the closed v0.9.1 default
	// (op.SupportedEncryptionAlgs) or the embedder's narrowed
	// subset (op.WithSupportedEncryptionAlgs). An empty list
	// suppresses every *_encryption_* array: the OP negotiates no
	// JWE at all.
	EncryptionAlgsSupported []string

	// EncryptionEncsSupported mirrors EncryptionAlgsSupported for
	// the *_encryption_enc_values_supported advertisement.
	EncryptionEncsSupported []string

	// Metadata carries the static RFC 8414 §2 metadata fields the
	// embedder injects through op.WithDiscoveryMetadata. The op
	// layer pre-validates the struct (override-deny check on
	// Metadata.Extra) so the discovery builder copies the values
	// onto the document without further policy.
	Metadata Metadata
}

// Metadata carries the static RFC 8414 §2 metadata fields the embedder
// publishes alongside the OP-controlled discovery document. The struct
// is wire-shape-aligned: each field maps to exactly one discovery JSON
// key, plus an Extra map for embedder-defined passthrough keys. The
// override-deny enforcement against [OPControlledFieldNames] lives in
// the op layer; this struct is a pure carrier.
type Metadata struct {
	// ServiceDocumentation maps to "service_documentation".
	ServiceDocumentation string

	// OPPolicyURI maps to "op_policy_uri".
	OPPolicyURI string

	// OPTermsOfServiceURI maps to "op_tos_uri".
	OPTermsOfServiceURI string

	// UILocalesSupported maps to "ui_locales_supported". Nil and
	// empty are equivalent (the field is omitted).
	UILocalesSupported []string

	// MTLSEndpointAliases maps to "mtls_endpoint_aliases" (RFC 8705
	// §5). The keys are discovery endpoint metadata names exactly as
	// they appear on the wire (e.g. "token_endpoint",
	// "introspection_endpoint", "revocation_endpoint",
	// "userinfo_endpoint", "registration_endpoint",
	// "device_authorization_endpoint", "pushed_authorization_request_endpoint");
	// the values are the alternative URLs that require client-
	// certificate authentication. Nil and empty are equivalent (the
	// field is omitted). The discovery builder ignores this map
	// entirely unless [Features.MTLS] is true so the field is
	// structurally feature-gated.
	MTLSEndpointAliases map[string]string

	// Extra carries arbitrary passthrough fields. Keys MUST NOT
	// collide with any name returned by [OPControlledFieldNames];
	// the op layer enforces this at construction time.
	Extra map[string]any
}

// EndpointPaths mirrors op.Endpoints with internal-friendly types.
type EndpointPaths struct {
	JWKS                string
	Authorize           string
	Token               string
	UserInfo            string
	EndSession          string
	Introspect          string
	Revoke              string
	PAR                 string
	Interaction         string
	Session             string
	Register            string
	DeviceAuthorization string
	Backchannel         string
	GrantManagement     string
}

// Features carries the enable bits for optional protocol extensions.
type Features struct {
	PAR                 bool
	JAR                 bool
	JARM                bool
	DPoP                bool
	MTLS                bool
	Introspect          bool
	Revoke              bool
	DynamicRegistration bool

	// AuthorizeEndpoint reports whether the OP mounts the browser
	// authorization endpoint, and with it the surfaces that only exist
	// behind it: RP-Initiated Logout and Back-Channel Logout. The op
	// layer wires the flag from the same predicate that decides the
	// router mount, so the advertisement cannot drift from the routing
	// table. A machine-to-machine OP (client_credentials only) leaves it
	// false and the discovery document stops claiming endpoints that
	// would answer 404.
	AuthorizeEndpoint bool

	// DeviceCodeGrant reports whether the OP is configured to accept
	// the RFC 8628 device_code grant. The discovery builder uses the
	// flag to gate emission of the device_authorization_endpoint
	// field; the op layer wires it from the resolved grants list and
	// substore presence.
	DeviceCodeGrant bool

	// CIBAGrant reports whether the OP is configured to accept the
	// CIBA Core 1.0 grant (urn:openid:params:grant-type:ciba). The
	// discovery builder uses the flag to gate emission of the
	// backchannel_authentication_endpoint /
	// backchannel_token_delivery_modes_supported /
	// backchannel_user_code_parameter_supported /
	// backchannel_authentication_request_signing_alg_values_supported
	// fields; the op layer wires it from the resolved grants list
	// and substore presence.
	CIBAGrant bool

	// EncryptionInbound reports whether the OP holds a JWE decryption
	// keyset (op.WithEncryptionKeyset). It gates the
	// request_object_encryption_* arrays and nothing else: an encrypted
	// request object is addressed to the OP's own key, so without one
	// the OP cannot accept any.
	//
	// The outbound arrays (id_token / userinfo / authorization /
	// introspection) are NOT gated on this flag. Those responses are
	// encrypted to a key from the relying party's JWKS, which the OP
	// never has to own, so an OP with no keyset of its own can still
	// serve every one of them. They are gated on
	// [Input.EncryptionAlgsSupported] / [Input.EncryptionEncsSupported]
	// being non-empty, plus their own protocol feature where one
	// applies (JARM, Introspect).
	EncryptionInbound bool
}

// ValidateIssuer enforces the OIDC Discovery 1.0 §3 / FAPI 2.0 §5.4
// shape constraints on the issuer URL. The accepted shape is the
// canonical form an RP can use for byte-exact comparison under
// RFC 9207 mix-up defense: an absolute https URL with a non-empty
// lowercase authority, no default port, no query, no fragment, no
// trailing slash, and a canonical path (no ".." / "." segments and
// no duplicate slashes). Loopback IP literals (127.0.0.0/8 and
// [::1]) are exempted from the https requirement so a development
// boot can use a plain-text scheme; production deployments are
// still required to publish the issuer over TLS. The textual host
// "localhost" is NOT in the carve-out because it can be DNS-hijacked
// (RFC 8252 §7.3 reasoning); [ValidateIssuerWithLocalhostName] admits it
// for callers that opted in explicitly.
//
// The validator is invoked by [Build] (defense in depth: op.WithIssuer
// performs the same check at the option site, but a future regression
// that loosens the option-layer rule must not silently land in the
// wire metadata).
func ValidateIssuer(raw string) error {
	return ValidateIssuerWithLocalhostName(raw, false)
}

// ValidateIssuerWithLocalhostName is [ValidateIssuer] with the textual
// host "localhost" admitted alongside the loopback IP literals when
// allowLocalhostName is true. The caller is expected to gate that on an
// explicit opt-in, because the DNS-hijack reasoning the default rests on
// does not stop being true — it is only acceptable on a developer's
// machine.
//
// The carve-out exists because two rules that are each correct do not
// leave a local passkey deployment anywhere to stand: WebAuthn requires
// a Relying Party ID that is a domain, browsers reject an IP literal for
// it, and the strict issuer rule rejects every http host that is not one.
func ValidateIssuerWithLocalhostName(raw string, allowLocalhostName bool) error {
	if raw == "" {
		return fmt.Errorf("%w: empty issuer", ErrIssuerInvalid)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", ErrIssuerInvalid, err)
	}
	if err := validateIssuerStructure(u); err != nil {
		return err
	}
	if err := validateIssuerCanonicalForm(raw, u); err != nil {
		return err
	}
	return validateIssuerScheme(u, allowLocalhostName)
}

// validateIssuerStructure enforces the URL-shape rules: absolute,
// non-empty authority, no query, no fragment, no trailing slash.
func validateIssuerStructure(u *url.URL) error {
	if !u.IsAbs() {
		return fmt.Errorf("%w: must be absolute", ErrIssuerInvalid)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: must carry an authority (non-empty host)", ErrIssuerInvalid)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("%w: must not carry a query", ErrIssuerInvalid)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: must not carry a fragment", ErrIssuerInvalid)
	}
	if strings.HasSuffix(u.Path, "/") {
		// OIDC Discovery 1.0 §3 / RFC 8414 §3 forbid both a bare
		// trailing slash ("https://idp.example.com/") and a trailing
		// slash on a non-empty path ("https://idp.example.com/oidc/")
		// because the issuer identifier is concatenated verbatim with
		// "/.well-known/..." to produce the configuration URI.
		return fmt.Errorf("%w: must not end with a trailing slash", ErrIssuerInvalid)
	}
	return nil
}

// validateIssuerCanonicalForm enforces RFC 3986 §3.2.2 / §6.2.2.1
// normalisation: lowercase scheme, lowercase authority, canonical path
// (no "..", ".", or duplicate slashes).
func validateIssuerCanonicalForm(raw string, u *url.URL) error {
	// url.Parse normalizes u.Scheme to lowercase, so an uppercase
	// scheme in raw input ("HTTPS://...") would slip past a u.Scheme
	// check. Inspect the raw prefix instead.
	if i := strings.Index(raw, ":"); i > 0 {
		if rawScheme := raw[:i]; rawScheme != strings.ToLower(rawScheme) {
			return fmt.Errorf("%w: scheme must be lowercase", ErrIssuerInvalid)
		}
	}
	// u.Host preserves the raw host:port casing. Reject any uppercase
	// in the authority so the published issuer matches the RFC 3986
	// §3.2.2 / §6.2.2.1 normalized form an RP would compare against.
	if u.Host != strings.ToLower(u.Host) {
		return fmt.Errorf("%w: host must be lowercase", ErrIssuerInvalid)
	}
	if u.Path != "" {
		// Reject ".." / "." segments and duplicate slashes. These
		// confuse the issuer concatenation that produces the
		// .well-known URI and defeat byte-exact comparison.
		if cleaned := path.Clean(u.Path); cleaned != u.Path {
			return fmt.Errorf("%w: path must be canonical (no '..', '.', or duplicate slashes)", ErrIssuerInvalid)
		}
	}
	return nil
}

// validateIssuerScheme enforces the scheme-specific rules: https with
// no default port, or http restricted to loopback IP literals — plus the
// textual "localhost" when the caller opted in.
func validateIssuerScheme(u *url.URL, allowLocalhostName bool) error {
	switch u.Scheme {
	case "https":
		if u.Port() == "443" {
			return fmt.Errorf("%w: must omit the default https port (:443)", ErrIssuerInvalid)
		}
		return nil
	case "http":
		if u.Port() == "80" {
			return fmt.Errorf("%w: must omit the default http port (:80)", ErrIssuerInvalid)
		}
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		if allowLocalhostName && u.Hostname() == "localhost" {
			return nil
		}
		return fmt.Errorf("%w: http scheme is permitted only for loopback IP literals (127.0.0.0/8 / [::1])", ErrIssuerInvalid)
	default:
		return fmt.Errorf("%w: scheme %q is not permitted", ErrIssuerInvalid, u.Scheme)
	}
}

// isLoopbackHost reports whether host is a loopback IP literal: the
// canonical loopback IPv4 address 127.0.0.1, the entire 127.0.0.0/8
// block (some test setups bind 127.0.0.2), or the IPv6 loopback ::1.
// The textual host "localhost" is intentionally NOT recognized because
// DNS resolution for "localhost" can be hijacked (RFC 8252 §7.3); a
// development boot binding loopback uses the IP literal directly. The
// check is closed: any host that does not match falls through to the
// production-grade https-only path.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// Build returns a [Document] populated from in. Absolute URLs are formed
// by joining the issuer, mount prefix, and endpoint paths. The function
// is total: callers that need to surface a configuration error from a
// malformed issuer call [ValidateIssuer] before [Build]. The op-layer
// wiring runs the validator in [op.New] so a misconfigured issuer
// surfaces at construction time, not the first /.well-known fetch.
func Build(in Input) Document {
	doc := newBaseDocument(in)
	applyFeatureEndpoints(in, &doc)
	applyJARFeature(in, &doc)
	applyDPoPFeature(in, &doc)
	applyMTLSFeature(in, &doc)
	applyProfileNarrowing(in, &doc)
	applyDynamicRegistration(in, &doc)
	applyJARMFeature(in, &doc)
	applyEndpointAuthMirrors(in, &doc)
	doc.RequirePushedAuthorizationRequests = in.RequirePAR
	// RFC 9207: every authorization response (success and error)
	// carries an "iss" parameter set to the OP's issuer. The library
	// emits it unconditionally — it is defense-in-depth against
	// mix-up attacks and is mandated by FAPI 2.0 §5.3.2.2.
	doc.AuthorizationResponseIssParameterSupported = true
	// OIDC Core 1.0 §5.5: advertise "claims" support when the OP has
	// not opted out. The library default is true (the parser is
	// always wired); op.WithClaimsParameterSupported(false) flips
	// this to false so the field is dropped from the wire and the
	// authorize / par parsers ignore the parameter.
	doc.ClaimsParameterSupported = in.ClaimsParameterSupported
	applyClaimsSupported(in, &doc)
	applyACRValuesSupported(in, &doc)
	applyAuthorizationDetailsTypesSupported(in, &doc)
	applyEncryptionFeature(in, &doc)
	applyCIBAFeature(in, &doc)
	applyStaticMetadata(in, &doc)
	return doc
}

// applyCIBAFeature publishes the CIBA Core 1.0 §3 metadata fields when
// the OP is configured to accept the CIBA grant. The
// backchannel_authentication_endpoint URL is built from the issuer +
// mount prefix + endpoint path the same way the other endpoints are.
// The token delivery modes list is fixed at ["poll"] because the OP
// implements poll mode only; ping and push are reserved for a future
// release. The user-code support flag is false because the library
// accepts the parameter on the wire but does not pre-validate against
// an OP-managed code registry. The request-object signing alg list is
// emitted only when JAR is also enabled because a CIBA request object
// shares the JAR verifier; the list mirrors the JAR alg posture so a
// single rotation flows to both surfaces.
func applyCIBAFeature(in Input, doc *Document) {
	if !in.Features.CIBAGrant {
		return
	}
	doc.BackchannelAuthenticationEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Backchannel)
	doc.BackchannelTokenDeliveryModesSupported = []string{"poll"}
	doc.BackchannelUserCodeParameterSupported = false
	if in.Features.JAR {
		doc.BackchannelAuthenticationRequestSigningAlgValuesSupported = []string{
			"RS256", "PS256", "ES256", "EdDSA",
		}
	}
}

// applyEncryptionFeature publishes the five
// *_encryption_alg_values_supported and *_encryption_enc_values_supported
// pairs, each on the capability that actually decides whether the OP
// can serve it.
//
// The direction matters. id_token / userinfo / authorization (JARM) /
// introspection are encrypted *to* the relying party, using a key taken
// from that party's JWKS, so the OP needs no encryption key of its own
// to serve them; they are advertised whenever the OP negotiates JWE at
// all, gated only by their own protocol feature where one applies.
// request_object travels the other way — it is encrypted to the OP —
// so it is advertised only when the OP holds a decryption keyset
// ([Features.EncryptionInbound]) and JAR is enabled.
//
// The alg / enc lists are the embedder's narrowed subset (or the
// closed v0.9.1 default when no narrowing was applied). An empty list
// on either side means no pair can be negotiated, so nothing is
// advertised.
func applyEncryptionFeature(in Input, doc *Document) {
	algs := slices.Clone(in.EncryptionAlgsSupported)
	encs := slices.Clone(in.EncryptionEncsSupported)
	if len(algs) == 0 || len(encs) == 0 {
		return
	}

	doc.IDTokenEncryptionAlgValuesSupported = algs
	doc.IDTokenEncryptionEncValuesSupported = encs
	doc.UserInfoEncryptionAlgValuesSupported = algs
	doc.UserInfoEncryptionEncValuesSupported = encs

	if in.Features.JARM {
		doc.AuthorizationEncryptionAlgValuesSupported = algs
		doc.AuthorizationEncryptionEncValuesSupported = encs
	}
	if in.Features.Introspect {
		doc.IntrospectionEncryptionAlgValuesSupported = algs
		doc.IntrospectionEncryptionEncValuesSupported = encs
	}
	if in.Features.EncryptionInbound && in.Features.JAR {
		doc.RequestObjectEncryptionAlgValuesSupported = algs
		doc.RequestObjectEncryptionEncValuesSupported = encs
	}
}

// newBaseDocument seeds the document with the fields every OP publishes
// regardless of its feature toggles, then layers the authorization-
// endpoint family on top ([applyAuthorizeEndpoint]). Subsequent helpers
// add the remaining feature-conditional fields.
func newBaseDocument(in Input) Document {
	doc := Document{
		Issuer:           in.Issuer,
		TokenEndpoint:    join(in.Issuer, in.MountPrefix, in.Endpoints.Token),
		UserInfoEndpoint: join(in.Issuer, in.MountPrefix, in.Endpoints.UserInfo),
		JWKSURI:          join(in.Issuer, in.MountPrefix, in.Endpoints.JWKS),
		// RFC 8414 §2 marks response_types_supported REQUIRED with no
		// carve-out, so the member stays on the wire even for an OP that
		// mounts no authorization endpoint. The empty array is the honest
		// value there: no response_type is accepted at all.
		ResponseTypesSupported: []string{},
		// OIDC Core §3.1.2.1 / Form Post Response Mode 1.0: "query" is
		// the implicit default for response_type=code; "form_post"
		// delivers the same parameters via a self-submitting POST body
		// to keep them out of access-log / Referer surfaces. JARM adds
		// the four "*.jwt" variants on top when the feature is on
		// ([applyJARMFeature]).
		ResponseModesSupported:            []string{"query", "form_post"},
		GrantTypesSupported:               in.GrantsSupported,
		SubjectTypesSupported:             subjectTypesFor(in.PairwiseEnabled),
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		UserInfoSigningAlgValuesSupported: []string{"ES256"},
		ScopesSupported:                   append([]string(nil), in.ScopesSupported...),
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: defaultAuthMethods(in.AuthMethodsSupported),
		BackchannelLogoutSessionSupported: false,
	}
	applyAuthorizeEndpoint(in, &doc)
	return doc
}

// applyAuthorizeEndpoint publishes the members that only carry meaning
// when the OP mounts the browser authorization endpoint: the endpoint
// URL, the response_type values it accepts, the RP-Initiated Logout
// endpoint, and the Back-Channel Logout capability flag. A logout token
// is only ever emitted from a session teardown that starts at
// /end_session, which in turn exists only alongside /authorize, so the
// three travel together.
//
// RFC 8414 §2 makes authorization_endpoint REQUIRED "unless no grant
// types are supported that use the authorization endpoint" — which is
// exactly this gate. Without it a machine-to-machine deployment would
// advertise routes its router never registered and hand the RP a bare
// 404 with no OAuth error body.
func applyAuthorizeEndpoint(in Input, doc *Document) {
	if !in.Features.AuthorizeEndpoint {
		return
	}
	doc.AuthorizationEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Authorize)
	doc.EndSessionEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.EndSession)
	doc.ResponseTypesSupported = []string{"code"}
	doc.BackchannelLogoutSupported = true
}

// subjectTypesFor returns the subject_types_supported slice. OIDC Core
// 1.0 §8 lists "public" as always-supported and adds "pairwise" only
// when the OP can actually issue per-RP subject identifiers; an OP
// that advertises pairwise without the wire-side capability would lie
// to RPs and be skipped by conformance tooling.
func subjectTypesFor(pairwiseEnabled bool) []string {
	if pairwiseEnabled {
		return []string{"public", "pairwise"}
	}
	return []string{"public"}
}

// applyFeatureEndpoints publishes the per-feature endpoint URLs
// (PAR / introspection / revocation / device_authorization). Each URL
// is gated on its feature flag so a deployment that does not advertise
// the feature keeps the field absent from the wire.
func applyFeatureEndpoints(in Input, doc *Document) {
	if in.Features.PAR {
		doc.PushedAuthorizationRequestEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.PAR)
	}
	if in.Features.Introspect {
		doc.IntrospectionEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Introspect)
	}
	if in.Features.Revoke {
		doc.RevocationEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Revoke)
	}
	if in.Features.DeviceCodeGrant {
		doc.DeviceAuthorizationEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.DeviceAuthorization)
	}
	if in.GrantManagementEnabled {
		doc.GrantManagementEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.GrantManagement)
		doc.GrantManagementActionsSupported = slices.Clone(in.GrantManagementActions)
		doc.GrantManagementActionRequired = in.GrantManagementActionRequired
	}
}

// applyJARFeature publishes the RFC 9101 request-object metadata when
// JAR is enabled.
//
// Wire-shape detail: the library admits "request_uri" only in the
// RFC 9126 §2.2 PAR form (urn:ietf:params:oauth:request_uri:*); a
// generic https URL is rejected at the parser
// (internal/authorize.ParseValues) because the OP-side fetcher
// RFC 9101 §10.2 requires (https-only / size cap / TTL / content-type
// / SSRF deny-list) is not implemented and FAPI 2.0 mandates PAR
// anyway. The discovery booleans below stay TRUE because there is no
// metadata key reserved for "PAR-only" — RPs discover the constraint
// by looking at pushed_authorization_request_endpoint and inspecting
// the URN prefix on the wire. Embedders that want a narrower
// advertisement override the document via [op.WithDiscoveryMetadata].
func applyJARFeature(in Input, doc *Document) {
	if !in.Features.JAR {
		return
	}
	doc.RequestParameterSupported = true
	doc.RequestURIParameterSupported = true
	// RFC 9101 §5.2.2 leaves the registration policy to the OP;
	// the library is strict (FAPI 2.0 Message Signing posture)
	// and refuses any request_uri the client has not preregistered.
	// The PAR-only stance documented above makes this advertisement
	// effectively trivial — every accepted request_uri is one the OP
	// itself minted at /par — but the field stays TRUE for parity
	// with conformance suites that probe it.
	doc.RequireRequestURIRegistration = true
	// RFC 9101 §10.1: advertise the JWS alg values the verifier
	// accepts on request objects. The list mirrors the project-
	// wide allow-list (internal/jose); operators that want to
	// pin a narrower set per-client use
	// [op/store.Client.RequestObjectSigningAlg].
	doc.RequestObjectSigningAlgValuesSupported = []string{
		"RS256", "PS256", "ES256", "EdDSA",
	}
}

// applyDPoPFeature publishes the RFC 9449 §5.1 alg list when DPoP is
// enabled. ES256 / EdDSA / PS256 covers FAPI 2.0 baseline plus the
// FAPI-recommended RSA-PSS scheme.
func applyDPoPFeature(in Input, doc *Document) {
	if !in.Features.DPoP {
		return
	}
	doc.DPoPSigningAlgValuesSupported = []string{"ES256", "EdDSA", "PS256"}
}

// applyMTLSFeature publishes the RFC 8705 binding signal, the §2 auth
// methods, and (when supplied) the §5 endpoint aliases. Aliases stay
// absent when MTLS itself is disabled even if the embedder pre-staged
// the option, so a feature toggle never leaks the alias map.
func applyMTLSFeature(in Input, doc *Document) {
	if !in.Features.MTLS {
		return
	}
	// RFC 8705 §3.3: the OP signals that it issues certificate-bound
	// access tokens. The flag covers both the §2 client-authentication
	// path and the §3 binding path; clients use it to decide whether
	// to present a certificate at /token in the first place.
	doc.TLSClientCertificateBoundAccessTokens = true
	// RFC 8705 §5: an OP that serves separate hostnames for its
	// mTLS-required endpoints publishes the alternative URLs here.
	// The field is published only when the embedder supplied at least
	// one alias; an MTLS-enabled deployment that fronts a single
	// hostname keeps this absent (the canonical *_endpoint values are
	// already mTLS-capable).
	if len(in.Metadata.MTLSEndpointAliases) > 0 {
		doc.MTLSEndpointAliases = maps.Clone(in.Metadata.MTLSEndpointAliases)
	}
}

// applyProfileNarrowing intersects the token-endpoint auth methods
// against the active profile's allow-list (FAPI 2.0 §3.1.3). The
// narrowing runs before the introspect / revoke mirrors so a single
// toggle keeps the three lists in lock-step.
func applyProfileNarrowing(in Input, doc *Document) {
	if len(in.ProfileAllowedAuthMethods) == 0 {
		return
	}
	doc.TokenEndpointAuthMethodsSupported = intersect(
		doc.TokenEndpointAuthMethodsSupported,
		in.ProfileAllowedAuthMethods,
	)
}

// applyDynamicRegistration publishes the registration endpoint and the
// initial-access-token auth method when RFC 7591 dynamic registration
// is enabled.
func applyDynamicRegistration(in Input, doc *Document) {
	if !in.Features.DynamicRegistration {
		return
	}
	doc.RegistrationEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Register)
	doc.RegistrationEndpointAuthMethodsSupported = []string{"initial_access_token"}
}

// applyJARMFeature publishes the four *.jwt response modes plus the
// signing-alg list (ES256 only, mirroring the rest of the OP's posture)
// when JARM is enabled. The legacy "query" / "form_post" entries come
// from [newBaseDocument]; this helper appends the JWT variants on top
// so a deployment without JARM still advertises form_post.
func applyJARMFeature(in Input, doc *Document) {
	if !in.Features.JARM {
		return
	}
	doc.ResponseModesSupported = append(doc.ResponseModesSupported,
		"query.jwt", "fragment.jwt", "form_post.jwt", "jwt")
	// The OP signs with ES256 only; the field stays single-valued
	// because the signing algorithm is fixed by design.
	doc.AuthorizationSigningAlgValuesSupported = []string{"ES256"}
}

// applyEndpointAuthMirrors copies the token-endpoint auth methods onto
// the introspection / revocation endpoints (RFC 8414 §2) and emits the
// assertion-bearing alg list (FAPI 2.0 §5.4 / OIDC Core §9) when one of
// those methods survives profile narrowing. The mirrors run AFTER every
// feature-driven extension so a single toggle of either feature keeps
// the lists in lock-step.
func applyEndpointAuthMirrors(in Input, doc *Document) {
	if in.Features.Introspect {
		doc.IntrospectionEndpointAuthMethodsSupported = append([]string(nil),
			doc.TokenEndpointAuthMethodsSupported...)
		// RFC 9701 §6: advertise the alg values the OP signs JWT-
		// formatted introspection responses with. The list mirrors
		// the ID-token / JARM posture (ES256 only) because the
		// signing key is shared.
		doc.IntrospectionSigningAlgValuesSupported = []string{"ES256"}
	}
	if in.Features.Revoke {
		doc.RevocationEndpointAuthMethodsSupported = append([]string(nil),
			doc.TokenEndpointAuthMethodsSupported...)
	}
	if containsAssertionBearingMethod(doc.TokenEndpointAuthMethodsSupported) {
		doc.TokenEndpointAuthSigningAlgValuesSupported = []string{
			"RS256", "PS256", "ES256", "EdDSA",
		}
	}
}

// applyClaimsSupported copies the embedder-supplied claims_supported
// list onto the document. Nil keeps the field omitted (the json
// omitempty tag covers both nil and empty slices) so the legacy wire
// shape is preserved when the option is not set; a non-nil empty slice
// round-trips as a non-nil empty slice through slices.Clone.
func applyClaimsSupported(in Input, doc *Document) {
	if in.ClaimsSupported == nil {
		return
	}
	doc.ClaimsSupported = slices.Clone(in.ClaimsSupported)
}

// applyACRValuesSupported publishes the OIDC Discovery 1.0 §3
// "acr_values_supported" array when the embedder opted in through
// op.WithACRValuesSupported. A non-nil slice is cloned so the wire
// output cannot be mutated through the caller's backing array;
// nil and empty are equivalent (the omitempty JSON tag drops both).
func applyACRValuesSupported(in Input, doc *Document) {
	if len(in.ACRValuesSupported) == 0 {
		return
	}
	doc.ACRValuesSupported = slices.Clone(in.ACRValuesSupported)
}

// applyAuthorizationDetailsTypesSupported publishes the RFC 9396 §10
// authorization_details_types_supported array when the embedder
// registered any types via op.WithAuthorizationDetailTypes. A non-nil
// slice is cloned; nil / empty stays omitted.
func applyAuthorizationDetailsTypesSupported(in Input, doc *Document) {
	if len(in.AuthorizationDetailsTypesSupported) == 0 {
		return
	}
	doc.AuthorizationDetailsTypesSupported = slices.Clone(in.AuthorizationDetailsTypesSupported)
}

// applyStaticMetadata copies the static RFC 8414 §2 metadata the
// embedder supplied through op.WithDiscoveryMetadata. The op layer has
// already rejected any Metadata.Extra key that collides with an
// OP-controlled field name, so the builder copies values verbatim.
// Empty strings and nil / empty slices stay omitted by virtue of the
// json:",omitempty" tag.
func applyStaticMetadata(in Input, doc *Document) {
	doc.ServiceDocumentation = in.Metadata.ServiceDocumentation
	doc.OPPolicyURI = in.Metadata.OPPolicyURI
	doc.OPTermsOfServiceURI = in.Metadata.OPTermsOfServiceURI
	if len(in.Metadata.UILocalesSupported) > 0 {
		doc.UILocalesSupported = slices.Clone(in.Metadata.UILocalesSupported)
	}
	if len(in.Metadata.Extra) > 0 {
		doc.Extra = maps.Clone(in.Metadata.Extra)
	}
}

// OPControlledFieldNames returns the JSON tag names of every field on
// [Document] that the OP itself populates. Embedders MUST NOT supply
// any of these names through [Metadata.Extra]; the op layer consults
// this list at construction time to surface a configuration error from
// op.New rather than silently dropping or overwriting the embedder's
// value at marshal time.
//
// The list is recomputed via reflection over the [Document] struct
// tags on every call so it stays in lock-step with the wire shape:
// adding a new field to [Document] automatically extends the
// deny-list. The reflection walk runs at op.New construction time
// only, so the per-call cost is negligible and a package-level cache
// is unnecessary.
//
// The four typed metadata fields ([Document.ServiceDocumentation] etc.)
// ARE included in the deny-list because the embedder supplies them
// through the named [Metadata] members rather than through Extra; an
// Extra entry whose key is "service_documentation" would create two
// sources of truth.
func OPControlledFieldNames() []string {
	t := reflect.TypeOf(Document{})
	out := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// containsAssertionBearingMethod reports whether methods includes a
// client authentication method whose proof is a JWT (private_key_jwt
// per RFC 7523 §3 or client_secret_jwt per RFC 7523 §3.1). The two
// methods are the only ones in the registry that consume the
// "client_assertion_type" parameter, so the alg advertisement applies
// to them and only them.
func containsAssertionBearingMethod(methods []string) bool {
	for _, m := range methods {
		if m == "private_key_jwt" || m == "client_secret_jwt" {
			return true
		}
	}
	return false
}

// join concatenates issuer + mountPrefix + endpoint into an absolute URL,
// handling the slash-collapsing edge cases. Empty endpoint segments are
// omitted; both issuer and mountPrefix are expected to be non-empty by
// the time Build is called.
func join(issuer, mountPrefix, endpoint string) string {
	if endpoint == "" {
		return ""
	}
	issuer = strings.TrimRight(issuer, "/")
	if mountPrefix == "/" {
		mountPrefix = ""
	} else {
		mountPrefix = strings.TrimRight(mountPrefix, "/")
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	return issuer + mountPrefix + endpoint
}

// defaultAuthMethods returns the auth-method advertisement, falling back
// to the v1.0 baseline when the caller does not supply an override. The
// baseline lists the symmetric secret methods plus private_key_jwt
// (OIDC Core §9 / RFC 7523 §3) — the OP wiring layer always installs
// the internal/clientauth.PrivateKeyJWTVerifier so a client whose
// metadata names "private_key_jwt" can authenticate out of the box.
func defaultAuthMethods(in []string) []string {
	if len(in) == 0 {
		return []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// intersect returns the elements of base that also appear in keep,
// preserving base's order. It is used by [Build] to apply the active
// [profile.Profile]'s auth-method allow-list without reshuffling the
// list the rest of the builder produced.
func intersect(base, keep []string) []string {
	if len(base) == 0 || len(keep) == 0 {
		return nil
	}
	allow := make(map[string]struct{}, len(keep))
	for _, v := range keep {
		allow[v] = struct{}{}
	}
	out := make([]string, 0, len(base))
	for _, v := range base {
		if _, ok := allow[v]; ok {
			out = append(out, v)
		}
	}
	return out
}
