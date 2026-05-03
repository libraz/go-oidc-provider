package discovery

import "encoding/json"

// Document is the JSON shape of the OpenID Connect Discovery 1.0 metadata
// response. Field names match the spec; optional members carry omitempty
// so deployments that disable a feature do not advertise dead endpoints.
//
// Adding fields is allowed in any minor release because the wire shape is
// dictated by the spec; removing fields requires a deprecation cycle.
type Document struct {
	// Issuer is the OP's canonical identifier (Discovery §3, "issuer").
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the absolute URL of the authorization
	// endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the absolute URL of the token endpoint.
	TokenEndpoint string `json:"token_endpoint"`

	// UserInfoEndpoint is the absolute URL of the UserInfo endpoint.
	UserInfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// JWKSURI is the absolute URL of the JWK Set the OP publishes.
	JWKSURI string `json:"jwks_uri"`

	// EndSessionEndpoint is the absolute URL of the RP-Initiated Logout
	// endpoint per OpenID Connect RP-Initiated Logout 1.0 §2.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	// BackchannelLogoutSupported reports whether the OP implements
	// OpenID Connect Back-Channel Logout 1.0 §2 — i.e. POSTs a Logout
	// Token to clients that registered a backchannel_logout_uri when
	// their session terminates. v1.0 always reports true; the field is
	// omitted from the wire only if the value is false (which the
	// library never sets) so RPs can rely on its presence.
	BackchannelLogoutSupported bool `json:"backchannel_logout_supported,omitempty"`

	// BackchannelLogoutSessionSupported reports whether the Logout
	// Tokens the OP issues carry the "sid" claim (OpenID Connect
	// Back-Channel Logout 1.0 §2.4). v1.0 emits "sid" whenever the
	// terminating session has a stable identifier, which is always the
	// case in this library, so the field is true.
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`

	// IntrospectionEndpoint is the absolute URL of the RFC 7662 token
	// introspection endpoint. Only emitted when the feature is enabled.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// IntrospectionEndpointAuthMethodsSupported lists the client
	// authentication methods accepted at the introspection endpoint.
	// RFC 8414 §2 advertises the field separately from the token
	// endpoint's so deployments may, in principle, accept different
	// methods at each. v1.0 mirrors the token endpoint's list (the
	// introspection handler reuses the same authentication machinery)
	// and only emits the field when the Introspect feature is enabled.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// RevocationEndpoint is the absolute URL of the RFC 7009 token
	// revocation endpoint. Only emitted when the feature is enabled.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// RevocationEndpointAuthMethodsSupported lists the client
	// authentication methods accepted at the revocation endpoint.
	// RFC 8414 §2 advertises the field separately from the token
	// endpoint's so deployments may, in principle, accept different
	// methods at each. v1.0 mirrors the token endpoint's list (the
	// revocation handler reuses the same authentication machinery)
	// and only emits the field when the Revoke feature is enabled.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// PushedAuthorizationRequestEndpoint is the absolute URL of the
	// RFC 9126 PAR endpoint. Only emitted when the feature is enabled.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`

	// RegistrationEndpoint is the absolute URL of the RFC 7591 Dynamic
	// Client Registration endpoint. Only emitted when the
	// DynamicRegistration feature is enabled.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// RegistrationEndpointAuthMethodsSupported lists the authentication
	// methods accepted at the registration endpoint. v1.0 advertises
	// "initial_access_token" only. Empty when the feature is disabled.
	RegistrationEndpointAuthMethodsSupported []string `json:"registration_endpoint_auth_methods_supported,omitempty"`

	// DeviceAuthorizationEndpoint is the absolute URL of the RFC 8628
	// §3.1 device-authorization endpoint. Only emitted when the OP is
	// configured to accept the device_code grant
	// (urn:ietf:params:oauth:grant-type:device_code).
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	// ResponseTypesSupported lists the response_type values the OP
	// accepts. v1.0 ships with "code" only (no implicit / hybrid).
	ResponseTypesSupported []string `json:"response_types_supported"`

	// GrantTypesSupported lists the grant_type values the token endpoint
	// accepts.
	GrantTypesSupported []string `json:"grant_types_supported"`

	// SubjectTypesSupported lists the subject_type values the OP can
	// produce. The slice always contains "public"; "pairwise" is
	// appended when the OP is configured with op.WithPairwiseSubject
	// or a custom op.WithSubjectGenerator that emits pairwise subs.
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// IDTokenSigningAlgValuesSupported lists the alg values the OP uses
	// to sign ID tokens. v1.0 is "ES256" only.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// ScopesSupported lists the scope values the OP advertises in
	// discovery. The op layer assembles the list from the OpenID
	// Connect Core 1.0 §5.4 standard scopes plus every embedder-
	// registered scope whose Public flag is true; non-public scopes
	// are intentionally absent from the wire.
	ScopesSupported []string `json:"scopes_supported"`

	// CodeChallengeMethodsSupported lists the PKCE methods the OP
	// accepts. v1.0 is "S256" only ("plain" is forbidden).
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`

	// TokenEndpointAuthMethodsSupported lists the client authentication
	// methods accepted at /token.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	// RequestParameterSupported reports whether the OP accepts the
	// "request" parameter (JAR). It is false unless the JAR feature is
	// enabled.
	RequestParameterSupported bool `json:"request_parameter_supported"`

	// RequestURIParameterSupported reports whether the OP accepts
	// "request_uri" (JAR). It is false unless JAR is enabled.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`

	// RequireRequestURIRegistration reports whether the OP requires
	// every "request_uri" value to appear in the client's preregistered
	// allowlist. The library enforces this unconditionally when JAR is
	// enabled (FAPI 2.0 Message Signing posture); the field is true
	// only when JAR is on so RPs can plan accordingly.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`

	// RequestObjectSigningAlgValuesSupported lists the JWS alg values
	// the OP accepts on a JAR request object (RFC 9101 §10.1). Only
	// emitted when the JAR feature is enabled; the list mirrors the
	// project-wide allow-list.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// RequirePushedAuthorizationRequests reports whether the OP requires
	// /par for every authorization request (FAPI 2.0 mandates it).
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests,omitempty"`

	// DPoPSigningAlgValuesSupported lists the JWS alg values the
	// OP accepts on the "DPoP" header (RFC 9449 §5.1). Only emitted
	// when the DPoP feature is enabled.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// TLSClientCertificateBoundAccessTokens reports whether the OP
	// issues RFC 8705 certificate-bound access tokens. The field is
	// false (and omitted from the wire) unless the MTLS feature is
	// enabled; clients consult it to decide whether to present a
	// client certificate at /token.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// MTLSEndpointAliases publishes the alternative URLs at which
	// the OP serves its mTLS-required endpoints (RFC 8705 §5). Only
	// emitted when the MTLS feature is enabled AND the embedder
	// supplied a non-empty alias map through op.WithDiscoveryMetadata.
	// A deployment that fronts a single hostname keeps this absent —
	// the canonical *_endpoint values are already reachable over
	// mTLS — and embedders that need the field publish it explicitly
	// to declare the alternative host topology.
	MTLSEndpointAliases map[string]string `json:"mtls_endpoint_aliases,omitempty"`

	// ResponseModesSupported lists the response_mode values the OP
	// accepts at /authorize. The default v1.0 set is omitted from the
	// wire (the spec defines well-known defaults); the field becomes
	// non-empty when the JARM feature is enabled so clients can
	// discover the *.jwt variants.
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// AuthorizationSigningAlgValuesSupported lists the alg values the
	// OP uses when signing JARM responses. v1.0 is "ES256" only.
	// Emitted only when the JARM feature is enabled.
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`

	// IntrospectionSigningAlgValuesSupported lists the JWS alg values
	// the OP signs JWT-formatted introspection responses with
	// (RFC 9701 §6). v1.0 is "ES256" only. Emitted only when the
	// Introspect feature is enabled because the field is meaningless
	// without a /introspect endpoint.
	IntrospectionSigningAlgValuesSupported []string `json:"introspection_signing_alg_values_supported,omitempty"`

	// TokenEndpointAuthSigningAlgValuesSupported lists the JWS alg
	// values the OP accepts on a "client_assertion" JWT
	// (RFC 7521 + RFC 7523 + OIDC Core 1.0 §9). The field is meaningful
	// only when the OP advertises an assertion-bearing auth method
	// (private_key_jwt or client_secret_jwt); it is omitted otherwise.
	// FAPI 2.0 §5.4 requires the field to be present and its values to
	// reflect the alg allowlist actually enforced at /token.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// AuthorizationResponseIssParameterSupported reports whether the
	// OP returns the RFC 9207 "iss" parameter on authorization
	// responses. Defensive against mix-up attacks; FAPI 2.0 §5.3.2.2
	// mandates it. The library always emits "iss" so the field is
	// always true when emitted (omitempty drops the false default).
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`

	// IDTokenEncryptionAlgValuesSupported lists the JWE alg values
	// the OP can use to encrypt id_tokens for clients whose metadata
	// requests encryption (OIDC Discovery 1.0 §3
	// "id_token_encryption_alg_values_supported"). The list mirrors
	// the OP's encryption keyset alg allow-list. Emitted only when
	// op.WithEncryptionKeyset has been supplied.
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// IDTokenEncryptionEncValuesSupported lists the JWE enc values
	// the OP can use to encrypt id_tokens (OIDC Discovery 1.0 §3
	// "id_token_encryption_enc_values_supported"). Emitted only
	// when op.WithEncryptionKeyset has been supplied.
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// UserInfoEncryptionAlgValuesSupported lists the JWE alg values
	// the OP can use to encrypt UserInfo responses (OIDC Discovery
	// 1.0 §3 "userinfo_encryption_alg_values_supported"). Emitted
	// only when op.WithEncryptionKeyset has been supplied.
	UserInfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// UserInfoEncryptionEncValuesSupported lists the JWE enc values
	// the OP can use to encrypt UserInfo responses (OIDC Discovery
	// 1.0 §3 "userinfo_encryption_enc_values_supported"). Emitted
	// only when op.WithEncryptionKeyset has been supplied.
	UserInfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// RequestObjectEncryptionAlgValuesSupported lists the JWE alg
	// values the OP accepts on a JAR request object (OIDC Discovery
	// 1.0 §3 "request_object_encryption_alg_values_supported", RFC
	// 9101 §10.1). Emitted only when op.WithEncryptionKeyset has
	// been supplied AND the JAR feature is enabled.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`

	// RequestObjectEncryptionEncValuesSupported lists the JWE enc
	// values the OP accepts on a JAR request object (OIDC Discovery
	// 1.0 §3 "request_object_encryption_enc_values_supported").
	// Emitted only when op.WithEncryptionKeyset has been supplied
	// AND the JAR feature is enabled.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// AuthorizationEncryptionAlgValuesSupported lists the JWE alg
	// values the OP can use to encrypt JARM responses (OAuth 2.0
	// JARM §10.1 "authorization_encryption_alg_values_supported").
	// Emitted only when op.WithEncryptionKeyset has been supplied
	// AND the JARM feature is enabled.
	AuthorizationEncryptionAlgValuesSupported []string `json:"authorization_encryption_alg_values_supported,omitempty"`

	// AuthorizationEncryptionEncValuesSupported lists the JWE enc
	// values the OP can use to encrypt JARM responses. Emitted only
	// when op.WithEncryptionKeyset has been supplied AND the JARM
	// feature is enabled.
	AuthorizationEncryptionEncValuesSupported []string `json:"authorization_encryption_enc_values_supported,omitempty"`

	// IntrospectionEncryptionAlgValuesSupported lists the JWE alg
	// values the OP can use to encrypt JWT-formatted introspection
	// responses (RFC 9701 §6 + OIDC Discovery 1.0 §3 by analogy with
	// id_token / userinfo). Emitted only when op.WithEncryptionKeyset
	// has been supplied AND the Introspect feature is enabled.
	IntrospectionEncryptionAlgValuesSupported []string `json:"introspection_encryption_alg_values_supported,omitempty"`

	// IntrospectionEncryptionEncValuesSupported lists the JWE enc
	// values the OP can use to encrypt introspection responses.
	// Emitted only when op.WithEncryptionKeyset has been supplied
	// AND the Introspect feature is enabled.
	IntrospectionEncryptionEncValuesSupported []string `json:"introspection_encryption_enc_values_supported,omitempty"`

	// ClaimsParameterSupported reports whether the OP honours the
	// OIDC Core 1.0 §5.5 "claims" request parameter — i.e. parses the
	// payload, persists it on the originating grant, and projects the
	// requested claims onto the id_token / userinfo responses. The
	// library defaults to true because the parser is always wired;
	// embedders that prefer to ignore the parameter can
	// opt out via op.WithClaimsParameterSupported(false), which sets
	// this field to false and routes incoming requests around the
	// parser.
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`

	// ClaimsSupported lists the claim names the OP can emit on
	// id_token / userinfo responses. OIDC Discovery 1.0 §3 lists this
	// field as RECOMMENDED but allows the OP to omit it when the OP
	// does not pre-enumerate its claim universe; the library leaves
	// it unset by default because the surface depends on the
	// configured user store. Embedders publish the closed list via
	// op.WithClaimsSupported(...).
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// ACRValuesSupported lists the Authentication Context Class
	// Reference values the OP advertises (OIDC Discovery 1.0 §3,
	// "acr_values_supported", OPTIONAL). The values come from the
	// OP's local trust framework or federation profile (RFC 8176
	// authentication-method references, NIST SP 800-63 step-up
	// labels, custom URNs); the library leaves the field unset by
	// default. Embedders publish the closed list via
	// op.WithACRValuesSupported(...).
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// ServiceDocumentation is the URL of a human-readable page that
	// documents the OP for developers. RFC 8414 §2 lists the field as
	// RECOMMENDED. The library does not own the URL; the embedder
	// supplies it through op.WithDiscoveryMetadata.
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// OPPolicyURI is the URL of the OP's privacy policy page.
	// OpenID Connect Discovery 1.0 §3 / RFC 8414 §2 list the field
	// as RECOMMENDED. Embedder-supplied via op.WithDiscoveryMetadata.
	OPPolicyURI string `json:"op_policy_uri,omitempty"`

	// OPTermsOfServiceURI is the URL of the OP's terms-of-service
	// page. OpenID Connect Discovery 1.0 §3 / RFC 8414 §2 list the
	// field as RECOMMENDED. Embedder-supplied via
	// op.WithDiscoveryMetadata.
	OPTermsOfServiceURI string `json:"op_tos_uri,omitempty"`

	// UILocalesSupported lists the BCP 47 language tags the OP's
	// human-facing UI supports. OpenID Connect Discovery 1.0 §3 /
	// RFC 8414 §2 list the field as OPTIONAL. Embedder-supplied via
	// op.WithDiscoveryMetadata.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// Extra carries embedder-supplied passthrough fields that are not
	// otherwise modelled on Document. The map is merged into the wire
	// output at the top level by Document.MarshalJSON; keys that
	// collide with an OP-controlled field are rejected at OP build
	// time (see op.WithDiscoveryMetadata). The field is internal to
	// the discovery package and never appears under its own JSON tag.
	Extra map[string]any `json:"-"`
}

// MarshalJSON serialises the discovery [Document] and merges any
// embedder-supplied [Document.Extra] entries at the top level of the
// JSON object. The merge runs at marshal time so the on-the-wire shape
// is the union of OP-controlled fields and embedder passthrough; the
// override-deny check that prevents Extra from clobbering OP-controlled
// fields runs earlier (op.WithDiscoveryMetadata) so a collision surfaces
// at op.New, not on first /.well-known fetch.
func (d Document) MarshalJSON() ([]byte, error) {
	type alias Document
	core, err := json.Marshal(alias(d))
	if err != nil {
		return nil, err
	}
	if len(d.Extra) == 0 {
		return core, nil
	}
	// Decode the core into a generic map so we can merge passthrough
	// keys without re-implementing the struct's omitempty handling.
	var merged map[string]any
	if err := json.Unmarshal(core, &merged); err != nil {
		return nil, err
	}
	if merged == nil {
		merged = make(map[string]any, len(d.Extra))
	}
	for k, v := range d.Extra {
		merged[k] = v
	}
	return json.Marshal(merged)
}
