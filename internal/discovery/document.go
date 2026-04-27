package discovery

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

	// ResponseTypesSupported lists the response_type values the OP
	// accepts. v1.0 ships with "code" only (no implicit / hybrid).
	ResponseTypesSupported []string `json:"response_types_supported"`

	// GrantTypesSupported lists the grant_type values the token endpoint
	// accepts.
	GrantTypesSupported []string `json:"grant_types_supported"`

	// SubjectTypesSupported lists the subject_type values the OP can
	// produce. v1.0 ships with "public"; pairwise lands later.
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
}
