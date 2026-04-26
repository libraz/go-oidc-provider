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

	// IntrospectionEndpoint is the absolute URL of the RFC 7662 token
	// introspection endpoint. Only emitted when the feature is enabled.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// RevocationEndpoint is the absolute URL of the RFC 7009 token
	// revocation endpoint. Only emitted when the feature is enabled.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

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
}
