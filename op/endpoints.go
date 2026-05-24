package op

// Endpoints overrides the default URL paths the [Provider] mounts inside its
// router. Empty strings retain the library default; the [Provider] always
// substitutes a value, so callers MAY pass a partially-populated struct to
// override only the paths they care about.
// Paths MUST start with "/". The [Provider] strips the configured mount
// prefix from incoming requests before consulting these values, so the
// stored value is always relative to the mount point.
// The default values are listed in the matching field comments. They mirror
// OpenID Connect Core 1.0 / OpenID Connect Discovery 1.0 conventions.
type Endpoints struct {
	// Discovery overrides /.well-known/openid-configuration. It is mounted
	// outside the configured MountPrefix because OpenID Connect
	// Discovery 1.0 §4 requires it under /.well-known.
	Discovery string

	// JWKS overrides /jwks. Default: "/jwks" relative to MountPrefix.
	JWKS string

	// Authorize overrides the authorization endpoint. Default: "/auth".
	Authorize string

	// Token overrides the token endpoint. Default: "/token".
	Token string

	// UserInfo overrides the UserInfo endpoint. Default: "/userinfo".
	UserInfo string

	// EndSession overrides the RP-Initiated Logout endpoint. Default:
	// "/end_session".
	EndSession string

	// Introspect overrides the token introspection endpoint. Default:
	// "/introspect". Only mounted when the Introspect feature is enabled.
	Introspect string

	// Revoke overrides the token revocation endpoint. Default: "/revoke".
	// Only mounted when the Revoke feature is enabled.
	Revoke string

	// PAR overrides the Pushed Authorization Request endpoint.
	// Default: "/par". Only mounted when the PAR feature is enabled.
	PAR string

	// Interaction overrides the SPA interaction prefix. The library
	// appends /{uid} and operation-specific suffixes. Default:
	// "/interaction".
	Interaction string

	// Session overrides the SPA session prefix. Default: "/session".
	Session string

	// Register overrides the RFC 7591 Dynamic Client Registration
	// endpoint. Default: "/register". Only mounted when the
	// DynamicRegistration feature is enabled via
	// [WithDynamicRegistration]; the discovery document advertises
	// "registration_endpoint" with the same gating.
	Register string

	// DeviceAuthorization overrides the RFC 8628 §3.1
	// device-authorization endpoint. Default: "/device_authorization".
	// Only mounted when the device_code grant is configured via
	// [WithDeviceCodeGrant] (or by including [grant.DeviceCode] in
	// [WithGrants]); the discovery document advertises
	// "device_authorization_endpoint" with the same gating.
	DeviceAuthorization string

	// Backchannel overrides the CIBA Core 1.0 §7
	// backchannel-authentication endpoint. Default: "/bc-authorize".
	// Only mounted when the CIBA grant is configured via [WithCIBA]
	// (or by including [grant.CIBA] in [WithGrants]); the discovery
	// document advertises "backchannel_authentication_endpoint" with
	// the same gating.
	Backchannel string

	// GrantManagement overrides the OAuth 2.0 Grant Management draft
	// endpoint. Default: "/grant_management". Only mounted when the
	// feature is enabled via [WithGrantManagement]; the discovery
	// document advertises "grant_management_endpoint" with the same
	// gating.
	GrantManagement string
}

// defaultEndpoints returns the endpoint paths the [Provider] uses when the
// caller does not supply [WithEndpoints]. The values are mounted relative
// to the configured MountPrefix (default "/oidc").
func defaultEndpoints() Endpoints {
	return Endpoints{
		Discovery:           "/.well-known/openid-configuration",
		JWKS:                "/jwks",
		Authorize:           "/auth",
		Token:               "/token",
		UserInfo:            "/userinfo",
		EndSession:          "/end_session",
		Introspect:          "/introspect",
		Revoke:              "/revoke",
		PAR:                 "/par",
		Interaction:         "/interaction",
		Session:             "/session",
		Register:            "/register",
		DeviceAuthorization: "/device_authorization",
		Backchannel:         "/bc-authorize",
		GrantManagement:     "/grant_management",
	}
}

// merge returns the endpoint set resulting from layering override on top of
// e. Empty fields in override leave e's value untouched.
func (e Endpoints) merge(override Endpoints) Endpoints {
	return Endpoints{
		Discovery:           pickEndpoint(override.Discovery, e.Discovery),
		JWKS:                pickEndpoint(override.JWKS, e.JWKS),
		Authorize:           pickEndpoint(override.Authorize, e.Authorize),
		Token:               pickEndpoint(override.Token, e.Token),
		UserInfo:            pickEndpoint(override.UserInfo, e.UserInfo),
		EndSession:          pickEndpoint(override.EndSession, e.EndSession),
		Introspect:          pickEndpoint(override.Introspect, e.Introspect),
		Revoke:              pickEndpoint(override.Revoke, e.Revoke),
		PAR:                 pickEndpoint(override.PAR, e.PAR),
		Interaction:         pickEndpoint(override.Interaction, e.Interaction),
		Session:             pickEndpoint(override.Session, e.Session),
		Register:            pickEndpoint(override.Register, e.Register),
		DeviceAuthorization: pickEndpoint(override.DeviceAuthorization, e.DeviceAuthorization),
		Backchannel:         pickEndpoint(override.Backchannel, e.Backchannel),
		GrantManagement:     pickEndpoint(override.GrantManagement, e.GrantManagement),
	}
}

// pickEndpoint returns override when it is non-empty, else base. It keeps
// [Endpoints.merge] a flat field map rather than a long if-ladder.
func pickEndpoint(override, base string) string {
	if override != "" {
		return override
	}
	return base
}
