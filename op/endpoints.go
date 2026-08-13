package op

import "net/url"

// Endpoints overrides the default URL paths the [Provider] mounts inside its
// router. Empty strings retain the library default; the [Provider] always
// substitutes a value, so callers MAY pass a partially-populated struct to
// override only the paths they care about.
// Paths MUST be clean absolute request paths beginning with "/". Query
// strings, fragments, trailing or duplicate slashes, percent-encoding, and
// net/http wildcard syntax are rejected at [New] construction time. Values
// are relative to the configured mount point and to any path carried by the
// issuer URL.
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
	//
	// Deprecated: the [Provider] mounts no handler under this prefix
	// and the discovery document does not advertise it. The path is
	// validated and reserved against the OP's other endpoint paths, so
	// overriding it only changes which paths [New] reports as
	// colliding. Session state is served under Interaction — or, when
	// [WithSPAUI] is configured, under [SPAUI.LoginMount].
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

// protocolEndpointPath returns the request path for an endpoint advertised as
// issuer + mount prefix + endpoint. Issuer paths are part of the public
// endpoint namespace, not merely metadata: an issuer such as
// https://idp.example.com/tenant therefore serves the default token endpoint
// at /tenant/oidc/token.
func protocolEndpointPath(c *config, endpoint string) string {
	return joinPath(routingMountPrefix(c.issuer, c.mountPrefix), endpoint)
}

// discoveryEndpointPath returns the request path for the discovery document.
// RFC 8414 §3 inserts the well-known suffix before an issuer path, so issuer
// https://idp.example.com/tenant is discovered at
// /.well-known/openid-configuration/tenant.
func discoveryEndpointPath(c *config) string {
	return joinPath(c.endpoints.Discovery, issuerPath(c.issuer))
}

// discoveryConcatenatedPath returns the second request path an issuer with a
// path is discovered at, or "" when no second mount is needed. OpenID Connect
// Discovery 1.0 §4 appends the well-known suffix to the issuer, so issuer
// https://idp.example.com/tenant is also discovered at
// /tenant/.well-known/openid-configuration — the URL a conformant relying
// party derives. A bare-host issuer produces the same path under both rules
// and must be mounted once, because http.ServeMux panics when one pattern
// is registered twice.
func discoveryConcatenatedPath(c *config) string {
	base := issuerPath(c.issuer)
	if base == "" {
		return ""
	}
	return joinPath(base, c.endpoints.Discovery)
}

// conflictingRouteName reports the active route that path would collide with,
// if any. The construction-time collision check reasons about the configured
// endpoints alone; the concatenated discovery path is derived from the issuer
// and the mount prefix together, so the router checks it separately rather
// than letting http.ServeMux panic.
func conflictingRouteName(c *config, path string) (string, bool) {
	candidate := routeReservation{path: path}
	for _, reserved := range c.activeRouteReservations() {
		if routesConflict(candidate, reserved) {
			return reserved.name, true
		}
	}
	return "", false
}

// routingMountPrefix combines the issuer path and the embedder-selected mount
// prefix into the base path used by protocol handlers.
func routingMountPrefix(issuer, mountPrefix string) string {
	base := issuerPath(issuer)
	if base == "" {
		return mountPrefix
	}
	if mountPrefix == "/" {
		return base
	}
	return base + mountPrefix
}

// issuerPath extracts the decoded URL path used by net/http for routing.
// WithIssuer validates the URL before any caller reaches this helper.
func issuerPath(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return u.Path
}

// joinPath concatenates two validated absolute request paths without
// introducing a duplicate slash.
func joinPath(base, endpoint string) string {
	if endpoint == "" {
		return base
	}
	if base == "" || base == "/" {
		return endpoint
	}
	if endpoint == "/" {
		return base
	}
	return base + endpoint
}
