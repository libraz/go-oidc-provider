package op

// Endpoints overrides the default URL paths the [Provider] mounts inside its
// router. Empty strings retain the library default; the [Provider] always
// substitutes a value, so callers MAY pass a partially-populated struct to
// override only the paths they care about.
//
// Paths MUST start with "/". The [Provider] strips the configured mount
// prefix from incoming requests before consulting these values, so the
// stored value is always relative to the mount point.
//
// The default values are listed in the matching field comments. They mirror
// OpenID Connect Core 1.0 / OpenID Connect Discovery 1.0 conventions and
// the project conventions documented in docs/plans/002-product-design.md
// §K.1.
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
}

// defaultEndpoints returns the endpoint paths the [Provider] uses when the
// caller does not supply [WithEndpoints]. The values are mounted relative
// to the configured MountPrefix (default "/oidc").
func defaultEndpoints() Endpoints {
	return Endpoints{
		Discovery:   "/.well-known/openid-configuration",
		JWKS:        "/jwks",
		Authorize:   "/auth",
		Token:       "/token",
		UserInfo:    "/userinfo",
		EndSession:  "/end_session",
		Introspect:  "/introspect",
		Revoke:      "/revoke",
		PAR:         "/par",
		Interaction: "/interaction",
		Session:     "/session",
	}
}

// merge returns the endpoint set resulting from layering override on top of
// e. Empty fields in override leave e's value untouched.
func (e Endpoints) merge(override Endpoints) Endpoints {
	out := e
	if override.Discovery != "" {
		out.Discovery = override.Discovery
	}
	if override.JWKS != "" {
		out.JWKS = override.JWKS
	}
	if override.Authorize != "" {
		out.Authorize = override.Authorize
	}
	if override.Token != "" {
		out.Token = override.Token
	}
	if override.UserInfo != "" {
		out.UserInfo = override.UserInfo
	}
	if override.EndSession != "" {
		out.EndSession = override.EndSession
	}
	if override.Introspect != "" {
		out.Introspect = override.Introspect
	}
	if override.Revoke != "" {
		out.Revoke = override.Revoke
	}
	if override.PAR != "" {
		out.PAR = override.PAR
	}
	if override.Interaction != "" {
		out.Interaction = override.Interaction
	}
	if override.Session != "" {
		out.Session = override.Session
	}
	return out
}
