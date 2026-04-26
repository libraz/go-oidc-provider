package discovery

import (
	"strings"
)

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
}

// EndpointPaths mirrors op.Endpoints with internal-friendly types.
type EndpointPaths struct {
	JWKS        string
	Authorize   string
	Token       string
	UserInfo    string
	EndSession  string
	Introspect  string
	Revoke      string
	PAR         string
	Interaction string
	Session     string
}

// Features carries the enable bits for optional protocol extensions.
type Features struct {
	PAR        bool
	JAR        bool
	JARM       bool
	DPoP       bool
	MTLS       bool
	Introspect bool
	Revoke     bool
}

// Build returns a [Document] populated from in. Absolute URLs are formed
// by joining the issuer, mount prefix, and endpoint paths.
func Build(in Input) Document {
	doc := Document{
		Issuer:                            in.Issuer,
		AuthorizationEndpoint:             join(in.Issuer, in.MountPrefix, in.Endpoints.Authorize),
		TokenEndpoint:                     join(in.Issuer, in.MountPrefix, in.Endpoints.Token),
		UserInfoEndpoint:                  join(in.Issuer, in.MountPrefix, in.Endpoints.UserInfo),
		JWKSURI:                           join(in.Issuer, in.MountPrefix, in.Endpoints.JWKS),
		EndSessionEndpoint:                join(in.Issuer, in.MountPrefix, in.Endpoints.EndSession),
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               in.GrantsSupported,
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		ScopesSupported:                   defaultScopes(),
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: defaultAuthMethods(in.AuthMethodsSupported),
	}
	if in.Features.PAR {
		doc.PushedAuthorizationRequestEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.PAR)
	}
	if in.Features.Introspect {
		doc.IntrospectionEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Introspect)
	}
	if in.Features.Revoke {
		doc.RevocationEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Revoke)
	}
	if in.Features.JAR {
		doc.RequestParameterSupported = true
		doc.RequestURIParameterSupported = true
	}
	return doc
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

// defaultScopes returns the OpenID Connect Core 1.0 §5.4 scope set the OP
// recognises out of the box. Custom scopes registered via op.WithScope
// (Phase 2) are appended to this list at higher layers.
func defaultScopes() []string {
	return []string{"openid", "profile", "email", "address", "phone", "offline_access"}
}

// defaultAuthMethods returns the auth-method advertisement, falling back to
// the v1.0 baseline (client_secret_basic + client_secret_post) when the
// caller does not supply an override.
func defaultAuthMethods(in []string) []string {
	if len(in) == 0 {
		return []string{"client_secret_basic", "client_secret_post"}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
