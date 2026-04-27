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

	// ScopesSupported lists the scope identifiers the OP advertises
	// in the discovery document. The op layer pre-filters this list
	// (built-in standard scopes plus every registered scope whose
	// Public flag is true) so the discovery builder does not need
	// any policy of its own.
	ScopesSupported []string
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
	Register    string
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
		ScopesSupported:                   append([]string(nil), in.ScopesSupported...),
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
		// RFC 9101 §5.2.2 leaves the registration policy to the OP;
		// the library is strict (FAPI 2.0 Message Signing posture)
		// and refuses any request_uri the client has not preregistered.
		doc.RequireRequestURIRegistration = true
		// RFC 9101 §10.1: advertise the JWS alg values the verifier
		// accepts on request objects. The list mirrors the project-
		// wide allow-list ([internal/jose]); operators that want to
		// pin a narrower set per-client use
		// [op/store.Client.RequestObjectSigningAlg].
		doc.RequestObjectSigningAlgValuesSupported = []string{
			"RS256", "PS256", "ES256", "EdDSA",
		}
	}
	if in.Features.DPoP {
		// RFC 9449 §5.1: emit the alg values the OP accepts on
		// proof JWTs. The list mirrors [internal/dpop] allowed
		// algorithms; ES256 / EdDSA is the FAPI 2.0 baseline.
		doc.DPoPSigningAlgValuesSupported = []string{"ES256", "EdDSA"}
	}
	if in.Features.MTLS {
		// RFC 8705 §3.3: the OP signals that it issues
		// certificate-bound access tokens. The flag covers both
		// the §2 client-authentication path and the §3 binding
		// path; clients use it to decide whether to present a
		// certificate at /token in the first place.
		doc.TLSClientCertificateBoundAccessTokens = true
		// Append the §2 auth methods so a client can discover
		// whether tls_client_auth / self_signed_tls_client_auth
		// are accepted at /token without trial-and-error.
		doc.TokenEndpointAuthMethodsSupported = appendUnique(
			doc.TokenEndpointAuthMethodsSupported,
			"tls_client_auth",
			"self_signed_tls_client_auth",
		)
	}
	if in.Features.DynamicRegistration {
		doc.RegistrationEndpoint = join(in.Issuer, in.MountPrefix, in.Endpoints.Register)
		doc.RegistrationEndpointAuthMethodsSupported = []string{"initial_access_token"}
	}
	if in.Features.JARM {
		// JARM (OpenID FAPI WG): advertise the four *.jwt response
		// modes alongside the legacy "query" / "form_post" so clients
		// can discover the protection without trial-and-error.
		doc.ResponseModesSupported = []string{
			"query", "form_post",
			"query.jwt", "fragment.jwt", "form_post.jwt", "jwt",
		}
		// v1.0 signs with ES256 only; keep the field single-valued so
		// embedders that grow the algorithm list see a stable shape.
		doc.AuthorizationSigningAlgValuesSupported = []string{"ES256"}
	}
	// RFC 8414 §2: the introspection endpoint advertises its client
	// authentication methods separately from the token endpoint. v1.0
	// reuses the same client-auth machinery at both, so the list
	// mirrors token_endpoint_auth_methods_supported. The copy happens
	// AFTER every feature-driven extension (mTLS appends
	// tls_client_auth / self_signed_tls_client_auth above) so the two
	// fields stay in lock-step on a single toggle of either feature.
	if in.Features.Introspect {
		doc.IntrospectionEndpointAuthMethodsSupported = append([]string(nil),
			doc.TokenEndpointAuthMethodsSupported...)
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

// appendUnique returns base with each entry from extra appended exactly
// once, preserving the original order. The helper exists so the mTLS
// branch above can extend the auth-method list without duplicating
// values an embedder may have already named in
// [Input.AuthMethodsSupported].
func appendUnique(base []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, v := range base {
		seen[v] = struct{}{}
	}
	out := append([]string(nil), base...)
	for _, v := range extra {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
