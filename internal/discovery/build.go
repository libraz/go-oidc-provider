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
		BackchannelLogoutSupported:        true,
		BackchannelLogoutSessionSupported: true,
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
	// FAPI 2.0 §3.1.3 narrowing: when an active profile constrains the
	// token-endpoint auth methods, intersect the advertised list with
	// the profile's allow-list before downstream fields (introspect /
	// revoke) take their copy. Filtering here keeps the three lists in
	// lock-step under a single toggle.
	if len(in.ProfileAllowedAuthMethods) > 0 {
		doc.TokenEndpointAuthMethodsSupported = intersect(
			doc.TokenEndpointAuthMethodsSupported,
			in.ProfileAllowedAuthMethods,
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
		// RFC 9701 §6: advertise the alg values the OP signs JWT-
		// formatted introspection responses with. The list mirrors
		// the ID-token / JARM posture (ES256 only) because the
		// signing key is shared.
		doc.IntrospectionSigningAlgValuesSupported = []string{"ES256"}
	}
	// RFC 8414 §2: the revocation endpoint advertises its client
	// authentication methods separately from the token endpoint. v1.0
	// reuses the same client-auth machinery at both, so the list
	// mirrors token_endpoint_auth_methods_supported. The copy happens
	// AFTER every feature-driven extension so the two fields stay in
	// lock-step on a single toggle of either feature.
	if in.Features.Revoke {
		doc.RevocationEndpointAuthMethodsSupported = append([]string(nil),
			doc.TokenEndpointAuthMethodsSupported...)
	}
	// FAPI 2.0 §5.4 / OIDC Core 1.0 §9: when the OP advertises an
	// assertion-bearing client authentication method (private_key_jwt
	// or client_secret_jwt) at /token, it MUST advertise the JWS alg
	// values it accepts on the assertion. v1.0 enforces the same
	// allow-list as the JAR / private_key_jwt verifier
	// ([internal/jose] + [internal/clientauth]), so the field's
	// content mirrors the request-object alg list that already gates
	// JAR. Emit the field whenever an assertion-bearing method made
	// it through the post-profile filter above.
	if containsAssertionBearingMethod(doc.TokenEndpointAuthMethodsSupported) {
		doc.TokenEndpointAuthSigningAlgValuesSupported = []string{
			"RS256", "PS256", "ES256", "EdDSA",
		}
	}
	// RFC 9207: every authorization response (success and error)
	// carries an "iss" parameter set to the OP's issuer. The library
	// emits it unconditionally — it is defense-in-depth against
	// mix-up attacks and is mandated by FAPI 2.0 §5.3.2.2.
	doc.AuthorizationResponseIssParameterSupported = true
	return doc
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

// defaultAuthMethods returns the auth-method advertisement, falling back to
// the v1.0 baseline when the caller does not supply an override. The
// baseline lists the symmetric secret methods plus private_key_jwt
// (OIDC Core §9 / RFC 7523 §3) — the OP wiring layer always installs
// the [internal/clientauth.PrivateKeyJWTVerifier] so a client whose
// metadata names "private_key_jwt" can authenticate out of the box.
// tls_client_auth / self_signed_tls_client_auth are appended only
// when the [feature.MTLS] flag is on; they live behind a feature
// gate because they require a [internal/mtls] verifier and a
// terminating-mTLS deployment shape.
func defaultAuthMethods(in []string) []string {
	if len(in) == 0 {
		return []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}
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
