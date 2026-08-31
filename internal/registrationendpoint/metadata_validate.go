package registrationendpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	internaljose "github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
)

// validatePolicy enforces the OP's structural rules on client metadata:
// redirect / logout URI shape, the grant + response_type whitelists and
// their consistency, the client-authentication method and its signing
// alg, subject_type, the requested scope set, the JWKS configuration,
// and the JOSE alg / enc values each surface may name (narrowed by
// jwePolicy). It returns the canonicalised metadata (defaults applied,
// scopes parsed) on success and a [validationError] on the first rule
// violation.
//
// The validator does not invoke [Deps.ValidateMetadata]; the handler
// runs that hook after structural validation passes so embedder code
// only sees metadata that already cleared the library checks.
//
// The validator never widens the submitted scope. Filling an omitted
// scope member with a default belongs to the registration path (see
// [defaultScopeIfEmpty]), which is the only path that knows which
// authority admitted the client; a management update therefore reaches
// this function with the scope the client actually submitted, and an
// omitted member stays omitted instead of collecting the OP's catalog.
// iatScopes remains the ceiling every named scope is held against.
func validatePolicy(
	m ClientMetadata,
	allowedGrantTypes []string,
	allowedResponseTypes []string,
	iatScopes []string,
	scopes *scoperegistry.Registry,
	pairwiseEnabled bool,
	allowLocalhostLoopback bool,
	allowInsecureBackchannelLogoutForDev bool,
	jwePolicy internaljose.JWEPolicy,
) (ClientMetadata, error) {
	if len(m.RedirectURIs) == 0 {
		return ClientMetadata{}, errInvalidRedirectURI("redirect_uris is required")
	}
	canonical := applyMetadataDefaults(m, allowedGrantTypes, allowedResponseTypes)
	if err := validateSignedResponseAlg(introspectionSignedResponseSurface(), canonical.IntrospectionSignedResponseAlg); err != nil {
		return ClientMetadata{}, err
	}
	canonical.IntrospectionSignedResponseAlg = normalizeIntrospectionSignedResponseAlg(canonical.IntrospectionSignedResponseAlg)
	checks := []func() error{
		func() error {
			return validateRedirectURIs(canonical.RedirectURIs, canonical.ApplicationType, hasImplicitResponseType(canonical.ResponseTypes), allowLocalhostLoopback)
		},
		func() error { return validateGrantTypes(canonical.GrantTypes, allowedGrantTypes) },
		func() error { return validateResponseTypes(canonical.ResponseTypes, allowedResponseTypes) },
		func() error {
			return validateGrantResponseTypeConsistency(canonical.GrantTypes, canonical.ResponseTypes)
		},
		func() error { return validateAuthMethod(canonical.TokenEndpointAuthMethod) },
		func() error { return validateTokenEndpointAuthSigningAlg(canonical.TokenEndpointAuthSigningAlg) },
		func() error { return validateSubjectType(canonical.SubjectType, pairwiseEnabled) },
		func() error {
			return validateSignedResponseAlg(idTokenSignedResponseSurface(), canonical.IDTokenSignedResponseAlg)
		},
		func() error { return validateRequestedScopes(canonical.Scope, iatScopes, scopes) },
		func() error { return validateMetadataURIs(canonical, allowInsecureBackchannelLogoutForDev) },
		func() error { return validateRequestObjectSigningAlg(canonical.RequestObjectSigningAlg) },
		func() error {
			return validateRequestObjectEncryption(canonical.RequestObjectEncryptionAlg, canonical.RequestObjectEncryptionEnc, jwePolicy)
		},
		func() error {
			return validateIDTokenResponseEncryption(canonical.IDTokenEncryptedResponseAlg, canonical.IDTokenEncryptedResponseEnc, jwePolicy)
		},
		func() error {
			return validateUserInfoResponseEncryption(canonical.UserInfoEncryptedResponseAlg, canonical.UserInfoEncryptedResponseEnc, jwePolicy)
		},
		func() error {
			return validateAuthorizationResponseEncryption(canonical.AuthorizationEncryptedResponseAlg, canonical.AuthorizationEncryptedResponseEnc, jwePolicy)
		},
		func() error {
			return validateIntrospectionResponseEncryption(canonical.IntrospectionEncryptedResponseAlg, canonical.IntrospectionEncryptedResponseEnc, jwePolicy)
		},
		func() error { return validateJWKSConfiguration(canonical, jwePolicy) },
		func() error { return validatePairwiseMetadata(canonical) },
		func() error { return validateDefaultMaxAge(canonical.DefaultMaxAge) },
		func() error {
			return validatePostLogoutRedirectURIs(canonical.PostLogoutRedirectURIs, canonical.ApplicationType, allowLocalhostLoopback)
		},
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return ClientMetadata{}, err
		}
	}
	return canonical, nil
}

// validateUnpersistedMetadata rules on the standard members the OP
// parses but does not store. Both handlers run it before
// [validatePolicy] so a request that asks for something the OP will not
// deliver is refused at registration time rather than silently accepted
// and quietly ignored.
//
// The members fall into two groups:
//
//   - Response-signing algorithms for the surfaces whose shape is not
//     client-configurable: UserInfo and the JARM authorization response.
//     Both are held against [validateSignedResponseAlg] exactly like the
//     persisted introspection member, so a client learns at registration
//     time which shape it will receive. m supplies the UserInfo
//     encryption metadata the UserInfo surface depends on; see
//     [userInfoSignedResponseSurface].
//   - Per-client enforcement flags. Asking the OP to require DPoP
//     (RFC 9449 §5.2), certificate-bound access tokens (RFC 8705 §3.4)
//     or pushed authorization requests (RFC 9126 §6.2) from this client
//     specifically is a hardening the OP applies globally or per
//     presented proof, never per registration. Storing the flag and not
//     enforcing it would leave the client believing a protection is in
//     place, so the request is refused instead. A false value is the
//     protocol default and is accepted as the no-op it is.
func validateUnpersistedMetadata(m ClientMetadata, extras metadataExtras) error {
	userInfo := userInfoSignedResponseSurface(m.UserInfoEncryptedResponseAlg != "")
	if err := validateSignedResponseAlg(userInfo, extras.UserInfoSignedResponseAlg); err != nil {
		return err
	}
	if err := validateSignedResponseAlg(authorizationSignedResponseSurface(), extras.AuthorizationSignedResponseAlg); err != nil {
		return err
	}
	if extras.DPoPBoundAccessTokens {
		return errInvalidClientMetadata(
			"dpop_bound_access_tokens true is not supported: the OP binds an access token when the " +
				"request presents a DPoP proof and does not enforce the requirement per client",
		)
	}
	if extras.TLSClientCertificateBoundAccessTokens {
		return errInvalidClientMetadata(
			"tls_client_certificate_bound_access_tokens true is not supported: the OP binds an access " +
				"token when the request presents a client certificate and does not enforce the " +
				"requirement per client",
		)
	}
	if extras.RequirePushedAuthorizationRequests {
		return errInvalidClientMetadata(
			"require_pushed_authorization_requests true is not supported: the OP requires pushed " +
				"authorization requests for every client or none, never per client",
		)
	}
	return nil
}

// signedResponseAlgSurface describes what one *_signed_response_alg
// member may name. The OP holds a single signing algorithm, so "ES256"
// is the only algorithm any surface can ever produce; whether a surface
// can also produce an unsigned body differs per surface, and a member
// naming a shape its surface never emits is refused rather than
// recorded. See [validateSignedResponseAlg] for the rule.
type signedResponseAlgSurface struct {
	// field is the wire member name, used in the error description.
	field string
	// signed reports whether registering the OP's signing algorithm
	// makes every later response on this surface a JWS.
	signed bool
	// unsigned reports whether registering "none" makes every later
	// response on this surface an unsigned body.
	unsigned bool
	// refusal states why the shape this surface cannot produce is
	// refused. A surface produces at least one of the two shapes, so a
	// single explanation covers whichever half is missing.
	refusal string
}

// idTokenSignedResponseSurface returns the ID Token surface. An ID
// Token is a JWS by definition (OIDC Core 1.0 §2); there is no unsigned
// ID Token for a client to ask for.
func idTokenSignedResponseSurface() signedResponseAlgSurface {
	return signedResponseAlgSurface{
		field:   "id_token_signed_response_alg",
		signed:  true,
		refusal: "the OP always signs an ID Token",
	}
}

// introspectionSignedResponseSurface returns the introspection-response
// surface, the one surface whose shape the client selects: a JWT
// response is emitted when the client registers the signed shape and a
// JSON body otherwise (RFC 9701 §4). The value is persisted on
// [ClientMetadata] and honoured unconditionally, which is the shape the
// other three surfaces are held against.
func introspectionSignedResponseSurface() signedResponseAlgSurface {
	return signedResponseAlgSurface{
		field:    "introspection_signed_response_alg",
		signed:   true,
		unsigned: true,
	}
}

// authorizationSignedResponseSurface returns the JARM authorization-
// response surface. A JARM response is a JWS on every response mode
// that carries one; the OP does not serve an unsigned JARM body.
func authorizationSignedResponseSurface() signedResponseAlgSurface {
	return signedResponseAlgSurface{
		field:   "authorization_signed_response_alg",
		signed:  true,
		refusal: "the OP always signs a JARM authorization response",
	}
}

// userInfoSignedResponseSurface returns the /userinfo surface for a
// client that did or did not register UserInfo response encryption.
//
// A UserInfo response is signed before it is encrypted (OIDC Core 1.0
// §5.3.2), so a client that registered userinfo_encrypted_response_alg
// receives a JWS on every call and may name the OP's signing algorithm.
// Without registered encryption the JWT shape is chosen per request by
// `Accept: application/jwt` and never by registration, so naming an
// algorithm there would ask for a response shape the OP will not switch
// to; only the unsigned JSON default may be named.
func userInfoSignedResponseSurface(encryptionRegistered bool) signedResponseAlgSurface {
	if encryptionRegistered {
		return signedResponseAlgSurface{
			field:   "userinfo_signed_response_alg",
			signed:  true,
			refusal: "a UserInfo response encrypted for this client is signed before it is encrypted",
		}
	}
	return signedResponseAlgSurface{
		field:    "userinfo_signed_response_alg",
		unsigned: true,
		refusal: "the OP serves the signed UserInfo shape to a request carrying " +
			"Accept: application/jwt, not to a registration",
	}
}

// validateSignedResponseAlg admits only the response shape the surface
// actually produces: the single JWS alg the OP signs with where the
// surface emits a JWS, and the explicit "none" where it emits an
// unsigned body. Every other algorithm name is refused because the OP
// holds one signing algorithm, and a shape the surface never produces is
// refused because accepting it would answer 201/200 to a request the OP
// does not act on. Omitting the member names no shape and is always
// accepted; the surface keeps its default.
func validateSignedResponseAlg(surface signedResponseAlgSurface, alg string) error {
	switch alg {
	case "":
		return nil
	case "ES256":
		if surface.signed {
			return nil
		}
	case "none":
		if surface.unsigned {
			return nil
		}
	default:
		return errInvalidClientMetadata(surface.field + " " + alg + " is not supported (ES256 only)")
	}
	return errInvalidClientMetadata(surface.field + " " + alg + " is not supported: " + surface.refusal)
}

func normalizeIntrospectionSignedResponseAlg(alg string) string {
	if alg == "none" {
		return ""
	}
	return alg
}

func validateDefaultMaxAge(v *int64) error {
	if v != nil && *v < 0 {
		return errInvalidClientMetadata("default_max_age must be a non-negative integer")
	}
	return nil
}

// defaultScopeIfEmpty returns scope unchanged when non-empty; when
// empty it returns the registration-path default joined by spaces.
//
// Only POST /register calls this. Handing a client scopes it did not
// ask for is a property of admitting a new registration, so the RFC
// 7592 update path has no default at all: an update that omits the
// scope member clears the stored value like every other omitted member
// rather than inheriting whichever default the creation path would
// have picked.
//
// The selection order is:
//  1. iatScopes — the IAT-bound allowlist
//     ([store.InitialAccessToken.AllowedScopes]). Operator-issued IAT
//     restrictions win over every other default so a tightly-scoped
//     IAT cannot be widened by a defaulting rule.
//  2. openRegistrationDefaultScopes when openRegistration is true —
//     the embedder-supplied default for open registration. Empty (the
//     zero value) means "no default": the registered client gets
//     [store.Client.Scopes] empty and must request scope explicitly
//     on subsequent /authorize calls.
//  3. scopes.PublicNames() filtered to scopes without an AllowedClients
//     restriction, applied only on the IAT-bound path when the IAT
//     carried no AllowedScopes restriction. Dynamic registrations do
//     not choose their client_id, so client-specific scopes cannot be
//     safely defaulted onto the newly minted client.
//  4. Empty string when no default applies.
//
// The minimum-privilege baseline for open registration is
// deliberate: prior to the
// [op.RegistrationOption.OpenRegistrationDefaultScopes] surface,
// open mode fell through to the registry's full public scope list,
// which silently widened every dynamically registered client.
// Embedders that rely on a wider default opt in explicitly through
// the option.
func defaultScopeIfEmpty(scope string, iatScopes []string, openRegistration bool, openRegistrationDefaultScopes []string, scopes *scoperegistry.Registry) string {
	if scope != "" {
		return scope
	}
	if len(iatScopes) > 0 {
		return strings.Join(iatScopes, " ")
	}
	if openRegistration {
		if len(openRegistrationDefaultScopes) > 0 {
			return strings.Join(openRegistrationDefaultScopes, " ")
		}
		return ""
	}
	if scopes != nil {
		names := registrationDefaultScopeNames(scopes)
		if len(names) > 0 {
			return strings.Join(names, " ")
		}
	}
	return ""
}

func registrationDefaultScopeNames(scopes *scoperegistry.Registry) []string {
	names := scopes.PublicNames()
	out := names[:0]
	for _, name := range names {
		if scopes.Allows(name, "") {
			out = append(out, name)
		}
	}
	return out
}

// applyMetadataDefaults populates fields the client left blank with
// the library defaults, returning the canonical metadata the policy
// validator and persistence layer consume.
func applyMetadataDefaults(m ClientMetadata, allowedGrantTypes, allowedResponseTypes []string) ClientMetadata {
	out := m
	if len(out.GrantTypes) == 0 {
		out.GrantTypes = cloneStrings(allowedGrantTypes)
	}
	if len(out.ResponseTypes) == 0 {
		out.ResponseTypes = cloneStrings(allowedResponseTypes)
	}
	if out.TokenEndpointAuthMethod == "" {
		out.TokenEndpointAuthMethod = defaultAuthMethod
	}
	if out.SubjectType == "" {
		out.SubjectType = defaultSubjectType
	}
	if out.IDTokenSignedResponseAlg == "" {
		out.IDTokenSignedResponseAlg = defaultIDTokenAlg
	}
	if out.ApplicationType == "" {
		out.ApplicationType = defaultApplicationType
	}
	return out
}

// validateGrantTypes enforces the AllowedGrantTypes whitelist. An
// empty allowed slice falls back to the library default
// {"authorization_code", "refresh_token"}; the caller of this helper
// always passes the resolved list from [Deps].
func validateGrantTypes(requested, allowed []string) error {
	for _, gt := range requested {
		if !slices.Contains(allowed, gt) {
			return errInvalidClientMetadata("grant_type " + gt + " is not allowed")
		}
	}
	return nil
}

// validateResponseTypes enforces the AllowedResponseTypes whitelist.
func validateResponseTypes(requested, allowed []string) error {
	for _, rt := range requested {
		if !slices.Contains(allowed, rt) {
			return errInvalidClientMetadata("response_type " + rt + " is not allowed")
		}
	}
	return nil
}

// validateGrantResponseTypeConsistency enforces the OIDC Core coupling
// between response_type and grant_type. The checks operate on the
// semantic token set of each response_type so "id_token code" and
// "code id_token" are treated identically.
func validateGrantResponseTypeConsistency(grantTypes, responseTypes []string) error {
	hasGrant := func(want string) bool { return slices.Contains(grantTypes, want) }
	for _, rt := range responseTypes {
		toks := strings.Fields(rt)
		hasCode := slices.Contains(toks, "code")
		hasToken := slices.Contains(toks, "token")
		hasIDToken := slices.Contains(toks, "id_token")

		if hasCode && !hasGrant("authorization_code") {
			return errInvalidClientMetadata("response_type " + rt + " requires grant_type authorization_code")
		}
		if (hasToken || hasIDToken) && !hasCode && !hasGrant("implicit") {
			return errInvalidClientMetadata("response_type " + rt + " requires grant_type implicit")
		}
		if hasCode && (hasToken || hasIDToken) && !hasGrant("implicit") {
			return errInvalidClientMetadata("response_type " + rt + " requires grant_type implicit")
		}
	}
	return nil
}

// validateAuthMethod rejects token_endpoint_auth_method values the
// library does not implement (client_secret_jwt is rejected because
// the library does not negotiate symmetric JWT algorithms) and any
// value outside the closed set the OP advertises.
func validateAuthMethod(m string) error {
	switch m {
	case "client_secret_basic", "client_secret_post", "private_key_jwt", "none":
		return nil
	case "client_secret_jwt":
		return errInvalidClientMetadata("token_endpoint_auth_method client_secret_jwt is not supported")
	default:
		return errInvalidClientMetadata("token_endpoint_auth_method " + m + " is not supported")
	}
}

func validateTokenEndpointAuthSigningAlg(alg string) error {
	if alg == "" {
		return nil
	}
	switch alg {
	case "RS256", "PS256", "ES256", "EdDSA":
		return nil
	default:
		return errInvalidClientMetadata("token_endpoint_auth_signing_alg " + alg + " is not supported")
	}
}

// validateSubjectType rejects "pairwise" when the OP was constructed
// without [op.WithPairwiseSubject] (signalled here by pairwiseEnabled
// being false).
func validateSubjectType(t string, pairwiseEnabled bool) error {
	switch t {
	case "public":
		return nil
	case "pairwise":
		if !pairwiseEnabled {
			return errInvalidClientMetadata("subject_type pairwise requires WithPairwiseSubject")
		}
		return nil
	default:
		return errInvalidClientMetadata("subject_type " + t + " is not supported")
	}
}

// validateRequestedScopes enforces (1) the IAT-bound AllowedScopes
// allowlist when present, (2) registration in the OP scope catalog, and
// (3) absence of an AllowedClients restriction on dynamic registrations.
// An empty Scope value is permitted; defaultScopeIfEmpty decides whether
// the registration path supplies a default before this validator runs.
func validateRequestedScopes(scope string, iatAllowed []string, scopes *scoperegistry.Registry) error {
	if scope == "" {
		return nil
	}
	for _, s := range strings.Fields(scope) {
		if len(iatAllowed) > 0 && !slices.Contains(iatAllowed, s) {
			return errInvalidClientMetadata("scope outside IAT allowlist")
		}
		if scopes != nil && !scopes.IsRegistered(s) {
			return errInvalidClientMetadata("scope " + s + " is not registered")
		}
		if scopes != nil && !scopes.Allows(s, "") {
			return errInvalidClientMetadata("scope " + s + " is restricted to specific clients")
		}
	}
	return nil
}

func validateMetadataURIs(m ClientMetadata, allowInsecureBackchannelLogoutForDev bool) error {
	for _, field := range []struct {
		name string
		raw  string
	}{
		{name: "client_uri", raw: m.ClientURI},
		{name: "logo_uri", raw: m.LogoURI},
		{name: "policy_uri", raw: m.PolicyURI},
		{name: "tos_uri", raw: m.TosURI},
		{name: "jwks_uri", raw: m.JWKsURI},
		{name: "sector_identifier_uri", raw: m.SectorIdentifierURI},
		{name: "initiate_login_uri", raw: m.InitiateLoginURI},
	} {
		if err := validateHTTPSAbsoluteURI(field.name, field.raw); err != nil {
			return err
		}
	}
	if err := validateBackchannelLogoutURI(m.BackchannelLogoutURI, allowInsecureBackchannelLogoutForDev); err != nil {
		return err
	}
	if err := validateBackchannelLogoutCoupling(m); err != nil {
		return err
	}
	for _, raw := range m.RequestURIs {
		if err := validateRequestURI("request_uris", raw); err != nil {
			return err
		}
	}
	return nil
}

// validateBackchannelLogoutURI mirrors [validateHTTPSAbsoluteURI]
// for the `backchannel_logout_uri` field, with one carve-out gated
// on [op.WithAllowInsecureBackchannelLogoutForDev]: under the dev
// opt-in, plain-http URLs whose host is a loopback identity
// (127.0.0.1, [::1], or "localhost") are admitted so the
// in-process examples and CI fixtures can run without TLS. The
// production posture (allowDevLoopback=false) is unchanged from the
// shared https-only rule.
func validateBackchannelLogoutURI(raw string, allowDevLoopback bool) error {
	if raw == "" {
		return nil
	}
	if !allowDevLoopback {
		return validateHTTPSAbsoluteURI("backchannel_logout_uri", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidClientMetadata("backchannel_logout_uri is not a valid URL")
	}
	if !u.IsAbs() {
		return errInvalidClientMetadata("backchannel_logout_uri must be absolute")
	}
	if u.Fragment != "" {
		return errInvalidClientMetadata("backchannel_logout_uri must not contain a fragment")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errInvalidClientMetadata("backchannel_logout_uri must include a host")
	}
	if u.User != nil {
		return errInvalidClientMetadata("backchannel_logout_uri must not contain userinfo")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return errInvalidClientMetadata(
		"backchannel_logout_uri must use https (or http with a loopback host under WithAllowInsecureBackchannelLogoutForDev)",
	)
}

// isLoopbackHost reports whether host is one of the dev-mode
// loopback identities WithAllowInsecureBackchannelLogoutForDev
// admits over plain http: the textual "localhost", or the IP
// literals 127.0.0.1 and [::1].
func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// validateBackchannelLogoutCoupling rejects session-bound back-channel
// logout registration. The current grant model does not retain a
// client-specific session lineage, so accepting the flag would either
// break the client's contract or leak an unrelated browser-session SID.
// Sub-only back-channel logout remains available through
// backchannel_logout_uri.
func validateBackchannelLogoutCoupling(m ClientMetadata) error {
	if m.BackchannelLogoutSessionRequired {
		return errInvalidClientMetadata(
			"backchannel_logout_session_required is not supported",
		)
	}
	return nil
}

func validateHTTPSAbsoluteURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidClientMetadata(field + " is not a valid URL")
	}
	if !u.IsAbs() {
		return errInvalidClientMetadata(field + " must be absolute")
	}
	if u.Scheme != "https" {
		return errInvalidClientMetadata(field + " must use https")
	}
	if u.Fragment != "" {
		return errInvalidClientMetadata(field + " must not contain a fragment")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errInvalidClientMetadata(field + " must include a host")
	}
	if u.User != nil {
		return errInvalidClientMetadata(field + " must not contain userinfo")
	}
	return nil
}

// validateRequestURI enforces the same https / absolute / host rules as
// [validateHTTPSAbsoluteURI] but permits a URI fragment, because
// OIDC Core §6.2 explicitly RECOMMENDS using the base64url-encoded
// SHA-256 hash of the request file as the fragment so caches can detect
// content changes.
//
// The userinfo rejection mirrors [validateHTTPSAbsoluteURI]: a URL of
// the shape `https://trusted.example@evil.example/...` parses with
// host=evil.example in Go but reads as host=trusted.example in many
// human / parser passes. The OP fetches request_uri payloads, so the
// audit / SSRF / allowlist boundary refuses parser-confusion URLs
// uniformly across every metadata field that accepts an https URL.
func validateRequestURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidClientMetadata(field + " is not a valid URL")
	}
	if !u.IsAbs() {
		return errInvalidClientMetadata(field + " must be absolute")
	}
	if u.Scheme != "https" {
		return errInvalidClientMetadata(field + " must use https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errInvalidClientMetadata(field + " must include a host")
	}
	if u.User != nil {
		return errInvalidClientMetadata(field + " must not contain userinfo")
	}
	return nil
}

//nolint:gocognit,cyclop // Registration validation keeps mutually exclusive key-source and requirement errors precise.
func validateJWKSConfiguration(m ClientMetadata, jwePolicy internaljose.JWEPolicy) error {
	if len(m.JWKs) > 0 && m.JWKsURI != "" {
		return errInvalidClientMetadata("jwks and jwks_uri are mutually exclusive")
	}
	if len(m.JWKs) > 0 {
		if err := validateInlineJWKS(m.JWKs); err != nil {
			return err
		}
	}
	requirements := jwksRequirements(m)
	if len(requirements) == 0 {
		return nil
	}
	hasInline := len(m.JWKs) > 0
	hasURI := m.JWKsURI != ""
	if hasInline == hasURI {
		if m.TokenEndpointAuthMethod == "private_key_jwt" && len(requirements) == 1 {
			return errInvalidClientMetadata("private_key_jwt requires exactly one of jwks or jwks_uri")
		}
		return errInvalidClientMetadata("client key requirements need exactly one of jwks or jwks_uri")
	}
	if hasURI {
		// jwks_uri is deliberately structural-only at registration time.
		// Fetching it here would turn DCR into an SSRF-capable network
		// operation and would still race the key's later rotation. Runtime
		// clientencjwks / assertion resolution remains fail-closed.
		return nil
	}
	keys, err := internaljose.ParseJWKSet(m.JWKs)
	if err != nil {
		return errInvalidClientMetadata("jwks is malformed")
	}
	for _, requirement := range requirements {
		if requirement.kind == jwksSigningRequirement && hasSigningKey(keys, requirement.alg) {
			continue
		}
		if requirement.kind == jwksEncryptionRequirement && hasEncryptionKey(keys, requirement.alg, jwePolicy) {
			continue
		}
		return errInvalidClientMetadata("jwks does not contain a usable key for " + requirement.field)
	}
	return nil
}

const (
	jwksSigningRequirement = iota
	jwksEncryptionRequirement
)

type jwksRequirement struct {
	kind  int
	alg   string
	field string
}

func jwksRequirements(m ClientMetadata) []jwksRequirement {
	var out []jwksRequirement
	if m.TokenEndpointAuthMethod == "private_key_jwt" {
		out = append(out, jwksRequirement{
			kind:  jwksSigningRequirement,
			alg:   m.TokenEndpointAuthSigningAlg,
			field: "private_key_jwt",
		})
	}
	if len(m.RequestURIs) > 0 || m.RequestObjectSigningAlg != "" {
		out = append(out, jwksRequirement{
			kind:  jwksSigningRequirement,
			alg:   m.RequestObjectSigningAlg,
			field: "request_object_signing_alg",
		})
	}
	for _, encryption := range []struct {
		field string
		alg   string
	}{
		{field: "id_token_encrypted_response_alg", alg: m.IDTokenEncryptedResponseAlg},
		{field: "userinfo_encrypted_response_alg", alg: m.UserInfoEncryptedResponseAlg},
		{field: "authorization_encrypted_response_alg", alg: m.AuthorizationEncryptedResponseAlg},
		{field: "introspection_encrypted_response_alg", alg: m.IntrospectionEncryptedResponseAlg},
	} {
		if encryption.alg != "" {
			out = append(out, jwksRequirement{
				kind:  jwksEncryptionRequirement,
				alg:   encryption.alg,
				field: encryption.field,
			})
		}
	}
	return dedupeJWKSRequirements(out)
}

func dedupeJWKSRequirements(in []jwksRequirement) []jwksRequirement {
	seen := make(map[string]struct{}, len(in))
	out := make([]jwksRequirement, 0, len(in))
	for _, requirement := range in {
		key := fmt.Sprintf("%d:%s", requirement.kind, requirement.alg)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, requirement)
	}
	return out
}

//nolint:gocognit // Each JWK shape and use rejection maps to a distinct client-metadata error.
func validateInlineJWKS(raw json.RawMessage) error {
	// The parser ignores members whose key type this build does not
	// understand (RFC 7517 §5), so a client registering a supported signing
	// key alongside an unsupported one still registers successfully; only a
	// set with nothing usable left is rejected.
	keys, err := internaljose.ParseJWKSet(raw)
	if err != nil {
		if errors.Is(err, internaljose.ErrNoUsableJWK) {
			return errInvalidClientMetadata("jwks must contain at least one supported key")
		}
		return errInvalidClientMetadata("jwks is malformed")
	}
	if len(keys) == 0 {
		return errInvalidClientMetadata("jwks must contain at least one key")
	}
	for _, key := range keys {
		if key.Use != "" && key.Use != "sig" && key.Use != "enc" {
			return errInvalidClientMetadata("jwks contains an unsupported key use")
		}
		if key.Algorithm != "" {
			if jweAlg, ok := internaljose.ParseJWEAlg(key.Algorithm); ok {
				if key.Use == "sig" {
					return errInvalidClientMetadata("jwks JWE key must not use use=sig")
				}
				if err := internaljose.AssertJWEAlgKeyShape(jweAlg, key.Key); err != nil {
					return errInvalidClientMetadata("jwks contains an unsupported key")
				}
				continue
			}
			if key.Use == "enc" {
				return errInvalidClientMetadata("jwks signing key must not use use=enc")
			}
			if err := internaljose.AssertAlgKeyShape(key.Algorithm, key.Key); err != nil {
				return errInvalidClientMetadata("jwks contains an unsupported key")
			}
			continue
		}
		if _, _, _, ok := internaljose.KeyShape(key.Key); !ok {
			return errInvalidClientMetadata("jwks contains an unsupported key")
		}
	}
	return nil
}

//nolint:gocognit // Key eligibility combines requested, declared, and inferred algorithm shape checks.
func hasSigningKey(keys []internaljose.JWK, requestedAlg string) bool {
	for _, key := range keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if requestedAlg != "" && key.Algorithm != "" && key.Algorithm != requestedAlg {
			continue
		}
		alg := requestedAlg
		if alg == "" {
			alg = key.Algorithm
		}
		if alg == "" {
			if _, _, _, ok := internaljose.KeyShape(key.Key); ok {
				return true
			}
			continue
		}
		if internaljose.AssertAlgKeyShape(alg, key.Key) == nil {
			return true
		}
	}
	return false
}

func hasEncryptionKey(keys []internaljose.JWK, requestedAlg string, policy internaljose.JWEPolicy) bool {
	alg, ok := internaljose.ParseJWEAlgPolicy(requestedAlg, policy)
	if !ok {
		return false
	}
	for _, key := range keys {
		if key.Use != "" && key.Use != "enc" {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != requestedAlg {
			continue
		}
		if internaljose.AssertJWEAlgKeyShape(alg, key.Key) == nil {
			return true
		}
	}
	return false
}

func validateRequestObjectSigningAlg(alg string) error {
	if alg == "" {
		return nil
	}
	switch alg {
	case "RS256", "PS256", "ES256", "EdDSA":
		return nil
	default:
		return errInvalidClientMetadata("request_object_signing_alg " + alg + " is not supported")
	}
}

// validateRequestObjectEncryption pins the JWE alg/enc the client may
// register against the closed allow-list exposed by [internaljose.ParseJWEAlg]
// / [internaljose.ParseJWEEnc], narrowed by the deployment's policy, so DCR
// cannot admit a value the verifier would later reject as
// [jar.ErrEncryptionAlgNotAllowed].
//
// The policy is the same value that drives inbound decryption, outbound
// recipient selection and the discovery advertisement, so an OP that
// removed an alg cannot be handed a client that registers it: admitting
// the registration would mint a client whose every encrypted exchange
// fails at runtime.
//
// Both alg and enc are required together. OIDC Core §6.1 permits
// registering one half and negotiating the other through the discovery
// list; this OP does not implement that negotiation (the runtime
// encryption path requires both values, see
// internal/clientencjwks.validateAlgEnc), so DCR rejects mixed
// half-pairs at registration time to close the admit/runtime-reject gap.
// Both empty is fine — the client takes the unencrypted (signed-only)
// path.
func validateRequestObjectEncryption(alg, enc string, policy internaljose.JWEPolicy) error {
	return validateJWEAlgEncPair("request_object_encryption_alg", "request_object_encryption_enc", alg, enc, policy)
}

// validateIDTokenResponseEncryption pins the JWE alg/enc the client may
// register for issued ID tokens (OIDC Core 1.0 §10.2). Same allow-list,
// policy narrowing and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateIDTokenResponseEncryption(alg, enc string, policy internaljose.JWEPolicy) error {
	return validateJWEAlgEncPair("id_token_encrypted_response_alg", "id_token_encrypted_response_enc", alg, enc, policy)
}

// validateUserInfoResponseEncryption pins the JWE alg/enc the client may
// register for /userinfo responses (OIDC Core 1.0 §5.3). Same allow-list,
// policy narrowing and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateUserInfoResponseEncryption(alg, enc string, policy internaljose.JWEPolicy) error {
	return validateJWEAlgEncPair("userinfo_encrypted_response_alg", "userinfo_encrypted_response_enc", alg, enc, policy)
}

// validateAuthorizationResponseEncryption pins the JWE alg/enc the
// client may register for JARM authorization responses. Same allow-list,
// policy narrowing and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateAuthorizationResponseEncryption(alg, enc string, policy internaljose.JWEPolicy) error {
	return validateJWEAlgEncPair(
		"authorization_encrypted_response_alg", "authorization_encrypted_response_enc", alg, enc, policy,
	)
}

// validateIntrospectionResponseEncryption pins the JWE alg/enc the
// client may register for JWT introspection responses (RFC 7662 + draft
// JWT Response for OAuth Token Introspection). Same allow-list, policy
// narrowing and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateIntrospectionResponseEncryption(alg, enc string, policy internaljose.JWEPolicy) error {
	return validateJWEAlgEncPair(
		"introspection_encrypted_response_alg", "introspection_encrypted_response_enc", alg, enc, policy,
	)
}

// validateJWEAlgEncPair is the shared allow-list check the encryption
// validators share. The (algField, encField) names are the wire field
// labels used in the error description so failures point the embedder
// at the offending metadata key.
//
// The allow-list is sourced verbatim from [internaljose.ParseJWEAlgPolicy] /
// [internaljose.ParseJWEEncPolicy] so the registration validator and the JWE
// verifier cannot drift; adding a new alg/enc requires editing
// internal/jose/jweparam.go only. RSA1_5, dir, A*KW, A*GCMKW and
// `none` are deliberately excluded from the JOSE allow-list and are
// therefore rejected here without any local mention. A value the
// deployment removed through policy is rejected with the same wording
// as one the library never shipped, so a registration attempt cannot
// be used to enumerate the operator's configuration.
//
// Both alg and enc must be set together. OIDC Core §6.1 permits a
// client to commit to one half and let the OP negotiate the other from
// the discovery list, but this OP does not implement that negotiation
// — the runtime check at
// internal/clientencjwks.validateAlgEnc requires both fields, so
// admitting a half-pair would surface as a runtime failure on the
// first encrypted response. Rejecting the mismatch at DCR time closes
// that admit/runtime-reject gap. Both empty is permitted: the client
// takes the unencrypted (signed-only) path.
func validateJWEAlgEncPair(algField, encField, alg, enc string, policy internaljose.JWEPolicy) error {
	if (alg == "") != (enc == "") {
		return errInvalidClientMetadata(algField + " and " + encField +
			" must be set together (RFC 7591 / OIDC Core §6.1)")
	}
	if alg != "" {
		if _, ok := internaljose.ParseJWEAlgPolicy(alg, policy); !ok {
			return errInvalidClientMetadata(algField + " " + alg + " is not supported")
		}
	}
	if enc != "" {
		if _, ok := internaljose.ParseJWEEncPolicy(enc, policy); !ok {
			return errInvalidClientMetadata(encField + " " + enc + " is not supported")
		}
	}
	return nil
}

func validatePairwiseMetadata(m ClientMetadata) error {
	if m.SubjectType != "pairwise" || m.SectorIdentifierURI != "" {
		return nil
	}
	host := ""
	for _, raw := range m.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil {
			return errInvalidRedirectURI("redirect_uri is not a valid URL")
		}
		redirectHost := strings.ToLower(u.Hostname())
		if host == "" {
			host = redirectHost
			continue
		}
		if redirectHost != host {
			return errInvalidClientMetadata("subject_type pairwise requires sector_identifier_uri when redirect_uris span multiple hosts")
		}
	}
	return nil
}

// validationError is the structural-validator's error sentinel. It
// carries the wire code and description the HTTP layer copies into the
// RFC 7591 §3.2.2 envelope.
type validationError struct {
	code        string
	description string
}

// Error implements error. The string is wire-stable so test snapshots
// can pin the message; the description is operator-facing.
func (e *validationError) Error() string {
	return e.code + ": " + e.description
}

// errInvalidClientMetadata constructs a validationError with the
// "invalid_client_metadata" wire code (RFC 7591 §3.2.2).
func errInvalidClientMetadata(desc string) error {
	return &validationError{code: codeInvalidClientMetadata, description: desc}
}

// errInvalidRedirectURI constructs a validationError with the
// "invalid_redirect_uri" wire code (RFC 7591 §3.2.2).
func errInvalidRedirectURI(desc string) error {
	return &validationError{code: codeInvalidRedirectURI, description: desc}
}

// asValidationError reports whether err is a [*validationError] and,
// if so, returns its (code, description) pair. Callers branch on the
// boolean to decide whether the error came from structural validation
// (deterministic mapping) or from a [Deps.ValidateMetadata] hook (uses
// the shared invalid_client_metadata code).
func asValidationError(err error) (*validationError, bool) {
	var ve *validationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
