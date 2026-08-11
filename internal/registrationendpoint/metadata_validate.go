package registrationendpoint

import (
	"encoding/json"
	"errors"
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
func validatePolicy(
	m ClientMetadata,
	allowedGrantTypes []string,
	allowedResponseTypes []string,
	iatScopes []string,
	openRegistration bool,
	openRegistrationDefaultScopes []string,
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
	canonical.Scope = defaultScopeIfEmpty(canonical.Scope, iatScopes, openRegistration, openRegistrationDefaultScopes, scopes)
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
		func() error { return validateIDTokenAlg(canonical.IDTokenSignedResponseAlg) },
		func() error { return validateRequestedScopes(canonical.Scope, iatScopes, scopes) },
		func() error { return validateMetadataURIs(canonical, allowInsecureBackchannelLogoutForDev) },
		func() error { return validateJWKSConfiguration(canonical) },
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
//   - Response-signing algorithms. Discovery publishes the alg values
//     the OP signs UserInfo and introspection responses with, so a
//     client naming one of those values MUST be admitted; naming any
//     other algorithm MUST be refused, because the OP signs with one
//     algorithm and would otherwise hand back a JWT the client cannot
//     verify. The value itself is not persisted: the OP selects the
//     JWT shape from the request's Accept header (UserInfo) or from the
//     client's stored introspection switch, and a registration request
//     sets neither.
//   - Per-client enforcement flags. Asking the OP to require DPoP
//     (RFC 9449 §5.2) or pushed authorization requests (RFC 9126 §6.2)
//     from this client specifically is a hardening the OP applies
//     globally or per presented proof, never per registration. Storing
//     the flag and not enforcing it would leave the client believing a
//     protection is in place, so the request is refused instead. A
//     false value is the protocol default and is accepted as the no-op
//     it is.
func validateUnpersistedMetadata(extras metadataExtras) error {
	if err := validateSignedResponseAlg("userinfo_signed_response_alg", extras.UserInfoSignedResponseAlg); err != nil {
		return err
	}
	if err := validateSignedResponseAlg("introspection_signed_response_alg", extras.IntrospectionSignedResponseAlg); err != nil {
		return err
	}
	if extras.DPoPBoundAccessTokens {
		return errInvalidClientMetadata(
			"dpop_bound_access_tokens true is not supported: the OP binds an access token when the " +
				"request presents a DPoP proof and does not enforce the requirement per client")
	}
	if extras.RequirePushedAuthorizationRequests {
		return errInvalidClientMetadata(
			"require_pushed_authorization_requests true is not supported: the OP requires pushed " +
				"authorization requests for every client or none, never per client")
	}
	return nil
}

// validateSignedResponseAlg admits the single JWS alg the OP signs
// with, plus the explicit "none" that names the unsigned JSON shape the
// OP serves by default. Every other value is refused: the OP holds one
// signing algorithm, so accepting a second name would promise a
// signature the client could not verify.
func validateSignedResponseAlg(field, alg string) error {
	switch alg {
	case "", "none", "ES256":
		return nil
	default:
		return errInvalidClientMetadata(field + " " + alg + " is not supported (ES256 only)")
	}
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

// validateIDTokenAlg enforces the permanent ES256-only signing policy.
func validateIDTokenAlg(alg string) error {
	if alg != "ES256" {
		return errInvalidClientMetadata("id_token_signed_response_alg " + alg + " is not supported (ES256 only)")
	}
	return nil
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
	if u.Host == "" {
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
		"backchannel_logout_uri must use https (or http with a loopback host under WithAllowInsecureBackchannelLogoutForDev)")
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
			"backchannel_logout_session_required is not supported")
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
	if u.Host == "" {
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
	if u.Host == "" {
		return errInvalidClientMetadata(field + " must include a host")
	}
	if u.User != nil {
		return errInvalidClientMetadata(field + " must not contain userinfo")
	}
	return nil
}

func validateJWKSConfiguration(m ClientMetadata) error {
	if len(m.JWKs) > 0 && m.JWKsURI != "" {
		return errInvalidClientMetadata("jwks and jwks_uri are mutually exclusive")
	}
	if m.TokenEndpointAuthMethod != "private_key_jwt" {
		return nil
	}
	hasInline := len(m.JWKs) > 0
	hasURI := m.JWKsURI != ""
	if hasInline == hasURI {
		return errInvalidClientMetadata("private_key_jwt requires exactly one of jwks or jwks_uri")
	}
	if hasInline {
		return validateInlineJWKS(m.JWKs)
	}
	return nil
}

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
		if key.Algorithm != "" {
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
		"authorization_encrypted_response_alg", "authorization_encrypted_response_enc", alg, enc, policy)
}

// validateIntrospectionResponseEncryption pins the JWE alg/enc the
// client may register for JWT introspection responses (RFC 7662 + draft
// JWT Response for OAuth Token Introspection). Same allow-list, policy
// narrowing and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateIntrospectionResponseEncryption(alg, enc string, policy internaljose.JWEPolicy) error {
	return validateJWEAlgEncPair(
		"introspection_encrypted_response_alg", "introspection_encrypted_response_enc", alg, enc, policy)
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
