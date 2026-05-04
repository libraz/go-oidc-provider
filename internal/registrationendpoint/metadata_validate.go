package registrationendpoint

import (
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
)

// validatePolicy enforces the structural rules from
// 02-product-design.md §A.6.2 / §A.6.2.2. It returns the
// canonicalised metadata (defaults applied, scopes parsed) on success
// and a [validationError] on the first rule violation.
// The validator does not invoke [Deps.ValidateMetadata]; the handler
// runs that hook after structural validation passes so embedder code
// only sees metadata that already cleared the library checks.
func validatePolicy(
	m ClientMetadata,
	allowedGrantTypes []string,
	allowedResponseTypes []string,
	iatScopes []string,
	scopes *scoperegistry.Registry,
	pairwiseEnabled bool,
	allowLocalhostLoopback bool,
) (ClientMetadata, error) {
	if len(m.RedirectURIs) == 0 {
		return ClientMetadata{}, errInvalidRedirectURI("redirect_uris is required")
	}
	canonical := applyMetadataDefaults(m, allowedGrantTypes, allowedResponseTypes)
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
		func() error { return validateSubjectType(canonical.SubjectType, pairwiseEnabled) },
		func() error { return validateIDTokenAlg(canonical.IDTokenSignedResponseAlg) },
		func() error { return validateRequestedScopes(canonical.Scope, iatScopes, scopes) },
		func() error { return validateMetadataURIs(canonical) },
		func() error { return validateJWKSConfiguration(canonical) },
		func() error { return validateRequestObjectSigningAlg(canonical.RequestObjectSigningAlg) },
		func() error {
			return validateRequestObjectEncryption(canonical.RequestObjectEncryptionAlg, canonical.RequestObjectEncryptionEnc)
		},
		func() error {
			return validateIDTokenResponseEncryption(canonical.IDTokenEncryptedResponseAlg, canonical.IDTokenEncryptedResponseEnc)
		},
		func() error {
			return validateUserInfoResponseEncryption(canonical.UserInfoEncryptedResponseAlg, canonical.UserInfoEncryptedResponseEnc)
		},
		func() error {
			return validateAuthorizationResponseEncryption(canonical.AuthorizationEncryptedResponseAlg, canonical.AuthorizationEncryptedResponseEnc)
		},
		func() error {
			return validateIntrospectionResponseEncryption(canonical.IntrospectionEncryptedResponseAlg, canonical.IntrospectionEncryptedResponseEnc)
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

func validateDefaultMaxAge(v *int64) error {
	if v != nil && *v < 0 {
		return errInvalidClientMetadata("default_max_age must be a non-negative integer")
	}
	return nil
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
// library does not implement (§J.1: client_secret_jwt is rejected
// because the library does not negotiate symmetric JWT alg) and any
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

// validateIDTokenAlg enforces the v1.0 ES256-only policy
// .
func validateIDTokenAlg(alg string) error {
	if alg != "ES256" {
		return errInvalidClientMetadata("id_token_signed_response_alg " + alg + " is not supported (ES256 only)")
	}
	return nil
}

// validateRequestedScopes enforces (1) the IAT-bound AllowedScopes
// allowlist when present and (2) the registry-level allowlist when a
// non-nil [scoperegistry.Registry] is supplied. An empty Scope value is
// permitted; the OP applies its global default (see §K.4) at the
// authorize-time scope intersection rather than here.
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
	}
	return nil
}

func validateMetadataURIs(m ClientMetadata) error {
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
	for _, raw := range m.RequestURIs {
		if err := validateHTTPSAbsoluteURI("request_uris", raw); err != nil {
			return err
		}
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
	return nil
}

func validateJWKSConfiguration(m ClientMetadata) error {
	if len(m.JWKs) > 0 && m.JWKsURI != "" {
		return errInvalidClientMetadata("jwks and jwks_uri are mutually exclusive")
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
// register against the closed allow-list exposed by [jose.ParseJWEAlg]
// / [jose.ParseJWEEnc] so DCR cannot admit a value the verifier would
// later reject as [jar.ErrEncryptionAlgNotAllowed]; an embedder that
// narrows the advertised list via [op.WithSupportedEncryptionAlgs] is
// responsible for the per-deployment hardening — the registration
// validator stays at the library ceiling so a non-narrowing OP accepts
// every alg/enc the JOSE wrapper can decrypt.
//
// Both alg and enc are required together. OIDC Core §6.1 permits
// registering one half and negotiating the other through the discovery
// list; this OP does not implement that negotiation (the runtime
// encryption path requires both values, see
// [internal/clientencjwks].validateAlgEnc), so DCR rejects mixed
// half-pairs at registration time to close the admit/runtime-reject gap.
// Both empty is fine — the client takes the unencrypted (signed-only)
// path.
func validateRequestObjectEncryption(alg, enc string) error {
	return validateJWEAlgEncPair("request_object_encryption_alg", "request_object_encryption_enc", alg, enc)
}

// validateIDTokenResponseEncryption pins the JWE alg/enc the client may
// register for issued ID tokens (OIDC Core 1.0 §10.2). Same closed
// allow-list and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateIDTokenResponseEncryption(alg, enc string) error {
	return validateJWEAlgEncPair("id_token_encrypted_response_alg", "id_token_encrypted_response_enc", alg, enc)
}

// validateUserInfoResponseEncryption pins the JWE alg/enc the client may
// register for /userinfo responses (OIDC Core 1.0 §5.3). Same closed
// allow-list and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateUserInfoResponseEncryption(alg, enc string) error {
	return validateJWEAlgEncPair("userinfo_encrypted_response_alg", "userinfo_encrypted_response_enc", alg, enc)
}

// validateAuthorizationResponseEncryption pins the JWE alg/enc the
// client may register for JARM authorization responses. Same closed
// allow-list and both-or-neither rule as
// [validateRequestObjectEncryption].
func validateAuthorizationResponseEncryption(alg, enc string) error {
	return validateJWEAlgEncPair("authorization_encrypted_response_alg", "authorization_encrypted_response_enc", alg, enc)
}

// validateIntrospectionResponseEncryption pins the JWE alg/enc the
// client may register for JWT introspection responses (RFC 7662 + draft
// JWT Response for OAuth Token Introspection). Same closed allow-list
// and both-or-neither rule as [validateRequestObjectEncryption].
func validateIntrospectionResponseEncryption(alg, enc string) error {
	return validateJWEAlgEncPair("introspection_encrypted_response_alg", "introspection_encrypted_response_enc", alg, enc)
}

// validateJWEAlgEncPair is the shared allow-list check the encryption
// validators share. The (algField, encField) names are the wire field
// labels used in the error description so failures point the embedder
// at the offending metadata key.
//
// The allow-list is sourced verbatim from [jose.ParseJWEAlg] /
// [jose.ParseJWEEnc] so the registration validator and the JWE
// verifier cannot drift; adding a new alg/enc requires editing
// [internal/jose/jweparam.go] only. RSA1_5, dir, A*KW, A*GCMKW and
// `none` are deliberately excluded from the JOSE allow-list and are
// therefore rejected here without any local mention.
//
// Both alg and enc must be set together. OIDC Core §6.1 permits a
// client to commit to one half and let the OP negotiate the other from
// the discovery list, but this OP does not implement that negotiation
// — the runtime check at
// [internal/clientencjwks].validateAlgEnc requires both fields, so
// admitting a half-pair would surface as a runtime failure on the
// first encrypted response. Rejecting the mismatch at DCR time closes
// that admit/runtime-reject gap. Both empty is permitted: the client
// takes the unencrypted (signed-only) path.
func validateJWEAlgEncPair(algField, encField, alg, enc string) error {
	if (alg == "") != (enc == "") {
		return errInvalidClientMetadata(algField + " and " + encField +
			" must be set together (RFC 7591 / OIDC Core §6.1)")
	}
	if alg != "" {
		if _, ok := jose.ParseJWEAlg(alg); !ok {
			return errInvalidClientMetadata(algField + " " + alg + " is not supported")
		}
	}
	if enc != "" {
		if _, ok := jose.ParseJWEEnc(enc); !ok {
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
		if host == "" {
			host = u.Hostname()
			continue
		}
		if u.Hostname() != host {
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
