package registrationendpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
)

// maxBodyBytes caps the size of a /register request body. The RFC 7591
// §2 metadata is small (kilobytes at most); a 64 KiB ceiling is far
// above any legitimate payload while bounding memory use against
// pathological inputs (gosec G120). The cap matches the token and PAR
// endpoints so the three surfaces share a single posture.
const maxBodyBytes = 64 * 1024

// ClientMetadata is the internal-package mirror of op.ClientMetadata.
// internal/* must not import op/, so the type is declared
// here and the op layer converts between the two through a thin shim.
// Field documentation lives on the public op.ClientMetadata; this type
// intentionally carries the same shape so the conversion remains a
// field-for-field copy.
type ClientMetadata struct {
	RedirectURIs             []string
	GrantTypes               []string
	ResponseTypes            []string
	Scope                    string
	TokenEndpointAuthMethod  string
	ApplicationType          string
	SubjectType              string
	IDTokenSignedResponseAlg string
	SectorIdentifierURI      string
	ClientName               string
	ClientURI                string
	LogoURI                  string
	PolicyURI                string
	TosURI                   string
	JWKsURI                  string
	JWKs                     json.RawMessage
	Contacts                 []string
	DefaultMaxAge            *int64
	RequireAuthTime          bool
	DefaultACRValues         []string
	InitiateLoginURI         string
	RequestURIs              []string
	RequestObjectSigningAlg  string
	PostLogoutRedirectURIs   []string
}

// metadataWire is the JSON shape RFC 7591 §2 / OIDC Dynamic Client
// Registration 1.0 §2 expect on the wire. The struct is unexported
// because callers consume the parsed [ClientMetadata] only; the wire
// shape is an implementation detail.
type metadataWire struct {
	RedirectURIs             []string        `json:"redirect_uris,omitempty"`
	GrantTypes               []string        `json:"grant_types,omitempty"`
	ResponseTypes            []string        `json:"response_types,omitempty"`
	Scope                    string          `json:"scope,omitempty"`
	TokenEndpointAuthMethod  string          `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType          string          `json:"application_type,omitempty"`
	SubjectType              string          `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg string          `json:"id_token_signed_response_alg,omitempty"`
	SectorIdentifierURI      string          `json:"sector_identifier_uri,omitempty"`
	ClientName               string          `json:"client_name,omitempty"`
	ClientURI                string          `json:"client_uri,omitempty"`
	LogoURI                  string          `json:"logo_uri,omitempty"`
	PolicyURI                string          `json:"policy_uri,omitempty"`
	TosURI                   string          `json:"tos_uri,omitempty"`
	JWKsURI                  string          `json:"jwks_uri,omitempty"`
	JWKs                     json.RawMessage `json:"jwks,omitempty"`
	Contacts                 []string        `json:"contacts,omitempty"`
	DefaultMaxAge            *int64          `json:"default_max_age,omitempty"`
	RequireAuthTime          bool            `json:"require_auth_time,omitempty"`
	DefaultACRValues         []string        `json:"default_acr_values,omitempty"`
	InitiateLoginURI         string          `json:"initiate_login_uri,omitempty"`
	RequestURIs              []string        `json:"request_uris,omitempty"`
	RequestObjectSigningAlg  string          `json:"request_object_signing_alg,omitempty"`
	PostLogoutRedirectURIs   []string        `json:"post_logout_redirect_uris,omitempty"`

	// SoftwareStatement is parsed only so the handler can detect its
	// presence and reject with invalid_software_statement; v1.0 does
	// not implement RFC 7591 §3.1.1 software statement verification.
	SoftwareStatement string `json:"software_statement,omitempty"`

	// ClientID is parsed solely so the handler can detect that the
	// caller tried to mutate the immutable identifier (RFC 7592 §2.2);
	// the value is otherwise ignored.
	ClientID string `json:"client_id,omitempty"`

	// RFC 7592 reserved response fields. The PUT path MUST reject
	// requests that try to write these values back.
	ClientSecret            json.RawMessage `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   json.RawMessage `json:"client_secret_expires_at,omitempty"`
	ClientIDIssuedAt        json.RawMessage `json:"client_id_issued_at,omitempty"`
	RegistrationAccessToken json.RawMessage `json:"registration_access_token,omitempty"`
	RegistrationClientURI   json.RawMessage `json:"registration_client_uri,omitempty"`
}

// metadataExtras carries the wire fields that are not part of the
// [ClientMetadata] surface but the validator still needs to inspect.
// Returned alongside [ClientMetadata] only when the caller wants to
// reject software_statement or detect a client_id override; the POST
// path uses this to fail with invalid_software_statement, the PUT path
// uses it to enforce immutability.
type metadataExtras struct {
	SoftwareStatement string
	ClientID          string
	ClientSecret      json.RawMessage
	ClientSecretExp   json.RawMessage
	ClientIDIssuedAt  json.RawMessage
	RegAccessToken    json.RawMessage
	RegClientURI      json.RawMessage
}

// parseClientMetadataWithExtras is the variant the handler uses; it
// returns both the public-shape metadata and the wire extras (software
// statement, attempted client_id) so the call site can reject those
// before running the structural validator.
func parseClientMetadataWithExtras(r io.Reader) (ClientMetadata, metadataExtras, error) {
	var w metadataWire
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return ClientMetadata{}, metadataExtras{}, fmt.Errorf("registrationendpoint: decode metadata: %w", err)
	}
	m := ClientMetadata{
		RedirectURIs:             cloneStrings(w.RedirectURIs),
		GrantTypes:               cloneStrings(w.GrantTypes),
		ResponseTypes:            cloneStrings(w.ResponseTypes),
		Scope:                    w.Scope,
		TokenEndpointAuthMethod:  w.TokenEndpointAuthMethod,
		ApplicationType:          w.ApplicationType,
		SubjectType:              w.SubjectType,
		IDTokenSignedResponseAlg: w.IDTokenSignedResponseAlg,
		SectorIdentifierURI:      w.SectorIdentifierURI,
		ClientName:               w.ClientName,
		ClientURI:                w.ClientURI,
		LogoURI:                  w.LogoURI,
		PolicyURI:                w.PolicyURI,
		TosURI:                   w.TosURI,
		JWKsURI:                  w.JWKsURI,
		JWKs:                     append(json.RawMessage(nil), w.JWKs...),
		Contacts:                 cloneStrings(w.Contacts),
		DefaultMaxAge:            cloneInt64Ptr(w.DefaultMaxAge),
		RequireAuthTime:          w.RequireAuthTime,
		DefaultACRValues:         cloneStrings(w.DefaultACRValues),
		InitiateLoginURI:         w.InitiateLoginURI,
		RequestURIs:              cloneStrings(w.RequestURIs),
		RequestObjectSigningAlg:  w.RequestObjectSigningAlg,
		PostLogoutRedirectURIs:   cloneStrings(w.PostLogoutRedirectURIs),
	}
	extras := metadataExtras{
		SoftwareStatement: w.SoftwareStatement,
		ClientID:          w.ClientID,
		ClientSecret:      append(json.RawMessage(nil), w.ClientSecret...),
		ClientSecretExp:   append(json.RawMessage(nil), w.ClientSecretExpiresAt...),
		ClientIDIssuedAt:  append(json.RawMessage(nil), w.ClientIDIssuedAt...),
		RegAccessToken:    append(json.RawMessage(nil), w.RegistrationAccessToken...),
		RegClientURI:      append(json.RawMessage(nil), w.RegistrationClientURI...),
	}
	return m, extras, nil
}

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

func cloneInt64Ptr(v *int64) *int64 {
	if v == nil {
		return nil
	}
	out := *v
	return &out
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

// validateRedirectURIs enforces the RFC 6749 §3.1.2 baseline plus the
// RFC 8252 §7.3 native-app loopback carve-out and OIDC Registration §2
// rules: every URL MUST be absolute, parseable, fragment-free, and
// match the scheme/host shape allowed for its application_type. Web
// clients require https (with a loopback-http carve-out gated by
// allowLocalhostLoopback for backward compatibility); native clients
// additionally accept loopback http unconditionally and custom URI
// schemes per RFC 8252 §7.1. The default IP-only loopback posture
// reflects the §8.3 DNS-rebinding concern. The caller's
// [ValidateMetadata] hook may tighten further.
func validateRedirectURIs(uris []string, applicationType string, hasImplicit, allowLocalhostLoopback bool) error {
	if len(uris) == 0 {
		return errInvalidRedirectURI("redirect_uris is required")
	}
	for _, raw := range uris {
		if err := validateRedirectURI(raw, applicationType, hasImplicit, allowLocalhostLoopback); err != nil {
			return err
		}
	}
	return nil
}

// validateRedirectURI enforces the per-URI rules. Split out from
// [validateRedirectURIs] so the per-row check stays under the
// project's gocognit / cyclop caps and so the error messages stay
// per-URI rather than masking the offending entry behind a generic
// loop diagnostic.
func validateRedirectURI(raw, applicationType string, hasImplicit, allowLocalhostLoopback bool) error {
	if raw == "" {
		return errInvalidRedirectURI("redirect_uri must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidRedirectURI("redirect_uri is not a valid URL")
	}
	if !u.IsAbs() {
		return errInvalidRedirectURI("redirect_uri must be absolute")
	}
	if u.Fragment != "" {
		return errInvalidRedirectURI("redirect_uri must not contain a fragment")
	}
	if applicationType == applicationTypeNative {
		return validateNativeRedirectURIScheme(u)
	}
	return validateWebRedirectURIScheme(u, hasImplicit, allowLocalhostLoopback)
}

// validateNativeRedirectURIScheme implements OIDC Registration §2 +
// RFC 8252 §7.1/§7.2/§7.3 for native clients: https (claimed), loopback
// http, or a custom URI scheme. Loopback http accepts the textual
// "localhost" host unconditionally for native clients per OIDC Reg §2;
// the AllowLocalhostLoopback gate is for the web-client carve-out only.
func validateNativeRedirectURIScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), true) {
			return errInvalidRedirectURI("native client redirect_uri http scheme requires a loopback host (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
		}
		return nil
	default:
		return validateNativeCustomScheme(u.Scheme)
	}
}

// validateNativeCustomScheme implements RFC 8252 §7.1 private-use URI
// scheme handling: schemes are accepted, but a non-reverse-DNS shape
// (no "." in the scheme, e.g. "myapp" instead of "com.example.myapp")
// is rejected because non-reverse-DNS schemes have a higher collision
// risk across applications. Schemes that collide with well-known web
// schemes are rejected outright.
func validateNativeCustomScheme(scheme string) error {
	if scheme == "" {
		return errInvalidRedirectURI("redirect_uri scheme must not be empty")
	}
	switch scheme {
	case "ftp", "file", "data", "javascript", "ws", "wss":
		return errInvalidRedirectURI("redirect_uri scheme " + scheme + " is not permitted for native clients")
	}
	if !strings.Contains(scheme, ".") {
		return errInvalidRedirectURI("native client custom URI scheme " + scheme + " SHOULD use reverse-DNS form (e.g. com.example.app); register a scheme containing a dot per RFC 8252 §7.1")
	}
	return nil
}

// validateWebRedirectURIScheme implements OIDC Registration §2 for web
// clients: https only, with the historical AllowLocalhostLoopback gate
// still admitting loopback-http for embedders that opted in before the
// native-app split. Implicit grant additionally forbids localhost host
// shapes per OIDC Reg §2.
func validateWebRedirectURIScheme(u *url.URL, hasImplicit, allowLocalhostLoopback bool) error {
	switch u.Scheme {
	case "https":
		if hasImplicit && isLoopbackRedirectHost(u.Hostname(), true) {
			return errInvalidRedirectURI("web client with implicit response_types must not use a loopback host as redirect_uri per OIDC Registration §2")
		}
		return nil
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), allowLocalhostLoopback) {
			if allowLocalhostLoopback {
				return errInvalidRedirectURI("redirect_uri http scheme is permitted only for loopback hosts (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
			}
			return errInvalidRedirectURI("redirect_uri http scheme is permitted only for loopback IP literals (127.0.0.1, [::1]) per RFC 8252 §7.3 + §8.3; pass op.WithAllowLocalhostLoopback() to also admit the textual \"localhost\" host")
		}
		return nil
	default:
		return errInvalidRedirectURI("web client redirect_uri scheme must be https; custom URI schemes require application_type=native")
	}
}

// validatePostLogoutRedirectURIs enforces the OpenID Connect
// RP-Initiated Logout 1.0 §3 requirement that every
// post_logout_redirect_uris entry be an absolute, fragment-free URL the
// OP can later compare byte-for-byte against /end_session input. The
// scheme matrix mirrors the redirect_uris policy: native clients may
// use https, loopback http (RFC 8252 §7.3), or a reverse-DNS custom
// scheme; web clients may use https with the existing AllowLocalhostLoopback
// gate widening the loopback http carve-out to the textual "localhost".
// On any failure the error code is invalid_client_metadata (the field
// is post-logout-specific; the redirect_uris-shaped invalid_redirect_uri
// code would mis-categorise it) and the description names both
// "post_logout_redirect_uris" and "loopback" so embedders can
// self-correct without inspecting source.
func validatePostLogoutRedirectURIs(uris []string, applicationType string, allowLocalhostLoopback bool) error {
	if len(uris) == 0 {
		return nil
	}
	for _, raw := range uris {
		if err := validatePostLogoutRedirectURI(raw, applicationType, allowLocalhostLoopback); err != nil {
			return err
		}
	}
	return nil
}

// validatePostLogoutRedirectURI runs the per-URI checks from
// [validatePostLogoutRedirectURIs]. Split out so the per-row diagnostic
// names the offending entry rather than collapsing the loop into a
// single message and so the gocognit / cyclop budget on the parent
// helper stays well below the project caps.
func validatePostLogoutRedirectURI(raw, applicationType string, allowLocalhostLoopback bool) error {
	if raw == "" {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry must not be empty (loopback http requires 127.0.0.1, [::1], or localhost when AllowLocalhostLoopback is set)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry " + raw + " is not a valid URL (loopback http hosts must be 127.0.0.1, [::1], or localhost)")
	}
	if !u.IsAbs() {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry " + raw + " must be an absolute URL (loopback http requires the explicit scheme://host form)")
	}
	if u.Fragment != "" {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry " + raw + " must not contain a fragment (loopback http URIs are compared byte-for-byte at /end_session)")
	}
	if applicationType == applicationTypeNative {
		return validateNativePostLogoutScheme(u)
	}
	return validateWebPostLogoutScheme(u, allowLocalhostLoopback)
}

// validateNativePostLogoutScheme implements the native carve-out for
// post_logout_redirect_uris: https, loopback http (the textual
// "localhost" host is admitted unconditionally for native clients,
// matching [validateNativeRedirectURIScheme]), or a reverse-DNS custom
// scheme per RFC 8252 §7.1.
func validateNativePostLogoutScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), true) {
			return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris http scheme for native clients requires a loopback host (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
		}
		return nil
	default:
		if err := validateNativeCustomScheme(u.Scheme); err != nil {
			return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris " + u.String() + ": " + err.Error() + " (loopback http hosts: 127.0.0.1, [::1], localhost)")
		}
		return nil
	}
}

// validateWebPostLogoutScheme implements the web-client policy:
// https only, with the AllowLocalhostLoopback gate admitting loopback
// http for embedders that opted in. Mirrors
// [validateWebRedirectURIScheme] without the implicit-flow carve-out
// (post_logout never participates in the implicit response).
func validateWebPostLogoutScheme(u *url.URL, allowLocalhostLoopback bool) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), allowLocalhostLoopback) {
			if allowLocalhostLoopback {
				return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris http scheme is permitted only for loopback hosts (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
			}
			return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris http scheme is permitted only for loopback IP literals (127.0.0.1, [::1]); pass op.WithAllowLocalhostLoopback() to also admit the textual \"localhost\" host")
		}
		return nil
	default:
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris scheme must be https for web clients; loopback http (127.0.0.1, [::1], localhost) and custom URI schemes require application_type=native")
	}
}

// errInvalidPostLogoutRedirectURI constructs a [validationError] whose
// description always names both "post_logout_redirect_uris" and
// "loopback". Centralising the wording keeps the embedder-facing
// contract — "if you see this error, the literal substrings tell you
// which field and which carve-out applies" — encoded in one place.
func errInvalidPostLogoutRedirectURI(desc string) error {
	return errInvalidClientMetadata(desc)
}

// hasImplicitResponseType reports whether any response_type entry
// contains an implicit-flow token (id_token or token without code).
func hasImplicitResponseType(responseTypes []string) bool {
	for _, rt := range responseTypes {
		toks := strings.Fields(rt)
		hasCode := slices.Contains(toks, "code")
		hasToken := slices.Contains(toks, "token")
		hasIDToken := slices.Contains(toks, "id_token")
		if !hasCode && (hasToken || hasIDToken) {
			return true
		}
	}
	return false
}

// isLoopbackRedirectHost reports whether host is a loopback literal
// the RFC 8252 §7.3 native-app carve-out admits over plain http. The
// IP literals 127.0.0.1 and [::1] are always admitted; the textual
// "localhost" token is admitted only when allowLocalhostLoopback is
// true. Hostname() strips the bracket from "[::1]"; we only accept
// the exact loopback addresses (not the 127.0.0.0/8 block) because a
// DCR-supplied redirect_uri names the URI the client expects to
// receive on — there is no operational reason to register 127.0.0.2.
func isLoopbackRedirectHost(host string, allowLocalhostLoopback bool) bool {
	if host == "" {
		return false
	}
	if allowLocalhostLoopback && strings.EqualFold(host, "localhost") {
		return true
	}
	switch host {
	case "127.0.0.1", "::1":
		return true
	}
	return false
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

// cloneStrings returns a fresh copy of in so a later mutation of the
// caller's slice cannot retroactively change the parsed value. nil
// inputs return nil.
func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return slices.Clone(in)
}

// Library defaults for the OIDC profile fields when the caller leaves
// them blank. The values mirror 02-product-design.md
// §A.6.2 / §K.3.
const (
	defaultAuthMethod      = "client_secret_basic"
	defaultSubjectType     = "public"
	defaultIDTokenAlg      = "ES256"
	defaultApplicationType = "web"
	applicationTypeNative  = "native"
)
