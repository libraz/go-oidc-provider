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
	DefaultMaxAge            int64
	RequireAuthTime          bool
	DefaultACRValues         []string
	InitiateLoginURI         string
	RequestURIs              []string
	RequestObjectSigningAlg  string
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
	DefaultMaxAge            int64           `json:"default_max_age,omitempty"`
	RequireAuthTime          bool            `json:"require_auth_time,omitempty"`
	DefaultACRValues         []string        `json:"default_acr_values,omitempty"`
	InitiateLoginURI         string          `json:"initiate_login_uri,omitempty"`
	RequestURIs              []string        `json:"request_uris,omitempty"`
	RequestObjectSigningAlg  string          `json:"request_object_signing_alg,omitempty"`

	// SoftwareStatement is parsed only so the handler can detect its
	// presence and reject with invalid_software_statement; v1.0 does
	// not implement RFC 7591 §3.1.1 software statement verification.
	SoftwareStatement string `json:"software_statement,omitempty"`

	// ClientID is parsed solely so the handler can detect that the
	// caller tried to mutate the immutable identifier (RFC 7592 §2.2);
	// the value is otherwise ignored.
	ClientID string `json:"client_id,omitempty"`
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
		DefaultMaxAge:            w.DefaultMaxAge,
		RequireAuthTime:          w.RequireAuthTime,
		DefaultACRValues:         cloneStrings(w.DefaultACRValues),
		InitiateLoginURI:         w.InitiateLoginURI,
		RequestURIs:              cloneStrings(w.RequestURIs),
		RequestObjectSigningAlg:  w.RequestObjectSigningAlg,
	}
	extras := metadataExtras{
		SoftwareStatement: w.SoftwareStatement,
		ClientID:          w.ClientID,
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
) (ClientMetadata, error) {
	if err := validateRedirectURIs(m.RedirectURIs); err != nil {
		return ClientMetadata{}, err
	}
	canonical := applyMetadataDefaults(m, allowedGrantTypes, allowedResponseTypes)
	if err := validateGrantTypes(canonical.GrantTypes, allowedGrantTypes); err != nil {
		return ClientMetadata{}, err
	}
	if err := validateResponseTypes(canonical.ResponseTypes, allowedResponseTypes); err != nil {
		return ClientMetadata{}, err
	}
	if err := validateAuthMethod(canonical.TokenEndpointAuthMethod); err != nil {
		return ClientMetadata{}, err
	}
	if err := validateSubjectType(canonical.SubjectType, pairwiseEnabled); err != nil {
		return ClientMetadata{}, err
	}
	if err := validateIDTokenAlg(canonical.IDTokenSignedResponseAlg); err != nil {
		return ClientMetadata{}, err
	}
	if err := validateRequestedScopes(canonical.Scope, iatScopes, scopes); err != nil {
		return ClientMetadata{}, err
	}
	return canonical, nil
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
// RFC 8252 §7.3 native-app loopback carve-out: every URL MUST be
// absolute, parseable, fragment-free, and either an https URL or a
// plain http URL whose host is a loopback literal (127.0.0.1, [::1],
// or localhost). Any other http URL — public hosts, private hosts,
// arbitrary domain names — is rejected so a hostile DCR cannot
// register a non-TLS redirect target on the open internet. The
// caller's [ValidateMetadata] hook may tighten further.
func validateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return errInvalidRedirectURI("redirect_uris is required")
	}
	for _, raw := range uris {
		if err := validateRedirectURI(raw); err != nil {
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
func validateRedirectURI(raw string) error {
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
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !isLoopbackRedirectHost(u.Hostname()) {
			return errInvalidRedirectURI("redirect_uri http scheme is permitted only for loopback hosts (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
		}
		return nil
	default:
		// Custom schemes (myapp:// for native-app rDNS) are rejected
		// at this layer; the [ValidateMetadata] embedder hook is the
		// seam for embedders that admit them under their own policy.
		return errInvalidRedirectURI("redirect_uri scheme must be https (http is restricted to loopback)")
	}
}

// isLoopbackRedirectHost reports whether host is a loopback literal
// the RFC 8252 §7.3 native-app carve-out admits over plain http. The
// match is case-insensitive on the textual "localhost" token and
// numeric on the IP literals; any other value (private IPs, public
// names, "::") falls through to the rejection path.
func isLoopbackRedirectHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// Hostname() strips the bracket from "[::1]"; net.ParseIP
	// accepts both "127.0.0.1" and "::1" verbatim. We only admit
	// the exact loopback addresses, not the entire 127.0.0.0/8
	// block, because a DCR-supplied redirect_uri carries the URI
	// the client is expected to receive on — there is no operational
	// reason to accept 127.0.0.2.
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
)
