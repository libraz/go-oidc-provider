package authorize

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Request is the parsed view of an authorization endpoint request, with all
// fields normalised: scope and prompt are split on ASCII whitespace, scope
// is deduplicated with order preserved, and max_age is parsed into a
// pointer so "absent" and "0" are distinguishable.
//
// Construct via [ParseRequest] (from an *http.Request) or [ParseValues]
// (from pre-extracted [url.Values]); both helpers run identical parsing.
// Validation against a registered client is a separate step on the value:
// see [Request.Validate].
type Request struct {
	// ClientID is the OAuth client_id parameter, verbatim.
	ClientID string

	// ResponseType is the OAuth response_type parameter, verbatim. The
	// validator only accepts "code" but parsing preserves whatever the
	// client sent so the eventual error message can echo it back.
	ResponseType string

	// RedirectURI is the OAuth redirect_uri parameter, verbatim. Byte-
	// equal comparison against the client's registered list happens in
	// [Request.Validate].
	RedirectURI string

	// Scope is the requested scope list, split on ASCII whitespace and
	// deduplicated with first-occurrence order preserved.
	Scope []string

	// State is the OAuth state parameter, verbatim.
	State string

	// Nonce is the OIDC nonce parameter, verbatim.
	Nonce string

	// CodeChallenge is the PKCE code_challenge parameter, verbatim.
	CodeChallenge string

	// CodeChallengeMethod is the PKCE code_challenge_method parameter.
	// The validator only accepts [pkce.Method] ("S256").
	CodeChallengeMethod string

	// Prompt is the OIDC prompt list, split on ASCII space (OIDC Core
	// §3.1.2.1 mandates space, not generic whitespace; the parser
	// follows the spec).
	Prompt []string

	// MaxAge is the OIDC max_age parameter, parsed into a pointer so the
	// validator can distinguish "absent" from a literal "0". A non-nil
	// value is guaranteed to be non-negative.
	MaxAge *int64

	// LoginHint is the OIDC login_hint parameter, verbatim.
	LoginHint string

	// UILocales is the OIDC ui_locales list, split on ASCII whitespace.
	UILocales []string

	// ACRValues is the OIDC acr_values list, split on ASCII whitespace.
	ACRValues []string

	// ResponseMode is the OAuth response_mode parameter, verbatim. The
	// validator accepts the empty string (the response_type-implied
	// default), the legacy "query" / "form_post" values, and the four
	// JARM values ("query.jwt", "fragment.jwt", "form_post.jwt", "jwt").
	// Whether a JARM mode is actually permitted at the wire layer is the
	// HTTP layer's responsibility — the [feature.JARM] gate is checked
	// there because the validator does not know feature flags.
	ResponseMode string

	// RequestObject is the raw JAR "request" parameter (RFC 9101 §6.1)
	// when the wire form carried one, before signature verification.
	// The validator does not verify it — that requires JWKS access only
	// available at the HTTP layer — but does enforce structural rules
	// (mutually exclusive with RequestURI, non-empty when present).
	RequestObject string

	// RequestURI is the raw JAR "request_uri" parameter (RFC 9101 §5.2.2
	// or RFC 9126 §2.2). The HTTP layer disambiguates between the JAR
	// and PAR forms by inspecting the URN prefix; the validator only
	// enforces that the value parses as a URI when present.
	RequestURI string

	// DPoPJKT is the RFC 9449 §10 "dpop_jkt" parameter — the SHA-256
	// thumbprint of the DPoP key the client commits to using at the
	// token endpoint. Empty when the wire form omitted it. The
	// validator does not check the format here; the HTTP layer
	// matches it against the inbound DPoP proof's JKT (when both are
	// present) and persists it onto the authorization_code so the
	// /token endpoint can refuse a proof signed with a different
	// key.
	DPoPJKT string

	// PARRequestURI is the urn:ietf:params:oauth:request_uri:* identifier
	// the request was loaded from when /authorize resolved a PAR record.
	// Empty for non-PAR requests. The field is set by the PAR consumption
	// path in the authorize endpoint and threaded through the snapshot
	// so the eventual code emission can mark the record one-time-used
	// (RFC 9126 §2.2). It is never parsed from the wire form.
	PARRequestURI string

	// Claims is the parsed OIDC Core 1.0 §5.5 "claims" request
	// parameter. Nil when the wire form omitted the parameter or when
	// the OP is configured to ignore it. The grant emission path
	// round-trips this field through [RequestSnapshot] so the token
	// and userinfo endpoints can honour the requested claim
	// projection without re-parsing the wire form.
	Claims *ClaimsRequest
}

// ParseRequest extracts the canonical [Request] from r. For GET it reads
// r.URL.Query(); for POST it parses the form body via [http.Request.ParseForm]
// and reads r.PostForm. Other methods produce no parameters and the parser
// will surface the request-level errors that follow.
//
// ParseRequest does NOT validate against any client. Its sole job is to
// turn the wire form into a normalised value, plus the structural checks
// that have no client dependency (duplicate single-valued parameters,
// repeated multi-valued parameters, malformed max_age).
func ParseRequest(r *http.Request) (*Request, error) {
	values, err := extractValues(r)
	if err != nil {
		return nil, err
	}
	return ParseValues(values)
}

// ParseValues parses the same [Request] shape from a pre-extracted
// [url.Values]. It is the kernel that [ParseRequest] delegates to and is
// exported so tests and adjacent packages (PAR, JAR) can reuse the parser
// without constructing a real *http.Request.
func ParseValues(v url.Values) (*Request, error) {
	singles, err := parseSingleValues(v)
	if err != nil {
		return nil, err
	}
	multis, err := parseMultiValues(v)
	if err != nil {
		return nil, err
	}
	maxAge, err := parseMaxAge(v)
	if err != nil {
		return nil, err
	}
	claims, err := ParseClaimsRequest(singles["claims"])
	if err != nil {
		return nil, err
	}
	return &Request{
		ClientID:            singles["client_id"],
		ResponseType:        singles["response_type"],
		RedirectURI:         singles["redirect_uri"],
		Scope:               dedupePreserve(strings.Fields(multis["scope"])),
		State:               singles["state"],
		Nonce:               singles["nonce"],
		CodeChallenge:       singles["code_challenge"],
		CodeChallengeMethod: singles["code_challenge_method"],
		Prompt:              splitPrompt(multis["prompt"]),
		MaxAge:              maxAge,
		LoginHint:           singles["login_hint"],
		UILocales:           strings.Fields(multis["ui_locales"]),
		ACRValues:           strings.Fields(multis["acr_values"]),
		ResponseMode:        singles["response_mode"],
		RequestObject:       singles["request"],
		RequestURI:          singles["request_uri"],
		DPoPJKT:             singles["dpop_jkt"],
		Claims:              claims,
	}, nil
}

// singleParseFields is the closed list of single-valued parameters
// [parseSingleValues] reads. Centralising the list keeps the parser
// loop short enough to stay under the project complexity gate.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var singleParseFields = []string{
	"client_id",
	"response_type",
	"redirect_uri",
	"state",
	"nonce",
	"code_challenge",
	"code_challenge_method",
	"login_hint",
	"response_mode",
	"request",
	"request_uri",
	"dpop_jkt",
	"claims",
}

// parseSingleValues extracts every single-valued parameter from v,
// surfacing [ErrDuplicateParameter] on the first conflict it finds.
func parseSingleValues(v url.Values) (map[string]string, error) {
	out := make(map[string]string, len(singleParseFields))
	for _, name := range singleParseFields {
		val, err := singleValue(v, name)
		if err != nil {
			return nil, err
		}
		out[name] = val
	}
	return out, nil
}

// multiParseFields lists the multi-valued parameters [parseMultiValues]
// reads. Each member is admitted at most once in the wire form
// (multi-valued semantics live inside the value, not the [url.Values]
// entry); the helpers below enforce that contract.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var multiParseFields = []string{"scope", "prompt", "ui_locales", "acr_values"}

// parseMultiValues extracts every multi-valued parameter from v.
// "scope" / "ui_locales" / "acr_values" are read via [multiValue] and
// "prompt" is read via [singleEntry]; the difference is documented on
// the helpers themselves.
func parseMultiValues(v url.Values) (map[string]string, error) {
	out := make(map[string]string, len(multiParseFields))
	for _, name := range multiParseFields {
		var (
			val string
			err error
		)
		if name == "prompt" {
			val, err = singleEntry(v, name)
		} else {
			val, err = multiValue(v, name)
		}
		if err != nil {
			return nil, err
		}
		out[name] = val
	}
	return out, nil
}

// Policy carries the runtime policy bits the [Request.Validate]
// pipeline consults. A zero value means "no profile is active": PKCE
// is recommended but not enforced when the request omits
// code_challenge entirely. Setting [Policy.PKCERequired] reverses
// that — every request MUST carry a code_challenge — and matches the
// FAPI 2.0 / OAuth 2.1 stance.
//
// The struct is intentionally shaped as a struct rather than a
// growing parameter list so future policy bits (DPoP-required,
// nonce-mandatory) can land without rewiring every caller.
type Policy struct {
	// PKCERequired forces every authorization-code request to carry a
	// code_challenge. Embedders configure this through the public
	// [op.WithProfile] surface; the validator does not consult the
	// profile itself, only the resolved bit.
	PKCERequired bool

	// NonceRequired forces every authorization request to carry a
	// nonce parameter. OIDC Core 1.0 makes nonce OPTIONAL for code-
	// flow. As with PKCERequired the validator only consults the
	// resolved bit, not the profile set itself.
	//
	// FAPI 2.0 Baseline / Message Signing do NOT set this bit: the
	// profile mandates "state OR nonce", which the [StateOrNonceRequired]
	// gate enforces instead. NonceRequired remains available for
	// embedders that want a strict nonce-on-every-request policy.
	NonceRequired bool

	// StateOrNonceRequired forces every authorization request to carry
	// at least one of state / nonce, satisfying FAPI 2.0 §5.3.2.1.1's
	// "either a state or a nonce" rule. Vanilla OIDC Core leaves this
	// false because state is RECOMMENDED, not required.
	StateOrNonceRequired bool

	// OpenIDScopeOptional, when true, lifts the OIDC Core 1.0
	// §3.1.2.1 requirement that every authorization request include
	// the "openid" scope. The default (false) matches OIDC: a request
	// without "openid" surfaces ErrScopeMissingOpenID. Embedders flip
	// this through the public [op.WithOpenIDScopeOptional] surface
	// when they intend to serve plain OAuth 2.0 authorization_code
	// flows alongside OIDC.
	OpenIDScopeOptional bool
}

// Validate cross-checks the parsed [Request] against the registered client
// and the OP's policy. The order is deliberate: client_id and redirect_uri
// run first because the eventual HTTP layer cannot redirect errors back to
// an RP whose redirect target it has not yet trusted.
//
// scopes is the OP's read-only scope registry. A nil value disables the
// AllowedClients allowlist check; the registered-client scope intersection
// still runs.
//
// policy carries runtime knobs that toggle individual checks (PKCE
// requirement, future profile-driven flags). A zero value selects the
// permissive defaults — only the spec-MUST checks fire.
//
// Callers MUST consult [IsRedirectSafe] before deciding whether to redirect
// on the returned error. The boundary is: every error produced before
// redirect_uri verification (ErrClientIDRequired, ErrRedirectURIRequired,
// ErrRedirectURIInvalid) is NOT redirect-safe; every error produced after
// is.
func (req *Request) Validate(client *store.Client, scopes *scoperegistry.Registry, policy Policy) error {
	if err := req.validateRedirectTarget(client); err != nil {
		return err
	}
	if err := req.validateResponseType(); err != nil {
		return err
	}
	if err := req.validateResponseMode(); err != nil {
		return err
	}
	if err := req.validateState(policy.StateOrNonceRequired); err != nil {
		return err
	}
	if err := req.validateScope(client, scopes, policy.OpenIDScopeOptional); err != nil {
		return err
	}
	if err := req.validateNonce(policy.NonceRequired); err != nil {
		return err
	}
	if err := req.validatePKCE(policy.PKCERequired); err != nil {
		return err
	}
	if err := req.validatePrompt(); err != nil {
		return err
	}
	return nil
}

// validateRedirectTarget enforces the not-redirect-safe checks: client_id
// and redirect_uri MUST be present and the redirect_uri MUST exact-match an
// entry in the client's registered list.
func (req *Request) validateRedirectTarget(client *store.Client) error {
	if req.ClientID == "" {
		return ErrClientIDRequired
	}
	if req.RedirectURI == "" {
		return ErrRedirectURIRequired
	}
	if client == nil || !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return ErrRedirectURIInvalid
	}
	return nil
}

// validateResponseType rejects every value other than the literal "code".
// Implicit / Hybrid flows are not shipped in v1.0.
func (req *Request) validateResponseType() error {
	if req.ResponseType != "code" {
		return ErrResponseTypeUnsupported
	}
	return nil
}

// validateResponseMode rejects unknown response_mode values. The empty
// string (default for the response_type) and the v0.x-supported set
// {"query", "form_post"} pass; the four JARM values
// {"query.jwt", "fragment.jwt", "form_post.jwt", "jwt"} pass too. The
// HTTP layer is still expected to enforce the [feature.JARM] gate
// before honouring a JARM mode — this validator only filters the
// catalogue of known names.
func (req *Request) validateResponseMode() error {
	switch req.ResponseMode {
	case "", "query", "form_post",
		"query.jwt", "fragment.jwt", "form_post.jwt", "jwt":
		return nil
	default:
		return ErrResponseModeUnsupported
	}
}

// validateState reports an error when state is required but absent.
// OAuth 2.0 / 2.1 RECOMMEND state as a CSRF defence; FAPI 2.0 ID2
// §5.3.2.1.1 mandates that clients include "either a state or a
// nonce" — i.e. at least one of the two, not both. The check is
// therefore satisfied if EITHER state is present OR a nonce is. This
// matches the OFCS expectation that "ensure-authorization-request-
// without-state-success" succeeds when nonce is supplied.
func (req *Request) validateState(stateOrNonceRequired bool) error {
	if !stateOrNonceRequired {
		return nil
	}
	if req.State == "" && req.Nonce == "" {
		return ErrStateRequired
	}
	return nil
}

// validateScope enforces the OIDC requirement that "openid" be present,
// the policy that every requested scope appear in the client's registered
// list, and the per-scope AllowedClients allowlist (op.Scope.AllowedClients
// from the registry). A nil registry disables only the allowlist check.
//
// openIDOptional, when true, lifts the "openid" requirement so the OP
// can serve plain OAuth 2.0 authorization_code flows. The
// client-registered-scope intersection and the allowlist still run
// — the only relaxation is the OIDC-mandatory "openid" presence check.
func (req *Request) validateScope(client *store.Client, scopes *scoperegistry.Registry, openIDOptional bool) error {
	if !openIDOptional && !slices.Contains(req.Scope, "openid") {
		return ErrScopeMissingOpenID
	}
	for _, s := range req.Scope {
		if !slices.Contains(client.Scopes, s) {
			return ErrScopeNotPermitted
		}
		if !scopes.Allows(s, client.ID) {
			return ErrScopeClientNotAllowed
		}
	}
	return nil
}

// validateNonce enforces the policy-conditional nonce rule. When
// required is true (FAPI 2.0 / explicit profile MUST) every request
// MUST carry a nonce; otherwise the empty value is accepted, matching
// the OIDC Core 1.0 errata that nonce is OPTIONAL for code-flow.
// id_token issuance keys on the stored value, so an absent nonce
// transparently omits the claim.
func (req *Request) validateNonce(required bool) error {
	if req.Nonce == "" && required {
		return ErrNonceRequired
	}
	return nil
}

// validatePKCE enforces the OP's PKCE policy and delegates challenge
// format checks to [pkce.ValidateChallenge]. When required is true,
// every request MUST carry a code_challenge (FAPI 2.0 / OAuth 2.1
// posture). When required is false, an absent challenge falls
// through silently and the PKCE flow is opted out for this request;
// a present challenge is still format-validated so a half-supplied
// pair (challenge but no method, or vice versa) produces a clear
// error rather than silent acceptance.
func (req *Request) validatePKCE(required bool) error {
	if req.CodeChallenge == "" {
		if required {
			return ErrPKCERequired
		}
		// PKCE is not active for this request. The grant-side code
		// path keys verification on the stored CodeChallenge, so an
		// empty value disables the verifier symmetrically.
		return nil
	}
	if req.CodeChallengeMethod == "" || req.CodeChallengeMethod != pkce.Method {
		return ErrPKCEMethodUnsupported
	}
	if err := pkce.ValidateChallenge(req.CodeChallenge, req.CodeChallengeMethod); err != nil {
		return translatePKCEErr(err)
	}
	return nil
}

// validatePrompt enforces the OIDC Core §3.1.2.1 prompt grammar: every
// value must be one of the four known names and "none" cannot be combined.
func (req *Request) validatePrompt() error {
	if len(req.Prompt) == 0 {
		return nil
	}
	hasNone := false
	for _, p := range req.Prompt {
		if !isKnownPrompt(p) {
			return ErrPromptInvalid
		}
		if p == "none" {
			hasNone = true
		}
	}
	if hasNone && len(req.Prompt) > 1 {
		return ErrPromptConflict
	}
	return nil
}

// isKnownPrompt reports whether p is one of the four prompt names OIDC
// Core §3.1.2.1 defines.
func isKnownPrompt(p string) bool {
	switch p {
	case "none", interaction.PromptLogin, interaction.PromptConsent, interaction.PromptSelectAccount:
		return true
	default:
		return false
	}
}

// translatePKCEErr maps the [pkce] sentinel errors onto the [authorize]
// catalogue. Format-class errors collapse onto [ErrPKCEFormat]; method
// errors collapse onto [ErrPKCEMethodUnsupported]; everything else falls
// through unchanged so the caller can spot a contract drift.
func translatePKCEErr(err error) error {
	switch {
	case errors.Is(err, pkce.ErrChallengeRequired):
		return ErrPKCERequired
	case errors.Is(err, pkce.ErrChallengeMethodUnsupported):
		return ErrPKCEMethodUnsupported
	case errors.Is(err, pkce.ErrChallengeFormat):
		return ErrPKCEFormat
	default:
		return err
	}
}

// extractValues returns the [url.Values] the parser should consume.
// GET requests use [http.Request.URL.Query()]; POST requests use the parsed
// form. Other methods return an empty value set so the per-parameter
// "required" checks fire in the validator.
func extractValues(r *http.Request) (url.Values, error) {
	if r == nil {
		return nil, ErrClientIDRequired
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		return r.PostForm, nil
	}
	return r.URL.Query(), nil
}

// singleValue returns the value of a single-valued parameter. Multiple
// occurrences are tolerated only when every value is byte-equal; differing
// values produce [ErrDuplicateParameter].
func singleValue(v url.Values, key string) (string, error) {
	values, ok := v[key]
	if !ok || len(values) == 0 {
		return "", nil
	}
	first := values[0]
	for _, candidate := range values[1:] {
		if candidate != first {
			return "", ErrDuplicateParameter
		}
	}
	return first, nil
}

// singleEntry returns the single occurrence of a multi-valued parameter
// that is permitted to appear at most once in [url.Values]. Repeated entries
// are rejected with [ErrDuplicateParameter] (concatenating would mask the
// case where a client legitimately needed to repeat the parameter, which
// the spec does not require).
func singleEntry(v url.Values, key string) (string, error) {
	values, ok := v[key]
	if !ok || len(values) == 0 {
		return "", nil
	}
	if len(values) > 1 {
		return "", ErrDuplicateParameter
	}
	return values[0], nil
}

// multiValue returns the single space-delimited string for a multi-valued
// parameter. Like [singleEntry], it rejects repetition rather than
// concatenating.
func multiValue(v url.Values, key string) (string, error) {
	return singleEntry(v, key)
}

// parseMaxAge extracts the max_age parameter into a *int64 so the caller
// can tell "absent" from "0". An empty string is treated as absent. Non-
// integer values, negative values, and integers that overflow int64 are
// rejected with [ErrMaxAgeInvalid].
func parseMaxAge(v url.Values) (*int64, error) {
	raw, err := singleValue(v, "max_age")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil //nolint:nilnil // documented "absent" sentinel
	}
	parsed, parseErr := strconv.ParseInt(raw, 10, 64)
	if parseErr != nil || parsed < 0 {
		return nil, ErrMaxAgeInvalid
	}
	return &parsed, nil
}

// dedupePreserve returns a copy of in with duplicate elements removed,
// preserving the first occurrence's position. It is the order-stable
// equivalent of slices.Compact for an unsorted input.
func dedupePreserve(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// splitPrompt splits the prompt parameter on a single ASCII space, matching
// the OIDC Core §3.1.2.1 grammar exactly. It is intentionally NOT
// [strings.Fields]: tabs and newlines in prompt are illegal under the
// spec, and collapsing them silently would mask malformed clients.
func splitPrompt(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, " ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
