package authorize

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

	// Resource is the RFC 8707 resource indicator. Empty means the
	// request omitted the parameter.
	Resource string

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

	// RequestURI is the raw "request_uri" parameter. The library admits
	// exactly the RFC 9126 §2.2 PAR form
	// (urn:ietf:params:oauth:request_uri:*) on the wire; [ParseValues]
	// rejects every other shape with [ErrInvalidRequestURI] before
	// constructing the [Request] so the field, when populated, is
	// always a syntactically-valid PAR URN. The non-PAR JAR-by-URI form
	// described in RFC 9101 §5.2.2 is intentionally not supported — the
	// OP-side fetcher RFC 9101 §10.2 mandates (https-only, size cap,
	// TTL, content-type, SSRF deny-list) is not implemented, and FAPI
	// 2.0 mandates PAR anyway.
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
