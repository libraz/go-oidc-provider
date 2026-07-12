package authorize

import (
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

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
	if err := req.validateResource(client); err != nil {
		return err
	}
	if err := req.validateNonce(policy.NonceRequired); err != nil {
		return err
	}
	if err := req.validatePKCE(policy.PKCERequired || clientRequiresPKCE(client)); err != nil {
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
	if client == nil || !redirectURIMatches(client, req.RedirectURI) {
		return ErrRedirectURIInvalid
	}
	return nil
}

func redirectURIMatches(client *store.Client, requested string) bool {
	for _, candidate := range client.RedirectURIs {
		if LoopbackURIMatches(client, candidate, requested) {
			return true
		}
	}
	return false
}

// LoopbackURIMatches reports whether requested matches the registered
// candidate for client, honouring the RFC 8252 §7.3 loopback any-port
// allowance for native / public clients (a native app registers
// http://127.0.0.1/cb but binds an ephemeral port at runtime). It is the
// shared primitive behind both the redirect_uri check here and the
// end_session post_logout_redirect_uri check in [internal/endsession], so
// the two surfaces treat native loopback callbacks identically instead of
// the logout path enforcing a stricter exact-match than /authorize.
func LoopbackURIMatches(client *store.Client, registered, requested string) bool {
	return registered == requested ||
		(clientAllowsLoopbackWildcard(client) && loopbackRedirectMatchesAnyPort(registered, requested))
}

func clientAllowsLoopbackWildcard(client *store.Client) bool {
	if client == nil {
		return false
	}
	return client.PublicClient || strings.EqualFold(client.ApplicationType, "native")
}

func loopbackRedirectMatchesAnyPort(registered, requested string) bool {
	regURL, err := url.Parse(registered)
	if err != nil {
		return false
	}
	reqURL, err := url.Parse(requested)
	if err != nil {
		return false
	}
	if regURL.Scheme != "http" || reqURL.Scheme != "http" {
		return false
	}
	if regURL.User.String() != reqURL.User.String() {
		return false
	}
	if regURL.Hostname() != reqURL.Hostname() {
		return false
	}
	if !isWildcardLoopbackHost(regURL.Hostname()) {
		return false
	}
	if regURL.Path != reqURL.Path ||
		regURL.RawPath != reqURL.RawPath ||
		regURL.RawQuery != reqURL.RawQuery ||
		regURL.Fragment != reqURL.Fragment {
		return false
	}
	return true
}

// isWildcardLoopbackHost reports whether host is one of the loopback
// shapes the registration endpoint admits for native clients (RFC
// 8252 §7.3 / OIDC Reg §2): the IP literals 127.0.0.1 and [::1], and
// the textual "localhost" alias. The DCR validator
// (internal/registrationendpoint/metadata_schemes.go) accepts all
// three for native clients; the authorize-side wildcard MUST mirror
// that set so a native app that registers http://localhost:0/cb can
// successfully call back on its ephemeral port. Restricting the
// wildcard to the IP literals previously broke the typical native
// flow (registration accepted localhost, authorize rejected it).
func isWildcardLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr == netip.MustParseAddr("127.0.0.1") || addr == netip.MustParseAddr("::1")
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
	if !openIDOptional && !oidcscope.ContainsOpenID(req.Scope) {
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

// validateResource enforces RFC 8707 §2 (the value MUST be an absolute
// URI without a fragment) plus the OP-side allowlist. The check
// delegates parsing / canonicalisation to
// [resourceindicator.Canonicalize] and REPLACES the request's Resource
// field with the canonical form so downstream code paths (the
// persisted [store.Grant], the access-token aud claim, the
// per-audience format selector consulted at /token) see the same bytes
// regardless of the wire-side casing or trailing slash. The allowlist
// match also goes through the shared helper
// ([resourceindicator.Contains]) so a registration that pre-dates the
// canonicalisation policy still matches a canonical request.
func (req *Request) validateResource(client *store.Client) error {
	if req.Resource == "" {
		return nil
	}
	canonical, err := resourceindicator.Canonicalize(req.Resource)
	if err != nil {
		return ErrResourceInvalid
	}
	if client == nil || !resourceindicator.Contains(client.Resources, canonical) {
		return ErrResourceNotAllowed
	}
	req.Resource = canonical
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

// clientRequiresPKCE reports whether the client type mandates PKCE
// regardless of the OP-wide [Policy.PKCERequired] flag. Public clients —
// including native apps per RFC 8252 §8.1 and the OAuth 2.1 draft §7.6 —
// MUST use PKCE on the authorization-code flow: they cannot authenticate
// at the token endpoint, so PKCE is the only defence against the
// authorization-code interception attack (a stolen code is unusable
// without the verifier). Confidential clients authenticate with client
// credentials and remain governed by [Policy.PKCERequired] alone.
func clientRequiresPKCE(client *store.Client) bool {
	if client == nil {
		return false
	}
	return client.PublicClient || strings.EqualFold(client.ApplicationType, "native")
}

// validatePKCE enforces the OP's PKCE policy and delegates challenge
// format checks to [pkce.ValidateChallenge]. When required is true,
// every request MUST carry a code_challenge (FAPI 2.0 / OAuth 2.1
// posture, or a public / native client per [clientRequiresPKCE]). When
// required is false, an absent challenge falls through silently and the
// PKCE flow is opted out for this request; a present challenge is still
// format-validated so a half-supplied pair (challenge but no method, or
// vice versa) produces a clear error rather than silent acceptance.
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
