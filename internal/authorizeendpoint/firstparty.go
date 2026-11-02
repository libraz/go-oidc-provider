package authorizeendpoint

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// firstPartyShouldSkipConsent reports whether the dispatcher's pending
// outcome (a consent prompt or a prompt=none consent_required error)
// should instead be auto-resolved through the first-party skip path
// configured by [op.WithFirstPartyClients]. The four preconditions:
//
//  1. The client_id appears in [Deps.FirstPartyClients] and the record
//     resolved for this request is static, admin or legacy-empty
//     sourced ([firstPartySource]); a dynamic or metadata-document
//     client under a listed id never qualifies.
//  2. The pending decision would otherwise prompt the user for
//     consent — either an interactive consent prompt or the
//     prompt=none consent_required error. Login / chooser / silent-
//     mint outcomes pass through unchanged.
//  3. An active session exists. With no session there is no subject
//     to bind the grant to; the first-party skip never invents one.
//  4. The request did NOT carry prompt=consent. An RP that explicitly
//     asks for re-consent always gets the prompt; the first-party
//     flag is the OP's posture, not the RP's override.
//
// What the skip actually elides is the scope screen: the ceremony
// presents scopes and nothing else. RFC 9396 authorization_details are
// carried by the request and land on the grant on either path, so
// enabling the skip does not remove an element-level display that the
// prompting path would otherwise have shown (see
// [authorizationDetailsCovered]).
func firstPartyShouldSkipConsent(
	r *http.Request,
	hint authorizeHint,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	deps resolved,
) bool {
	if active == nil || client == nil {
		return false
	}
	if !deps.isFirstPartyClient(client.ID) || !firstPartySource(client.Source) {
		return false
	}
	if !firstPartyAutoGrantRequestTrusted(r, req.RedirectURI) {
		return false
	}
	if slices.Contains(req.Prompt, interaction.PromptConsent) {
		return false
	}
	if oidcscope.ContainsOfflineAccess(req.Scope) {
		return false
	}
	if req.GrantManagementAction != "" {
		// A Grant Management mutation always gets an explicit consent
		// ceremony; the first-party auto-grant never silently
		// creates / replaces / merges a managed grant.
		return false
	}
	if len(req.AuthorizationDetails) > 0 {
		// RFC 9396 authorization_details are rich, consent-bearing
		// authorizations (e.g. a payment_initiation amount/payee). The
		// first-party auto-grant never silently grants them; the user
		// always sees an explicit consent ceremony.
		return false
	}
	switch hint.decision {
	case decisionInteract:
		return hint.prompt == interaction.PromptConsent
	case decisionConsentRequired:
		return true
	default:
		return false
	}
}

// firstPartySource reports whether a client of source may receive the
// first-party skip: one the operator vetted (static, admin, or the
// legacy empty value read as static), never a self-registered or
// metadata-document client.
func firstPartySource(source store.ClientSource) bool {
	switch source {
	case "", store.ClientSourceStatic, store.ClientSourceAdmin:
		return true
	default:
		return false
	}
}

func firstPartyAutoGrantRequestTrusted(r *http.Request, redirectURI string) bool {
	if r == nil {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "same-site":
		return firstPartySameSiteOriginMatchesRedirect(r, redirectURI)
	default:
		return false
	}
}

func firstPartySameSiteOriginMatchesRedirect(r *http.Request, redirectURI string) bool {
	redirectOrigin, ok := originFromRawURL(redirectURI)
	if !ok {
		return false
	}
	for _, raw := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		if raw == "" {
			continue
		}
		if origin, ok := originFromRawURL(raw); ok && origin == redirectOrigin {
			return true
		}
	}
	return false
}

func originFromRawURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

// applyFirstPartySkip plans the grant the dispatcher would otherwise have
// asked the user to confirm and rewrites the hint so the switch in
// [dispatchAuthorize] mints a code silently. The grant is deliberately not
// written here: mintAndRedirect commits it together with PAR consumption and
// authorization-code persistence.
//
// The grant subject is the raw OP-internal identifier the session
// carries, mirroring what interaction.go persists at the end of an
// interactive consent ceremony and matching [store.Grant.Subject]'s
// contract. Projection through [op.SubjectGenerator] happens per client
// at egress — id_token, JWT access token, userinfo, introspection —
// never at persistence, so that one grant serves every client the
// subject authorizes and a salt rotation changes what is emitted
// without rewriting stored rows. Storing a projected value here would
// be projected a second time downstream and would also break the
// (Subject, ClientID) grant lookup, which is keyed on the raw subject.
// The authorize endpoint holds no projector, which is what keeps the
// mistake from being reachable by accident.
//
// AuthTime / ACR / AMR are left for [resolveSilentGrant], which stamps
// the context [reportAuthContext] resolved for this request, the same
// one it stamps on a cached grant.
func applyFirstPartySkip(
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
) authorizeHint {
	planned := &grantUpsert{
		Subject:              active.Session.Subject,
		ClientID:             client.ID,
		Scope:                append([]string(nil), req.Scope...),
		Claims:               req.Claims,
		AuthorizationDetails: req.AuthorizationDetails,
		Now:                  deps.now(),
	}
	return authorizeHint{decision: decisionMint, autoGrant: planned}
}
