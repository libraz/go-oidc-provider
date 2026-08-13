package authorizeendpoint

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxJARRequestURIBody caps the body size a JAR request_uri lookup may
// retrieve. The signed JWT is small in practice (a few KiB); 64 KiB
// matches the form-body cap so an attacker cannot push the OP into a
// large allocation through this side channel.
const maxJARRequestURIBody = int64(64 * 1024)

// jarRequestURITimeout caps the HTTP fetch for a JAR request_uri. The
// budget mirrors the JWKS fetcher so a malicious upstream cannot stall
// the request thread.
const jarRequestURITimeout = 5 * time.Second

// resolveJARRequestIfNeeded inspects the wire values for a JAR-style
// "request" or "request_uri" parameter, fetches / verifies the request
// object, merges its claims onto the wire values, and returns the
// merged [url.Values] (post-merge) for the authorize parser to consume.
//
// Return semantics:
//
//   - (nil, false, false): no JAR parameter present; caller proceeds.
//   - (mergedValues, true, false): merge succeeded; caller re-parses.
//   - (nil, true, true): function wrote the response; caller stops.
//
// The function leaves PAR-style "request_uri" values
// (urn:ietf:params:oauth:request_uri:...) untouched: those go through
// the existing PAR consumption path.
//
// Every rejection here is pre-redirect-trust, so it renders through
// [renderJARError] rather than redirecting. That helper negotiates the
// same way the rest of the /authorize failure paths do: the embedder's
// [interaction.Driver] owns the surface a browser sees. Under a profile
// that mandates signed requests every /authorize call is a JAR call, so
// this is the error path the deployment's users actually meet, and
// answering it with a raw JSON body is a visible regression from what
// the same failure produces one gate later.
func resolveJARRequestIfNeeded(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	clientID string,
	values url.Values,
) (url.Values, bool, bool) {
	requestObject := values.Get("request")
	requestURI := values.Get("request_uri")
	if requestObject == "" && requestURI == "" {
		return nil, false, false
	}
	ctx := r.Context()
	// The wire "state" has not been through the parser yet (a repeated
	// parameter is faulted later), so read the first occurrence only.
	// It is echoed into the rendered page, never into a redirect: the
	// driver escapes it, and no redirect target is trusted at this
	// stage.
	state := values.Get("state")
	if requestObject != "" && requestURI != "" {
		renderJARError(w, r, deps, errInvalidRequest,
			"request and request_uri are mutually exclusive", state)
		return nil, true, true
	}
	// PAR's request_uri shape is handled by [resolvePARIfNeeded]; defer
	// to it without disturbing the wire values. The classification uses
	// the shared predicate so this branch and the PAR consumer agree on
	// what a PAR URN is — a value only one of them recognises would fall
	// through to a fetcher the client never asked for.
	if requestURI != "" && authorize.HasPARRequestURIPrefix(requestURI) {
		return nil, false, false
	}
	if deps.JAR == nil {
		renderJARError(w, r, deps, errInvalidRequest,
			"request and request_uri are not supported by this OP", state)
		return nil, true, true
	}
	if clientID == "" {
		renderJARError(w, r, deps, errInvalidRequest, "client_id is required", state)
		return nil, true, true
	}
	client, err := deps.Clients.GetClient(ctx, clientID)
	if err != nil || client == nil {
		// A nil client alongside a nil error violates the store contract;
		// a client the backend cannot produce is not a registered one.
		renderJARError(w, r, deps, errInvalidRequest, "client_id is not registered", state)
		return nil, true, true
	}
	raw := requestObject
	if requestURI != "" {
		fetched, ok := fetchJARRequestURI(w, r, deps, client, requestURI, state)
		if !ok {
			return nil, true, true
		}
		raw = fetched
	}
	// Verify consumes the request object's "jti", so the object is
	// single-use from here. That is the same rule the pushed path
	// applies — /par verifies (and consumes) the object once at push
	// time — and the visible difference between the two is a property of
	// the mechanisms rather than a policy split: a pushed request is
	// thereafter referenced by a request_uri, which /authorize resolves
	// with a lookup and spends only at code emission, whereas a direct
	// request object IS the /authorize parameter and is therefore
	// re-presented by a reload. Relaxing it here would make the object
	// replayable at /authorize with no counterpart at /par.
	obj, err := deps.JAR.Verify(ctx, raw, clientID, client)
	if err != nil {
		writeJAREnvelopeError(w, r, deps, err, state)
		return nil, true, true
	}
	merged, err := jar.Merge(values, obj)
	if err != nil {
		writeJAREnvelopeError(w, r, deps, err, state)
		return nil, true, true
	}
	return merged, true, false
}

// renderJARError renders a JAR-stage rejection. Every such rejection is
// pre-redirect-trust — the request object is what would have carried the
// redirect_uri, and it has just been refused — so the response is an
// inline page (or the JSON envelope for a non-browser caller), never a
// redirect. state is the RP-supplied value echoed onto the page; the
// driver is responsible for escaping it.
func renderJARError(w http.ResponseWriter, r *http.Request, deps resolved, code, description, state string) {
	renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, code, description, state)
}

// fetchJARRequestURI retrieves the signed request object referenced by
// uri. The fetch enforces:
//
//   - Membership in the client's preregistered RequestURIs allowlist
//     (RFC 9101 §5.2.2 / FAPI 2.0 Message Signing). The OP is strict:
//     no preregistration means the URI is not honoured.
//   - The same SSRF deny-list (URL-time + dial-time) and body cap that
//     back the JWKS / sector_identifier_uri fetchers. The fetch runs
//     through the shared [securefetch] envelope — the same one those
//     use — so a DNS-rebinding peer cannot pivot between the URL gate
//     and the dial; cloud-metadata IPs remain rejected even when
//     AllowPrivate is enabled. The envelope is built once per handler
//     and held on [resolved], so repeat lookups reuse its connection
//     pool rather than handshaking afresh.
//   - HTTPS-only by default. http:// is admitted only when
//     [op.WithAllowPrivateNetworkJAR] is set so loopback fixtures keep
//     working without weakening the production posture.
//   - No redirects. RFC 9101 leaves the matter open, but a 30x is the
//     easiest way an attacker upstream of the RP could pivot the OP
//     onto a different host whose SSRF disposition was not validated.
//   - Content-Type whitelist. The body is permitted to declare
//     application/oauth-authz-req+jwt (RFC 9101 §10.6),
//     application/jwt, text/plain, or be absent (some IdPs publish
//     bare JWS bodies without a Content-Type); anything else is
//     rejected so a misrouted captive-portal HTML / octet-stream
//     cannot be parsed as a JWS by accident.
//
// The function writes the response envelope on every failure path; the
// boolean is false in that case and true on success.
func fetchJARRequestURI(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	client *store.Client,
	uri string,
	state string,
) (string, bool) {
	ctx := r.Context()
	if !isPreregisteredRequestURI(client, uri) {
		renderJARError(w, r, deps, errInvalidRequestURI,
			"request_uri is not preregistered for this client", state)
		return "", false
	}
	// NewRequest runs the URL-time SSRF gate; the dial-time gate rides on
	// the shared client's transport.
	fetchReq, err := deps.jarFetch.NewRequest(ctx, http.MethodGet, uri, nil)
	if err != nil {
		renderJARError(w, r, deps, errInvalidRequestURI,
			classifyJARRequestURINewRequestError(err), state)
		return "", false
	}
	fetchReq.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt, text/plain;q=0.5")
	body, resp, err := deps.jarFetch.Do(fetchReq) //nolint:bodyclose // securefetch.Do drains and closes the body internally.
	if err != nil {
		renderJARError(w, r, deps, errInvalidRequestURI,
			classifyJARRequestURIFetchError(err, resp), state)
		return "", false
	}
	// The media-type gate stays here rather than in the policy's
	// AcceptContentTypes: an absent Content-Type is admitted (RFC 9101
	// §10.6 is a SHOULD), and the envelope's allow-list has no spelling
	// for "absent". The body it was read alongside is already bounded by
	// the policy's cap, so a wrong media type costs a capped read and
	// nothing more.
	if !isJARRequestObjectContentType(resp.Header.Get("Content-Type")) {
		renderJARError(w, r, deps, errInvalidRequestURI,
			fmt.Sprintf("request_uri content-type %q is not a JWS media type", resp.Header.Get("Content-Type")), state)
		return "", false
	}
	return strings.TrimSpace(string(body)), true
}

// jarRequestURIPolicy returns the [securefetch.Policy] the JAR
// request_uri fetcher runs under. The policy is the single source of
// truth for the URL-time gate, the dial-time gate, and the response-side
// status / body-cap checks, so none of them can drift apart.
//
// HTTPS-only is the production posture; AllowPrivate widens the scheme
// allow-list to include http so loopback fixtures keep working. Cloud
// metadata IPs remain rejected unconditionally — that gate is enforced
// by the netsec URL check and the dial-control hook regardless of
// AllowPrivate.
//
// AcceptContentTypes is deliberately empty: the media-type rule this
// endpoint needs admits an absent header, which the envelope's allow-list
// cannot express, so [isJARRequestObjectContentType] applies it at the
// call site instead.
func jarRequestURIPolicy(allowPrivate bool) securefetch.Policy {
	schemes := []string{"https"}
	if allowPrivate {
		schemes = []string{"http", "https"}
	}
	return securefetch.Policy{
		AllowPrivateNetwork: allowPrivate,
		AllowedSchemes:      schemes,
		Timeout:             jarRequestURITimeout,
		MaxBodyBytes:        maxJARRequestURIBody,
		// MaxRedirects=0 (the default) refuses every 30x; the redirect
		// surfaces as a non-2xx status the fetch-error classifier
		// reports separately.
	}
}

// classifyJARRequestURINewRequestError maps a request-construction
// failure onto the wire description. An empty URL is a malformed
// request_uri; everything else reaching here came from the URL-time SSRF
// gate.
func classifyJARRequestURINewRequestError(err error) string {
	if errors.Is(err, securefetch.ErrEmptyURL) {
		return "request_uri is malformed"
	}
	return classifyJARRequestURISSRFError(err)
}

// classifyJARRequestURIFetchError maps a [securefetch.Client.Do] failure
// onto the wire description. resp is nil when the round trip never
// produced one.
//
// The status branch splits a refused redirect from any other non-2xx:
// MaxRedirects=0 collapses every 30x onto http.ErrUseLastResponse, so a
// redirect arrives here as a 3xx status rather than a followed hop, and
// the operator is told which of the two happened.
func classifyJARRequestURIFetchError(err error, resp *http.Response) string {
	switch {
	case errors.Is(err, securefetch.ErrUnexpectedStatus):
		if resp == nil {
			return "request_uri fetch failed"
		}
		if resp.StatusCode/100 == 3 {
			return "request_uri must not redirect"
		}
		return fmt.Sprintf("request_uri responded with status %d", resp.StatusCode)
	case errors.Is(err, securefetch.ErrBodyTooLarge):
		return "request_uri body exceeds size cap"
	case errors.Is(err, securefetch.ErrReadBody):
		return "request_uri body read failed"
	}
	return classifyJARRequestURIDoError(err)
}

// isJARRequestObjectContentType reports whether ct is a recognised
// JAR request-object media type. RFC 9101 §10.6 SHOULDs
// application/oauth-authz-req+jwt; in practice some IdPs emit
// application/jwt or text/plain for bare JWS bodies. An absent
// Content-Type is also accepted because the same RFC clause is a
// SHOULD, not a MUST. Anything else (text/html captive portal,
// application/octet-stream from a misrouted CDN) is rejected so a
// non-JWS body cannot be fed into the verifier.
func isJARRequestObjectContentType(ct string) bool {
	if ct == "" {
		return true
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	switch ct {
	case "application/oauth-authz-req+jwt",
		"application/jwt",
		"text/plain":
		return true
	}
	return false
}

// classifyJARRequestURISSRFError maps a [netsec] sentinel raised by
// the URL-time gate onto a short operator-friendly description. The
// description is what the wire envelope surfaces; we never echo the
// wrapped error verbatim to the client because the wrap may carry the
// internal hostname.
func classifyJARRequestURISSRFError(err error) string {
	switch {
	case errors.Is(err, netsec.ErrCloudMetadataBlocked):
		return "request_uri target is blocked by the cloud-metadata gate"
	case errors.Is(err, netsec.ErrPrivateNetworkBlocked):
		return "request_uri target is blocked by the private-network gate"
	case errors.Is(err, netsec.ErrSchemeNotAllowed):
		return "request_uri scheme is not allowed"
	case errors.Is(err, netsec.ErrMissingHost):
		return "request_uri is missing host"
	}
	return "request_uri is not safe to fetch"
}

// classifyJARRequestURIDoError maps the error [http.Client.Do] returns
// from the wrapped netsec client into one of the wire descriptions the
// fetcher emits. SSRF rejections raised from the dial-time hook or
// the [urlGateRoundTripper] arrive wrapped in a transport error; we
// recognise them so the operator-facing wording matches the URL-time
// rejection above instead of collapsing onto "fetch failed".
func classifyJARRequestURIDoError(err error) string {
	switch {
	case errors.Is(err, netsec.ErrCloudMetadataBlocked),
		errors.Is(err, netsec.ErrPrivateNetworkBlocked):
		return "request_uri target resolves to a blocked network"
	case errors.Is(err, netsec.ErrRedirectBlocked):
		return "request_uri must not redirect"
	}
	return "request_uri fetch failed"
}

// isPreregisteredRequestURI reports whether uri appears verbatim in
// the client's RequestURIs allowlist. RFC 9101 §5.2.2 leaves matching
// semantics to the OP; we apply byte-equal comparison so an attacker
// cannot trick the verifier with prefix tricks (e.g. a registered
// "https://rp.example.com/req" matching "https://rp.example.com/req-evil").
func isPreregisteredRequestURI(c *store.Client, uri string) bool {
	for _, allowed := range c.RequestURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// writeJAREnvelopeError translates a [jar] sentinel into the OAuth
// JSON envelope. The taxonomy mirrors RFC 9101 §6.1's error catalogue:
// alg / signature / claim failures map to invalid_request_object;
// JWKS-resolution failures map to the same code (the OP cannot
// distinguish a bad request from a misconfigured client without
// helping an attacker enumerate clients).
//
// The description is [jar.Description]'s, shared with /par and the
// back-channel authentication endpoint. Only the wire code is decided
// here: the endpoints legitimately differ on that and on nothing else.
func writeJAREnvelopeError(w http.ResponseWriter, r *http.Request, deps resolved, err error, state string) {
	switch {
	case errors.Is(err, jar.ErrClientIDMismatch):
		renderJARError(w, r, deps, errInvalidRequest, jar.Description(err), state)
	default:
		renderJARError(w, r, deps, errInvalidRequestObject, jar.Description(err), state)
	}
}
