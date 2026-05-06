package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/netsec"
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
func resolveJARRequestIfNeeded(
	ctx context.Context,
	w http.ResponseWriter,
	deps resolved,
	clientID string,
	values url.Values,
) (url.Values, bool, bool) {
	requestObject := values.Get("request")
	requestURI := values.Get("request_uri")
	if requestObject == "" && requestURI == "" {
		return nil, false, false
	}
	if requestObject != "" && requestURI != "" {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest,
			"request and request_uri are mutually exclusive")
		return nil, true, true
	}
	// PAR's request_uri shape is handled by [resolvePARIfNeeded]; defer
	// to it without disturbing the wire values.
	if requestURI != "" && strings.HasPrefix(requestURI, parRequestURIPrefix) {
		return nil, false, false
	}
	if deps.JAR == nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest,
			"request and request_uri are not supported by this OP")
		return nil, true, true
	}
	if clientID == "" {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "client_id is required")
		return nil, true, true
	}
	client, err := deps.Clients.GetClient(ctx, clientID)
	if err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "client_id is not registered")
		return nil, true, true
	}
	raw := requestObject
	if requestURI != "" {
		fetched, ok := fetchJARRequestURI(ctx, w, client, requestURI, deps.AllowPrivateNetworkJAR)
		if !ok {
			return nil, true, true
		}
		raw = fetched
	}
	obj, err := deps.JAR.Verify(ctx, raw, clientID, client)
	if err != nil {
		writeJAREnvelopeError(w, err)
		return nil, true, true
	}
	merged, err := jar.Merge(values, obj)
	if err != nil {
		writeJAREnvelopeError(w, err)
		return nil, true, true
	}
	return merged, true, false
}

// fetchJARRequestURI retrieves the signed request object referenced by
// uri. The fetch enforces:
//
//   - Membership in the client's preregistered RequestURIs allowlist
//     (RFC 9101 §5.2.2 / FAPI 2.0 Message Signing). The OP is strict:
//     no preregistration means the URI is not honoured.
//   - The same SSRF deny-list (URL-time + dial-time), body cap, and
//     content-type policy that backs the JWKS / sector_identifier_uri
//     fetchers. The implementation goes through [internal/netsec] so
//     a DNS-rebinding peer cannot pivot between the URL gate and the
//     dial; cloud-metadata IPs remain rejected even when AllowPrivate
//     is enabled.
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
	ctx context.Context,
	w http.ResponseWriter,
	client *store.Client,
	uri string,
	allowPrivate bool,
) (string, bool) {
	if !isPreregisteredRequestURI(client, uri) {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			"request_uri is not preregistered for this client")
		return "", false
	}
	netsecOpts := jarRequestURINetsecOptions(allowPrivate)
	if err := netsec.AssertSafeURL(ctx, uri, netsecOpts); err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			classifyJARRequestURISSRFError(err))
		return "", false
	}
	httpClient := netsec.NewHTTPClient(netsecOpts)
	// The URL came from the client's preregistered allowlist and has
	// passed both the URL-time SSRF gate above and the dial-time gate
	// installed by [netsec.NewHTTPClient]; the gosec G107/G704 SSRF
	// taint warning is acknowledged here as covered by the deny-list.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody) //nolint:gosec // see netsec gates above.
	if err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI, "request_uri is malformed")
		return "", false
	}
	req.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt, text/plain;q=0.5")
	resp, err := httpClient.Do(req) //nolint:gosec // see netsec gates above.
	if err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			classifyJARRequestURIDoError(err))
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	// MaxRedirects=0 in netsec.Options collapses every 30x onto
	// http.ErrUseLastResponse, so a redirect surfaces here as a non-2xx
	// status. We refuse the response rather than follow the location.
	if resp.StatusCode/100 == 3 {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			"request_uri must not redirect")
		return "", false
	}
	if resp.StatusCode/100 != 2 {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			fmt.Sprintf("request_uri responded with status %d", resp.StatusCode))
		return "", false
	}
	if !isJARRequestObjectContentType(resp.Header.Get("Content-Type")) {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			fmt.Sprintf("request_uri content-type %q is not a JWS media type", resp.Header.Get("Content-Type")))
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJARRequestURIBody+1))
	if err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI, "request_uri body read failed")
		return "", false
	}
	if int64(len(body)) > maxJARRequestURIBody {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			"request_uri body exceeds size cap")
		return "", false
	}
	return strings.TrimSpace(string(body)), true
}

// jarRequestURINetsecOptions returns the [netsec.Options] snapshot the
// JAR request_uri fetcher uses for the URL-time gate and the HTTP
// client. The function is the single source of truth so the URL gate
// and the dial gate cannot drift apart.
//
// HTTPS-only is the production posture; AllowPrivate widens the scheme
// allow-list to include http so loopback fixtures keep working. Cloud
// metadata IPs remain rejected unconditionally — that gate is enforced
// by [netsec.AssertSafeURLParsed] and the dial-control hook regardless
// of AllowPrivate.
func jarRequestURINetsecOptions(allowPrivate bool) netsec.Options {
	schemes := []string{"https"}
	if allowPrivate {
		schemes = []string{"http", "https"}
	}
	return netsec.Options{
		AllowPrivate:   allowPrivate,
		AllowedSchemes: schemes,
		Timeout:        jarRequestURITimeout,
		// MaxRedirects=0 (default) makes [netsec] refuse every 30x;
		// the Do call below surfaces the redirect as a non-2xx status.
	}
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
func writeJAREnvelopeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jar.ErrClientIDMismatch):
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "client_id mismatch in request object")
	default:
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestObject, sanitiseJARDescription(err))
	}
}

// sanitiseJARDescription returns a short operator-friendly description
// derived from err. We never echo the wrapped third-party error to the
// client; the description is one of a small closed set so log readers
// can correlate the wire response with the sentinel without a full
// stack trace.
//
// The mapping is split between a sentinel→string table (the bulk of
// the catalogue) and a literal switch for [jar.ErrParse], which is
// checked last because every other JAR sentinel may unwrap onto it
// via [fmt.Errorf]. Walking the table top-down would otherwise resolve
// every JAR error to "malformed" and hide the more specific cause.
//
//nolint:gochecknoglobals // immutable error-to-description catalogue.
var jarDescriptions = []struct {
	sentinel error
	desc     string
}{
	{jar.ErrAlgNotAllowed, "request object alg is not allowed"},
	{jar.ErrSigInvalid, "request object signature is invalid"},
	{jar.ErrIssMismatch, "request object iss does not match client_id"},
	{jar.ErrAudMismatch, "request object aud does not match issuer"},
	{jar.ErrExpired, "request object is expired or too old"},
	{jar.ErrNotYetValid, "request object is not yet valid"},
	{jar.ErrNestedRequest, "request object must not contain nested request parameters"},
	{jar.ErrJWKSFetch, "client jwks fetch failed"},
	{jar.ErrNoMatchingJWK, "no matching client jwk"},
	{jar.ErrJWKSConfigured, "client has no JWKs or JWKsURI"},
	{jar.ErrJTIMissing, "request object missing jti"},
	{jar.ErrJTIReplayed, "request object jti already consumed"},
	{jar.ErrEncryptionUnsupported, "encrypted request objects are not supported"},
	{jar.ErrEncryptionAlgNotAllowed, "request object encryption alg/enc is not allowed"},
	{jar.ErrDecryptFailed, "request object could not be decrypted"},
	{jar.ErrParse, "request object is malformed"},
}

func sanitiseJARDescription(err error) string {
	for _, entry := range jarDescriptions {
		if errors.Is(err, entry.sentinel) {
			return entry.desc
		}
	}
	return "request object verification failed"
}
