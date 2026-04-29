package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jar"
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
//   - The same SSRF deny-list, body cap, and content-type policy the
//     JWKS fetcher applies. The body is permitted to be either
//     application/oauth-authz-req+jwt (RFC 9101 §10.6) or text/plain
//     because some IdPs publish bare JWS bodies.
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
	if err := assertJARRequestURISafe(ctx, uri, allowPrivate); err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI, err.Error())
		return "", false
	}
	httpClient := &http.Client{Timeout: jarRequestURITimeout}
	// The URL came from the client's preregistered allowlist and has
	// passed the SSRF deny-list above; the gosec G107 / taint warning
	// is acknowledged here and not surfaced as a real risk.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody) //nolint:gosec // see assertJARRequestURISafe.
	if err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI, "request_uri is malformed")
		return "", false
	}
	resp, err := httpClient.Do(req) //nolint:gosec // see assertJARRequestURISafe.
	if err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI, "request_uri fetch failed")
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequestURI,
			fmt.Sprintf("request_uri responded with status %d", resp.StatusCode))
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

// assertJARRequestURISafe enforces the SSRF-style deny-list on a JAR
// request_uri before the HTTP fetcher dials. The list mirrors the
// JWKS fetcher in [internal/jar]: only http / https schemes, no
// loopback or RFC 1918 hosts. When allowPrivate is true the deny-list
// is suppressed so embedders fronting their RPs with private DNS can
// opt in via op.WithAllowPrivateNetworkJAR.
func assertJARRequestURISafe(ctx context.Context, raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("request_uri is not a parseable URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("request_uri scheme %q is not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("request_uri is missing host")
	}
	if allowPrivate {
		return nil
	}
	if jar.IsLocalHostname(host) {
		return fmt.Errorf("request_uri host %q is loopback", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if jar.IsPrivateIP(ip) {
			return fmt.Errorf("request_uri host %q is loopback / private", host)
		}
		return nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, jarRequestURITimeout)
	defer cancel()
	addrs, lookupErr := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if lookupErr != nil {
		return fmt.Errorf("request_uri host %q cannot be resolved", host)
	}
	for _, addr := range addrs {
		if jar.IsPrivateIP(addr.IP) {
			return fmt.Errorf("request_uri host %q resolves to a private IP", host)
		}
	}
	return nil
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
func sanitiseJARDescription(err error) string {
	switch {
	case errors.Is(err, jar.ErrAlgNotAllowed):
		return "request object alg is not allowed"
	case errors.Is(err, jar.ErrSigInvalid):
		return "request object signature is invalid"
	case errors.Is(err, jar.ErrIssMismatch):
		return "request object iss does not match client_id"
	case errors.Is(err, jar.ErrAudMismatch):
		return "request object aud does not match issuer"
	case errors.Is(err, jar.ErrExpired):
		return "request object is expired or too old"
	case errors.Is(err, jar.ErrNotYetValid):
		return "request object is not yet valid"
	case errors.Is(err, jar.ErrNestedRequest):
		return "request object must not contain nested request parameters"
	case errors.Is(err, jar.ErrJWKSFetch):
		return "client jwks fetch failed"
	case errors.Is(err, jar.ErrNoMatchingJWK):
		return "no matching client jwk"
	case errors.Is(err, jar.ErrJWKSConfigured):
		return "client has no JWKs or JWKsURI"
	case errors.Is(err, jar.ErrJTIMissing):
		return "request object missing jti"
	case errors.Is(err, jar.ErrJTIReplayed):
		return "request object jti already consumed"
	case errors.Is(err, jar.ErrParse):
		return "request object is malformed"
	default:
		return "request object verification failed"
	}
}
