package authorizeendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
)

// parRequestURIPrefix is the URN namespace RFC 9126 §2.2 reserves for PAR
// request_uri values. The /par endpoint emits this prefix verbatim; the
// authorize endpoint matches on it to distinguish PAR URIs from the
// (out-of-scope) JAR request_uri parameter.
const parRequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// errPARDisabled is the wire response when the OP receives a request_uri
// while [Deps.PARs] is nil. The library uses invalid_request rather than
// invalid_request_uri because the latter implies "we recognise PAR, your
// URI is bad" and would mislead clients about feature availability.
var errPARDisabled = &authorize.Error{
	Code:        "invalid_request",
	Description: "request_uri is not supported by this OP",
}

// errPARClientMismatch is the wire response when the request_uri redeems
// cleanly but the request's client_id disagrees with the PAR record's.
// Per RFC 9126 §2.3 this is invalid_request, not invalid_request_uri.
var errPARClientMismatch = &authorize.Error{
	Code:        "invalid_request",
	Description: "request_uri client_id does not match request client_id",
}

// errPARRequired is the wire response when the active profile (FAPI 2.0
// Baseline / Message Signing) mandates PAR but the /authorize request
// arrived without a urn:ietf:params:oauth:request_uri: prefixed
// request_uri. Per RFC 9126 §2.3 / FAPI 2.0 §5.3.1 this is
// invalid_request, not invalid_request_uri (the latter implies a PAR
// URI was offered and rejected).
var errPARRequired = &authorize.Error{
	Code:        "invalid_request",
	Description: "this OP requires authorization requests to be pushed via the PAR endpoint",
}

// resolvePARIfNeeded inspects the incoming /authorize values for a
// request_uri parameter and, when present, replaces the parsed request
// with the snapshot recovered from the persisted PAR record. The function
// is a no-op when no request_uri is present.
//
// The returned bool reports whether the call wrote a response: true means
// "stop, response written" and false means "continue with req". On the
// PAR-success path the returned *authorize.Request supersedes the caller's
// query-derived request; when no request_uri is present both returns are
// the zero value (nil, false) and the caller proceeds with the original
// request.
//
// Per RFC 9126 §2.3, when request_uri is present the OP MUST ignore every
// other authorization-request parameter except client_id; this function
// implements that rule by returning the snapshot's parameters verbatim.
//
// Find (not Consume) is used here so a /authorize visit that parks the
// user at the login screen does not invalidate the request_uri: a second
// visit before authentication completes (e.g. the user opening the link
// twice, or a multi-step interaction redirect) MUST still resolve. The
// one-time-use guarantee RFC 9126 §2.2 mandates is enforced when the
// authorization code is issued — see consumePARIfNeeded.
func resolvePARIfNeeded(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	queryClientID string,
	values url.Values,
) (*authorize.Request, bool) {
	uri := values.Get("request_uri")
	if uri == "" {
		return nil, false
	}
	if !strings.HasPrefix(uri, parRequestURIPrefix) {
		// Not a PAR URN: leave the value intact so the downstream JAR
		// consumer can pick it up (a non-PAR request_uri is a JAR
		// reference per RFC 9101 §5.2.2). When JAR is also disabled,
		// the JAR consumer surfaces invalid_request itself.
		return nil, false
	}
	if deps.PARs == nil {
		renderAuthorizeError(w, r, deps, errPARDisabled)
		return nil, true
	}
	rec, err := deps.PARs.Find(ctx, uri)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			renderAuthorizeError(w, r, deps, authorize.ErrInvalidRequestURI)
			return nil, true
		}
		renderBrowserError(w, r, deps.Driver, http.StatusInternalServerError, errServerError, "PAR backend unavailable", "")
		return nil, true
	}
	if rec.ConsumedAt != nil {
		// A request_uri that has already issued an authorization code
		// is single-use per RFC 9126 §2.2; reject the replay.
		renderAuthorizeError(w, r, deps, authorize.ErrInvalidRequestURI)
		return nil, true
	}
	if queryClientID != "" && rec.ClientID != queryClientID {
		renderAuthorizeError(w, r, deps, errPARClientMismatch)
		return nil, true
	}
	var snap authorize.RequestSnapshot
	if err := json.Unmarshal(rec.RawParams, &snap); err != nil {
		renderBrowserError(w, r, deps.Driver, http.StatusInternalServerError, errServerError, "PAR record could not be decoded", "")
		return nil, true
	}
	out := snap.ToRequest()
	out.PARRequestURI = uri
	return out, false
}

// consumePARIfNeeded marks the PAR record bound to req as one-time-used.
// The function is a no-op when the request did not originate from /par
// (req.PARRequestURI == "") or when the PAR substore is not wired.
//
// Returns nil on success, [store.ErrAlreadyConsumed] if a parallel code
// emission already redeemed the URI, and any other error verbatim from
// the store. Callers MUST invoke this immediately before persisting the
// authorization code so the consume happens atomically with the code's
// existence.
func consumePARIfNeeded(ctx context.Context, deps resolved, req *authorize.Request) error {
	if req == nil || req.PARRequestURI == "" || deps.PARs == nil {
		return nil
	}
	_, err := deps.PARs.Consume(ctx, req.PARRequestURI)
	return err
}

// renderAuthorizeError writes the pre-redirect-trust failure envelope
// for the PAR consumption helper. Every PAR-resolution failure is by
// definition pre-redirect-trust, so the helper picks HTML or JSON via
// renderBrowserError rather than hard-coding the shape.
func renderAuthorizeError(w http.ResponseWriter, r *http.Request, deps resolved, ae *authorize.Error) {
	renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, ae.Code, ae.Description, "")
}
