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
func resolvePARIfNeeded(
	ctx context.Context,
	w http.ResponseWriter,
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
		renderAuthorizeError(w, errPARDisabled)
		return nil, true
	}
	rec, err := deps.PARs.Consume(ctx, uri)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrAlreadyConsumed) {
			renderAuthorizeError(w, authorize.ErrInvalidRequestURI)
			return nil, true
		}
		renderJSONError(w, http.StatusInternalServerError, errServerError, "PAR backend unavailable")
		return nil, true
	}
	if queryClientID != "" && rec.ClientID != queryClientID {
		renderAuthorizeError(w, errPARClientMismatch)
		return nil, true
	}
	var snap authorize.RequestSnapshot
	if err := json.Unmarshal(rec.RawParams, &snap); err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "PAR record could not be decoded")
		return nil, true
	}
	return snap.ToRequest(), false
}

// renderAuthorizeError writes the JSON envelope shape the authorize
// endpoint owes pre-redirect-trust failures. It exists so the PAR
// consumption helper does not need to discriminate redirect-safety: every
// PAR-resolution failure is by definition pre-redirect-trust.
func renderAuthorizeError(w http.ResponseWriter, ae *authorize.Error) {
	renderJSONError(w, http.StatusBadRequest, ae.Code, ae.Description)
}
