// Package httpx provides the HTTP boundary helpers shared by every OP
// endpoint: bounded body decoders, OAuth-style error / JSON writers, and
// content-negotiation primitives. It deliberately knows nothing about the
// OIDC protocol; downstream packages translate their domain errors into the
// status/code/description triples this package emits.
package httpx

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// JSONContentType is the value the package stamps on every successful JSON
// response. RFC 8259 fixes JSON's MIME type so callers should not need to
// override it; the constant is exported for tests that assert on it.
const JSONContentType = "application/json; charset=utf-8"

// noStoreCacheControl is the value applied to every response written via
// [WriteJSON].02-product-design.md §A.12.9, every dynamic
// authentication-flow response must instruct caches not to retain the body.
// Discovery / JWKS use a different (cacheable) profile applied by their own
// handlers.
const noStoreCacheControl = "no-store"

// WriteJSON marshals body and writes it as a JSON response with the supplied
// status. It also stamps Content-Type and Cache-Control: no-store so dynamic
// responses are never cached. If marshalling fails it writes a 500 with an
// opaque "server_error" body — the marshal error is otherwise unobservable
// and would result in the client seeing only a partial payload.
// WriteJSON returns the marshal/write error so the caller can record it in
// audit logs. The HTTP response is always finalised regardless of the
// returned error so callers must not write to the [http.ResponseWriter]
// after this call.
func WriteJSON(w http.ResponseWriter, status int, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		writeServerError(w)
		return err
	}
	h := w.Header()
	h.Set("Content-Type", JSONContentType)
	h.Set("Cache-Control", noStoreCacheControl)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(status)
	_, werr := w.Write(encoded)
	return werr
}

// writeServerError writes a minimal "server_error" JSON body. The function
// is intentionally separate from [WriteJSON] so it cannot recurse if the
// fallback body itself fails to marshal (it never does — it is a constant).
func writeServerError(w http.ResponseWriter) {
	const fallback = `{"error":"server_error"}`
	h := w.Header()
	h.Set("Content-Type", JSONContentType)
	h.Set("Cache-Control", noStoreCacheControl)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(fallback)))
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(fallback))
}
