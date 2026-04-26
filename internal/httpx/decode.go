package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// MaxFormBytes caps the size of an application/x-www-form-urlencoded body
// the OP will read. The token endpoint and friends never receive payloads
// near this size; the cap exists to bound DoS exposure.
const MaxFormBytes = 64 * 1024 // 64 KiB

// MaxJSONBytes caps the size of a JSON request body. Interaction endpoints
// post small payloads (login form fields, consent decisions); 256 KiB is
// well above any legitimate use.
const MaxJSONBytes = 256 * 1024

// ErrBodyTooLarge is returned when a request body exceeds the configured
// limit. Callers should map it to HTTP 413.
var ErrBodyTooLarge = errors.New("httpx: request body exceeds limit")

// ErrUnsupportedMediaType is returned when the request's Content-Type does
// not match the decoder's expectation. Callers should map it to HTTP 415.
var ErrUnsupportedMediaType = errors.New("httpx: unsupported media type")

// ErrInvalidBody is returned when a JSON or form body is malformed. The
// error path is intentionally opaque: leaking parser specifics has been a
// fingerprinting vector in past OPs.
var ErrInvalidBody = errors.New("httpx: invalid request body")

// DecodeForm parses an application/x-www-form-urlencoded body bounded by
// [MaxFormBytes] and returns the [url.Values]. The Content-Type header
// must match (parameters such as charset are tolerated).
//
// The function does not consume the body's [io.ReadCloser]; callers may
// continue reading trailing artifacts if needed, but typical OP endpoints
// have nothing after the form.
func DecodeForm(r *http.Request) (url.Values, error) {
	if !hasContentType(r, "application/x-www-form-urlencoded") {
		return nil, ErrUnsupportedMediaType
	}
	raw, err := readBounded(r.Body, MaxFormBytes)
	if err != nil {
		return nil, err
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, ErrInvalidBody
	}
	return v, nil
}

// DecodeJSON unmarshals the request body into dst. Body size is bounded by
// [MaxJSONBytes] and unknown fields are rejected so a typo does not silently
// drop a parameter.
//
// dst must be a pointer to a struct; callers should never pass a pointer to
// any/[]any because that disables the unknown-field guard.
func DecodeJSON(r *http.Request, dst any) error {
	if !hasContentType(r, "application/json") {
		return ErrUnsupportedMediaType
	}
	raw, err := readBounded(r.Body, MaxJSONBytes)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return ErrInvalidBody
	}
	// Reject any trailing data — multiple JSON documents in one body is a
	// parser-confusion vector.
	if dec.More() {
		return ErrInvalidBody
	}
	return nil
}

// readBounded reads up to limit bytes from body and reports
// [ErrBodyTooLarge] if the body would exceed the cap. Reading limit+1 bytes
// distinguishes "exactly at the cap" (allowed) from "above the cap" (reject)
// without re-reading the body.
func readBounded(body io.ReadCloser, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, ErrInvalidBody
	}
	if int64(len(raw)) > limit {
		return nil, ErrBodyTooLarge
	}
	return raw, nil
}

// hasContentType reports whether r's Content-Type header begins with the
// given media type, ignoring parameters (charset, boundary, ...) per
// RFC 9110 §8.3. Comparison is case-insensitive on the type/subtype.
func hasContentType(r *http.Request, want string) bool {
	got := r.Header.Get("Content-Type")
	if got == "" {
		return false
	}
	if i := strings.IndexByte(got, ';'); i >= 0 {
		got = got[:i]
	}
	return strings.EqualFold(strings.TrimSpace(got), want)
}
