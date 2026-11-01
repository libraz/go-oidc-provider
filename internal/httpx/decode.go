package httpx

import (
	"encoding/json"
	"errors"
	"io"
)

// MaxFormBytes caps the size of an application/x-www-form-urlencoded body
// the OP will read. The token endpoint and friends never receive payloads
// near this size; the cap exists to bound DoS exposure.
//
// This is the project's single definition of the 64 KiB body-size
// ceiling: internal/endpointsupport's MaxFormBytes constant aliases this
// value rather than declaring its own copy, so every endpoint that
// installs an [http.MaxBytesReader] cap — directly or via
// endpointsupport.LimitFormBody — shares one source of truth.
const MaxFormBytes = 64 * 1024 // 64 KiB

// AtEOF reports whether only whitespace follows the value dec last decoded.
// [json.Decoder.More] is not a substitute: it reports false before a stray
// `}` or `]`, so `{"a":1}}` would pass as a single document.
func AtEOF(dec *json.Decoder) bool {
	var trailing json.RawMessage
	return errors.Is(dec.Decode(&trailing), io.EOF)
}
