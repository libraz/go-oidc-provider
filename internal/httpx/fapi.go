package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// FAPIInteractionIDHeader is the canonical header that FAPI 2.0 §6
// requires the OP to echo on every response, generating a fresh
// value when the client did not supply one. The lowercase form is
// the spec's wire shape; HTTP header lookups are case-insensitive,
// so the constant doubles as both read and write key.
const FAPIInteractionIDHeader = "x-fapi-interaction-id"

// InteractionIDMiddleware returns an HTTP middleware that implements
// the FAPI 2.0 §6 "x-fapi-interaction-id" echo: if the client
// supplied a value, it is forwarded verbatim onto the response; if
// not, the middleware generates a random UUIDv4 and stamps it. The
// header lands on the response BEFORE next.ServeHTTP is invoked so
// downstream handlers may read it from the writer (or overwrite it
// when they have a more meaningful value to substitute).
//
// The middleware is unconditional: callers gate it on the active
// [profile.Profile] in the OP wiring layer rather than encoding the
// policy here, which keeps the package free of a dependency on
// op/profile and lets test rigs exercise the echo without standing
// up a full Provider.
func InteractionIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(FAPIInteractionIDHeader)
		if id == "" {
			id = NewInteractionID()
		}
		w.Header().Set(FAPIInteractionIDHeader, id)
		next.ServeHTTP(w, r)
	})
}

// NewInteractionID returns a fresh UUIDv4 string suitable for the
// FAPI x-fapi-interaction-id header. The implementation pulls 16
// bytes from [crypto/rand], stamps the version + variant nibbles
// per RFC 4122 §4.4, and returns the canonical hyphenated form.
//
// crypto/rand failures collapse onto an empty string. The caller
// (the middleware) treats empty as "no header to set", so the
// failure mode is "header missing" rather than panic — losing the
// echo on a one-off entropy hiccup is an acceptable degradation
// where panicking would brown out the OP.
func NewInteractionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	// RFC 4122 §4.4 UUID v4 layout: bits 48–51 carry the version
	// nibble (4 == 0100); bits 64–65 carry the variant marker
	// (10xx == "RFC 4122").
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst)
}
