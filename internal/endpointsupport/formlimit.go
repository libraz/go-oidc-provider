package endpointsupport

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// MaxFormBytes caps the size of the request body every body-accepting
// OP endpoint reads before parsing it — application/x-www-form-urlencoded
// (token, PAR, introspect, revoke, device_authorization, bc-authorize,
// authorize POST, end_session POST, grant management, userinfo POST) as
// well as the application/json DCR bodies (register / manage) that share
// the same posture. RFC 6749 / 7009 / 7591 / 7592 / 7662 / 9126 / OIDC
// RP-Initiated Logout 1.0 each describe modest payloads — the access
// token / id_token_hint / client assertion / client metadata are the
// largest fields and comfortably fit in a few KiB — so 64 KiB is well
// above any legitimate request while bounding memory use against
// pathological inputs (gosec G120).
//
// The value is sourced from [httpx.MaxFormBytes] so the 64 KiB ceiling
// has exactly one definition project-wide; every endpoint reads it
// through this alias rather than declaring its own copy.
const MaxFormBytes = httpx.MaxFormBytes

// LimitFormBody installs an [http.MaxBytesReader] cap on r.Body sized
// at [MaxFormBytes]. This is the single shared body-size gate every OP
// endpoint calls immediately before ParseForm (or, for the DCR JSON
// endpoints, before decoding the body) so a multi-megabyte body is
// short-circuited at read time rather than fully buffered. Despite the
// name, the helper is content-type agnostic — it merely wraps r.Body in
// [http.MaxBytesReader] — so the DCR endpoints reuse it for their
// application/json bodies rather than declaring a second byte-cap
// mechanism for the same 64 KiB ceiling.
//
// The function is a no-op when r or w is nil; callers that hand in a
// constructed request always pass both, but the defensive guard makes
// the helper safe to invoke without a nil-check.
func LimitFormBody(w http.ResponseWriter, r *http.Request) {
	if r == nil || w == nil || r.Body == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
}
