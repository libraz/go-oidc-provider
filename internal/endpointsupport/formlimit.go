package endpointsupport

import "net/http"

// MaxFormBytes caps the size of an application/x-www-form-urlencoded
// request body the OP's form-accepting endpoints will read. RFC 6749 /
// 7009 / 7662 / 9126 / OIDC RP-Initiated Logout 1.0 each describe
// modest payloads — the access token / id_token_hint / client
// assertion are the largest fields and comfortably fit in a few KiB —
// so 64 KiB is well above any legitimate request while bounding memory
// use against pathological inputs (gosec G120). The constant is shared
// across endpoints so a regression that drops the cap on one endpoint
// is caught by a uniform constant rather than a copy-pasted literal.
const MaxFormBytes = 64 * 1024

// LimitFormBody installs an [http.MaxBytesReader] cap on r.Body sized
// at [MaxFormBytes]. Endpoints call this immediately before ParseForm
// so a multi-megabyte body is short-circuited at read time. The helper
// is the consolidated form of the per-endpoint MaxBytesReader call so
// the cap stays uniform across token / introspect / revoke / par /
// register / userinfo / end_session.
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
