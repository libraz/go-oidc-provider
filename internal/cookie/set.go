package cookie

import (
	"errors"
	"net/http"
	"strings"
)

// HostPrefix is the cookie name prefix mandated by RFC 6265bis §4.1.3.2 for
// host-locked cookies. Every credential the OP issues MUST carry it: the
// browser refuses to set the cookie if Secure is missing, Path is anything
// other than "/", or Domain is set, so an attacker who tampers with the
// attribute set cannot downgrade the cookie's scope.
const HostPrefix = "__Host-"

// ErrMissingHostPrefix is returned by [Set] when name does not start with
// [HostPrefix]. The error path surfaces the misconfiguration at the call
// site rather than letting the OP issue a non-host-locked credential.
var ErrMissingHostPrefix = errors.New("cookie: name must start with __Host-")

// SetOptions are the only attributes a caller may influence when issuing a
// cookie. Secure / HttpOnly / Path / Domain are fixed by [Set] so a forgetful
// caller cannot weaken the credential's scope.
type SetOptions struct {
	// MaxAge is the cookie's lifetime in seconds. Zero leaves the
	// attribute unset (session cookie); negative deletes the cookie at
	// the browser per RFC 6265 §5.3 step 11.
	MaxAge int

	// SameSite controls the cross-site policy. Zero substitutes
	// [http.SameSiteLaxMode] which is the §F.1 default for
	// authentication-flow cookies.
	SameSite http.SameSite
}

// Set writes a host-locked cookie with the OP's mandatory attribute set:
// Secure=true, HttpOnly=true, Path="/", Domain="" (host-only). The name MUST
// start with [HostPrefix]; callers that forget the prefix get
// [ErrMissingHostPrefix] instead of an under-protected cookie.
//
// Set is the only sanctioned cookie issuance helper inside the OP. Callers
// that bypass it (e.g. by constructing [http.Cookie] directly) skip the
// attribute enforcement and are flagged by reviewers per the F.1 policy.
func Set(w http.ResponseWriter, name, value string, opts SetOptions) error {
	if !strings.HasPrefix(name, HostPrefix) {
		return ErrMissingHostPrefix
	}
	sameSite := opts.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   "",
		MaxAge:   opts.MaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})
	return nil
}

// ClearByName writes a deletion cookie for name via [Set]. It mirrors [Set]
// so a caller cannot forget the host-prefix invariant when expiring a
// credential. Use [Clear] (Profile-based) when integrating with code that
// already handles cookies via [Build] / [Profile].
func ClearByName(w http.ResponseWriter, name string) error {
	return Set(w, name, "", SetOptions{MaxAge: -1})
}
