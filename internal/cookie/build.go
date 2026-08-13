package cookie

import (
	"errors"
	"net/http"
	"time"
)

// Build constructs an [http.Cookie] honouring the supplied [Profile]. It does
// not encrypt or otherwise mutate value; callers must pass the already-sealed
// string when [Profile.Encrypted] is true.
//
// Build returns an error if the profile is invalid (e.g. Name without the
// __Host- prefix when HostPrefix is true). The error path exists because the
// profile may have been constructed dynamically; the predefined profile
// constants in this package always validate.
func Build(p Profile, value string) (*http.Cookie, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	//nolint:gosec // G124: Secure and SameSite come from the validated profile rather than a literal, which the rule cannot follow.
	c := &http.Cookie{
		Name:     p.Name,
		Value:    value,
		Path:     "/",
		Secure:   !p.Insecure,
		HttpOnly: true,
		SameSite: p.SameSite,
	}
	if p.MaxAge > 0 {
		c.MaxAge = int(p.MaxAge.Seconds())
	}
	return c, nil
}

// ErrSessionExpired reports that the session a cookie was about to carry has
// no server-side lifetime left. Callers MUST clear the session cookie instead
// of writing one.
var ErrSessionExpired = errors.New("cookie: session lifetime already elapsed")

// BuildSession constructs the browser-session cookie for an already-sealed
// payload, capping its Max-Age at the remaining server-side lifetime of the
// session the payload names.
//
// expiresAt (the session record's server-side expiry) and now (the calling
// endpoint's clock reading) are both required arguments rather than optional
// refinements, because every exit path that writes this cookie has to answer
// the same question: how much longer may the browser present this value? A
// cookie that outlives its session only lets a stolen value be replayed
// against a store that will reject it, and the browser keeps re-sending it
// until the profile lifetime elapses.
//
// A zero expiresAt means the caller knows of no server-side bound, so the
// profile's own MaxAge stands. A non-positive remaining lifetime yields
// [ErrSessionExpired].
func BuildSession(value string, expiresAt, now time.Time) (*http.Cookie, error) {
	profile := SessionProfile
	if !expiresAt.IsZero() {
		remaining := expiresAt.UTC().Sub(now.UTC())
		if remaining <= 0 {
			return nil, ErrSessionExpired
		}
		if remaining < profile.MaxAge {
			// Cookie Max-Age is expressed in whole seconds. Preserve a
			// positive sub-second server-side lifetime as one second rather
			// than truncating it to zero, which would silently turn the
			// authenticated cookie into a browser-session cookie.
			seconds := remaining / time.Second
			if remaining%time.Second != 0 {
				seconds++
			}
			profile.MaxAge = seconds * time.Second
		}
	}
	return Build(profile, value)
}

// Clear constructs an [http.Cookie] that instructs the browser to delete the
// cookie defined by [Profile]. The empty value plus MaxAge=-1 is the standard
// recipe per RFC 6265 §4.1.2.
func Clear(p Profile) (*http.Cookie, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	//nolint:gosec // G124: Secure and SameSite come from the validated profile rather than a literal, which the rule cannot follow.
	return &http.Cookie{
		Name:     p.Name,
		Value:    "",
		Path:     "/",
		Secure:   !p.Insecure,
		HttpOnly: true,
		SameSite: p.SameSite,
		MaxAge:   -1,
	}, nil
}
