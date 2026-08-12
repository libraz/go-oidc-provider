package cookie

import (
	"net/http"
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
