package cookie

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// Profile describes a cookie's transport-level policy: name, lifetime, scope,
// SameSite, and whether the payload is encrypted. A cookie definition lives
// in one place so the wire shape is auditable in a single read.
//
// A Profile is immutable. Construct one via the package-level constants or
// [NewProfile]; the latter validates the [__Host-] requirements at build
// time so misconfiguration cannot escape into production.
type Profile struct {
	// Name is the wire-level cookie name. When [HostPrefix] is true the
	// "__Host-" prefix is enforced and Path is forced to "/".
	Name string

	// MaxAge is the cookie lifetime. Zero means session cookie (browser
	// purges on close); negative values are forbidden because [Build]
	// produces them implicitly via [Clear].
	MaxAge time.Duration

	// SameSite is the SameSite policy. SameSiteDefaultMode is rejected;
	// callers must pick Lax, Strict, or None explicitly.
	SameSite http.SameSite

	// HostPrefix toggles the [__Host-] prefix and the matching policy
	// (Path=/, Secure required, no Domain attribute).
	HostPrefix bool

	// Encrypted reports whether the payload must be sealed with [Codec]
	// before being placed in the cookie value. The value is informational
	// — [Build] does not encrypt for you; the caller passes the already
	// sealed string.
	Encrypted bool

	// Insecure opts out of the Secure attribute on the rendered cookie.
	// The zero value (false) keeps Secure=true, which is the only RFC
	// 6265bis-compliant configuration for [SameSiteNoneMode] and the
	// only safe configuration for any cookie carrying authentication
	// material. Embedders MAY set Insecure=true for non-confidential
	// cookies on plain-HTTP development origins; [validate] rejects the
	// combination Insecure=true + SameSite=None (RFC 6265bis §4.1.2.7).
	Insecure bool
}

// errSameSiteNoneRequiresSecure is returned when a Profile combines
// [http.SameSiteNoneMode] with Insecure=true. RFC 6265bis §4.1.2.7
// makes Secure mandatory whenever SameSite=None is used; the package
// rejects the combination at construction time so a misconfigured
// profile cannot escape into a response.
var errSameSiteNoneRequiresSecure = errors.New(
	"cookie: SameSite=None requires Secure (RFC 6265bis §4.1.2.7); set Insecure=false",
)

// errSameSiteRequired is returned when a Profile would emit a cookie without
// an explicit SameSite mode. The browser default is Lax for new cookies but
// older browsers vary, so the package forces an explicit choice.
var errSameSiteRequired = errors.New("cookie: SameSite mode must be Lax, Strict, or None")

// errHostPrefixMismatch is returned when [HostPrefix] is true but the name
// is missing the "__Host-" prefix, or vice versa. The two flags must agree
// because the prefix changes the security guarantees.
var errHostPrefixMismatch = errors.New("cookie: HostPrefix true requires __Host- name prefix")

// errNegativeMaxAge is returned when [Profile.MaxAge] is negative. Negative
// max-age values are reserved for the [Clear] helper which builds an
// expiring-cookie response from a profile.
var errNegativeMaxAge = errors.New("cookie: MaxAge must be zero or positive")

// errEmptyName is returned when [Profile.Name] is empty. http.SetCookie would
// silently swallow it; we reject up front.
var errEmptyName = errors.New("cookie: Name must not be empty")

// validate enforces the [__Host-] prefix policy and other invariants that
// must hold before a cookie is rendered onto the wire. SameSite zero value
// (unset) and SameSiteDefaultMode are both rejected because the package
// requires an explicit Lax / Strict / None choice.
//
// validate also rejects the unsafe combination SameSite=None + Insecure
// per RFC 6265bis §4.1.2.7: SameSite=None makes the cookie a target for
// cross-site request inclusion, and shipping it without Secure exposes
// it to network attackers. [Build] honours [Profile.Insecure] for
// non-confidential dev cookies (e.g. plain-HTTP locale preference);
// the validate() guard ensures Insecure cannot apply to SameSite=None
// regardless of how the profile is composed.
func (p Profile) validate() error {
	if p.Name == "" {
		return errEmptyName
	}
	switch p.SameSite {
	case http.SameSiteLaxMode, http.SameSiteStrictMode, http.SameSiteNoneMode:
		// ok
	default:
		return errSameSiteRequired
	}
	if p.SameSite == http.SameSiteNoneMode && p.Insecure {
		return errSameSiteNoneRequiresSecure
	}
	if p.MaxAge < 0 {
		return errNegativeMaxAge
	}
	hasPrefix := strings.HasPrefix(p.Name, "__Host-")
	if p.HostPrefix != hasPrefix {
		return errHostPrefixMismatch
	}
	return nil
}

// SessionProfile defines the __Host-oidc_session cookie: a 14-day idle
// AES-encrypted Lax cookie restricted to the OP origin via the __Host- prefix.
//
//nolint:gochecknoglobals // Predefined cookie profiles are configuration constants.
var SessionProfile = Profile{
	Name:       "__Host-oidc_session",
	MaxAge:     14 * 24 * time.Hour,
	SameSite:   http.SameSiteLaxMode,
	HostPrefix: true,
	Encrypted:  true,
}

// InteractionProfile defines the __Host-oidc_interaction cookie: an
// hour-long, AES-encrypted, Lax cookie carrying the in-flight interaction id.
//
//nolint:gochecknoglobals // Predefined cookie profiles are configuration constants.
var InteractionProfile = Profile{
	Name:       "__Host-oidc_interaction",
	MaxAge:     time.Hour,
	SameSite:   http.SameSiteLaxMode,
	HostPrefix: true,
	Encrypted:  true,
}

// CSRFProfile defines the __Host-oidc_csrf cookie: a session-scoped,
// HMAC-only (no AEAD), Strict SameSite cookie used for double-submit.
//
//nolint:gochecknoglobals // Predefined cookie profiles are configuration constants.
var CSRFProfile = Profile{
	Name:       "__Host-oidc_csrf",
	MaxAge:     0, // session cookie
	SameSite:   http.SameSiteStrictMode,
	HostPrefix: true,
	Encrypted:  false,
}

// LocaleProfile defines the __Host-oidc_locale cookie: a one-year,
// plain-text Lax cookie remembering the user's chosen UI locale.
//
//nolint:gochecknoglobals // Predefined cookie profiles are configuration constants.
var LocaleProfile = Profile{
	Name:       "__Host-oidc_locale",
	MaxAge:     365 * 24 * time.Hour,
	SameSite:   http.SameSiteLaxMode,
	HostPrefix: true,
	Encrypted:  false,
}
