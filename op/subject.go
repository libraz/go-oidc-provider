package op

// Subject is the OP-internal identifier for an authenticated end user. It is
// the value the library writes into the "sub" claim of issued ID tokens and
// access JWTs. A Subject MUST NOT carry upstream identifiers verbatim;
// federated logins go through [FederatedSubject] before becoming a Subject.
type Subject string

// String returns the underlying identifier.
func (s Subject) String() string { return string(s) }

// IsZero reports whether s is the zero value, i.e. unset.
func (s Subject) IsZero() bool { return s == "" }

// FederatedSubject is the typed wrapper for an upstream identifier returned
// by an external IdP. It is the only way the library accepts an upstream
// "sub": resolving it to an internal [Subject] requires a [store.UserStore]
// that owns the (Provider, ExternalID) → Subject mapping.
//
// The wrapper exists so a string returned by Google or GitHub cannot be
// assigned to a [Subject] by mistake, even with implicit conversions.
type FederatedSubject struct {
	// Provider is the registered upstream identifier (e.g. "google",
	// "github"). The library MUST reject Provider values that are not in
	// the configured federation registry.
	Provider string

	// ExternalID is the opaque identifier returned by the upstream IdP.
	// The library treats it as opaque bytes; it is never displayed to
	// end users and never written into a "sub" claim directly.
	ExternalID string
}

// IsZero reports whether the FederatedSubject is unset.
func (f FederatedSubject) IsZero() bool { return f.Provider == "" && f.ExternalID == "" }

// Identity is the bundle of subject-scoped facts the library needs to issue
// tokens and render UserInfo: the canonical [Subject], the authentication
// context the user satisfied, and the claim values keyed by claim name.
//
// Identity is constructed by the user's [interaction.Driver] after a
// successful authentication and consumed by the token endpoint and the
// /userinfo endpoint. It is never stored by the library.
type Identity struct {
	// Subject is the OP-internal "sub" value. It MUST be non-empty.
	Subject Subject

	// AuthenticationContext describes how the user authenticated. It is
	// optional; when set, the library copies AMR and ACR into ID tokens.
	AuthenticationContext AuthContext

	// Claims is the map of claim name to claim value. The map MAY be nil;
	// only requested claims are released to a given client.
	Claims Claims
}

// AuthContext records authentication-method facts that flow into ID token
// claims (RFC 8176 amr, OpenID Connect Core 1.0 §2 acr). It is copied
// verbatim into tokens; ad-hoc fields are not exposed.
type AuthContext struct {
	// AMR is the list of authentication-method reference values per
	// RFC 8176. Order is significant: it MUST reflect the order the user
	// completed the methods.
	AMR []string

	// ACR is the authentication-context-class reference per OpenID
	// Connect Core 1.0 §5.5.1.1. Empty means the OP did not assert one.
	ACR string

	// AuthTime is the wall-clock time at which the user completed
	// authentication, as a Unix timestamp. Zero means unknown; the
	// library omits the auth_time claim in that case.
	AuthTime int64
}
