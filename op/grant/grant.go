package grant

// Type is the typed enumeration of OAuth 2.0 grant_type values supported by
// the library. The zero value is invalid; callers MUST use one of the
// exported constants.
type Type uint8

const (
	// typeUnspecified is the zero value used to detect an uninitialised
	// [Type]. Code that compares against [Type] values via a switch should
	// surface this via the default arm so accidentally-zero callers fail
	// loudly.
	typeUnspecified Type = iota

	// AuthorizationCode selects the authorization_code grant from
	// RFC 6749 §4.1 / OpenID Connect Core 1.0 §3.1.3.
	AuthorizationCode

	// RefreshToken selects the refresh_token grant from RFC 6749 §6.
	// The library issues refresh tokens only when the granted scope
	// includes "openid" AND the client lists "refresh_token" in
	// [op.store.Client.GrantTypes]; non-OIDC clients therefore do not
	// silently accumulate long-lived credentials. The "offline_access"
	// scope is accepted for OIDC compatibility but is not the gate.
	RefreshToken

	// ClientCredentials selects the client_credentials grant from
	// RFC 6749 §4.4. It is restricted to confidential clients.
	ClientCredentials

	// DeviceCode selects the urn:ietf:params:oauth:grant-type:device_code
	// grant from RFC 8628. Implemented in v1.x; the constant exists so
	// option signatures are stable across releases.
	DeviceCode
)

// String returns the wire form of the grant_type. The wire form is the value
// that appears in HTTP request bodies and discovery metadata; it MUST match
// the relevant RFC verbatim.
func (t Type) String() string {
	switch t {
	case AuthorizationCode:
		return "authorization_code"
	case RefreshToken:
		return "refresh_token"
	case ClientCredentials:
		return "client_credentials"
	case DeviceCode:
		return "urn:ietf:params:oauth:grant-type:device_code"
	case typeUnspecified:
		return ""
	default:
		return ""
	}
}

// IsValid reports whether t is one of the recognised exported constants.
// The library uses this in option validation; user code should rarely need
// it.
func (t Type) IsValid() bool {
	switch t {
	case AuthorizationCode, RefreshToken, ClientCredentials, DeviceCode:
		return true
	case typeUnspecified:
		return false
	default:
		return false
	}
}
