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
	//
	// Under the historical default policy, the library issues refresh
	// tokens when the granted scope contains "openid" and the client
	// lists "refresh_token" in [store.Client.GrantTypes].
	// "offline_access" is not an issuance requirement in that mode; it
	// controls consent and the optional offline-token TTL bucket.
	//
	// Embedders that require "offline_access" for issuance must also
	// configure [op.WithStrictOfflineAccess]. Removing RefreshToken from
	// [op.WithGrants], or "refresh_token" from a client's GrantTypes,
	// disables issuance regardless of the selected offline-access policy.
	RefreshToken

	// ClientCredentials selects the client_credentials grant from
	// RFC 6749 §4.4. It is restricted to confidential clients.
	ClientCredentials

	// DeviceCode selects the urn:ietf:params:oauth:grant-type:device_code
	// grant from RFC 8628. Enable its device-authorization endpoint and
	// token-endpoint redemption path with [op.WithDeviceCodeGrant].
	DeviceCode

	// CIBA selects the urn:openid:params:grant-type:ciba grant from
	// the OpenID Connect Client-Initiated Backchannel Authentication
	// Flow Core 1.0 specification. The library implements poll mode
	// only; push and ping delivery modes are reserved for a future
	// release.
	CIBA
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
	case CIBA:
		return "urn:openid:params:grant-type:ciba"
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
	case AuthorizationCode, RefreshToken, ClientCredentials, DeviceCode, CIBA:
		return true
	case typeUnspecified:
		return false
	default:
		return false
	}
}
