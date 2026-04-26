package feature

// Flag is the typed enumeration of optional protocol extensions. The zero
// value is invalid; callers MUST use one of the exported constants.
type Flag uint8

const (
	// flagUnspecified is the zero value used to detect an uninitialised
	// [Flag]. Switch statements should surface it via the default arm so
	// accidentally-zero callers fail loudly.
	flagUnspecified Flag = iota

	// PKCE enables RFC 7636 Proof Key for Code Exchange. PKCE is enabled
	// by default on the authorization_code grant; explicit selection only
	// affects discovery metadata and per-client policy.
	PKCE

	// PAR enables RFC 9126 Pushed Authorization Requests. The /par
	// endpoint becomes routable and the request_uri parameter is
	// accepted at /authorize.
	PAR

	// JAR enables RFC 9101 JWT-Secured Authorization Requests. The
	// request and request_uri parameters are validated as signed JWTs.
	JAR

	// JARM enables JWT Secured Authorization Response Mode (OpenID
	// Foundation FAPI 2.0). Authorization responses are signed JWTs
	// rather than query parameters or fragments.
	JARM

	// DPoP enables RFC 9449 Demonstrating Proof of Possession. Access
	// and refresh tokens are bound to a client-held key via DPoP proofs.
	DPoP

	// MTLS enables RFC 8705 OAuth 2.0 Mutual-TLS Client Authentication
	// and certificate-bound access tokens.
	MTLS

	// Introspect enables RFC 7662 Token Introspection. The /introspect
	// endpoint becomes routable for confidential clients and resource
	// servers.
	Introspect

	// Revoke enables RFC 7009 OAuth 2.0 Token Revocation. The /revoke
	// endpoint becomes routable for confidential clients.
	Revoke

	// DynamicRegistration enables RFC 7591 / RFC 7592 / OpenID Connect
	// Dynamic Client Registration 1.0. The /register endpoint becomes
	// routable, the discovery document advertises
	// "registration_endpoint", and operators may mint Initial Access
	// Tokens via [op.Provider.IssueInitialAccessToken]. Activated
	// implicitly by [op.WithDynamicRegistration]; callers do not pass
	// this flag to [op.WithFeature] directly.
	DynamicRegistration
)

// String returns the canonical lower-case identifier used in discovery
// metadata and audit events. It MUST be stable across releases.
func (f Flag) String() string {
	switch f {
	case PKCE:
		return "pkce"
	case PAR:
		return "par"
	case JAR:
		return "jar"
	case JARM:
		return "jarm"
	case DPoP:
		return "dpop"
	case MTLS:
		return "mtls"
	case Introspect:
		return "introspect"
	case Revoke:
		return "revoke"
	case DynamicRegistration:
		return "dynamic_registration"
	case flagUnspecified:
		return ""
	default:
		return ""
	}
}

// IsValid reports whether f is one of the recognised exported constants.
func (f Flag) IsValid() bool {
	switch f {
	case PKCE, PAR, JAR, JARM, DPoP, MTLS, Introspect, Revoke, DynamicRegistration:
		return true
	case flagUnspecified:
		return false
	default:
		return false
	}
}
