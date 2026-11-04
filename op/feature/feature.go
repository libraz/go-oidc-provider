package feature

// Flag is the typed enumeration of optional protocol extensions. The zero
// value is invalid; callers MUST use one of the exported constants.
//
// Extensions that need configuration of their own (dynamic client
// registration, rich authorization requests, grant management) have no
// flag: the option that supplies the configuration enables them.
type Flag uint8

const (
	// flagUnspecified is the zero value used to detect an uninitialised
	// [Flag]. Switch statements should surface it via the default arm so
	// accidentally-zero callers fail loudly.
	flagUnspecified Flag = iota

	// PKCE names RFC 7636 Proof Key for Code Exchange.
	//
	// The flag has no runtime or discovery effect. PKCE with S256 is
	// supported unconditionally and "code_challenge_methods_supported"
	// always advertises ["S256"], so passing this flag to
	// [op.WithFeature] neither adds nor removes anything. In particular
	// it does NOT make code_challenge mandatory: public and native
	// clients always require it, and confidential clients are held to it
	// only under [op.WithProfile] with profile.OAuth21 or either FAPI
	// 2.0 profile. Use [op.WithProfile] to harden a deployment.
	//
	// The constant is retained because it is part of the v1.0 stable
	// enumeration.
	PKCE

	// PAR enables RFC 9126 Pushed Authorization Requests. The /par
	// endpoint becomes routable and the request_uri parameter is
	// accepted at /authorize.
	PAR

	// JAR enables RFC 9101 JWT-Secured Authorization Requests. The
	// request and request_uri parameters are validated as signed JWTs.
	JAR

	// JARM enables JWT Secured Authorization Response Mode (OpenID
	// Foundation FAPI 2.0). It adds the signed response modes
	// (query.jwt, fragment.jwt, form_post.jwt, jwt) alongside the
	// unsigned ones; a response is a signed JWT when the client requests
	// one of those modes, or when a profile that mandates JARM
	// (FAPI 2.0 Message Signing) is active.
	JARM

	// DPoP enables RFC 9449 Demonstrating Proof of Possession. Access
	// and refresh tokens are bound to a client-held key via DPoP proofs.
	DPoP

	// MTLS enables RFC 8705: the OP reads the client certificate
	// presented on the request (TLS handshake, or a trusted
	// reverse-proxy header when one is configured).
	//
	//   - §3 certificate-bound access tokens: the certificate's
	//     "x5t#S256" thumbprint goes into the issued token's "cnf"
	//     claim and is re-verified at /token and /userinfo.
	//   - §2 client authentication: "tls_client_auth" and
	//     "self_signed_tls_client_auth" become selectable — advertised
	//     in discovery, admitted by static seeding and dynamic
	//     registration — at every client-authenticating endpoint.
	//
	// The halves are independent: a client authenticating with
	// private_key_jwt still gets certificate-bound tokens when it
	// presents a certificate.
	MTLS

	// Introspect enables RFC 7662 Token Introspection. The /introspect
	// endpoint becomes routable for confidential clients and resource
	// servers.
	Introspect

	// Revoke enables RFC 7009 OAuth 2.0 Token Revocation. The /revoke
	// endpoint becomes routable for confidential and public clients,
	// each revoking only tokens issued to itself.
	Revoke
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
	case flagUnspecified:
		return ""
	default:
		return ""
	}
}

// IsValid reports whether f is one of the recognised exported constants.
func (f Flag) IsValid() bool {
	switch f {
	case PKCE, PAR, JAR, JARM, DPoP, MTLS, Introspect, Revoke:
		return true
	case flagUnspecified:
		return false
	default:
		return false
	}
}
