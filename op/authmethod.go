package op

// AuthMethod is a typed wrapper for the OAuth 2.0 / OpenID Connect
// token-endpoint client authentication method values registered in
// IANA's "OAuth Token Endpoint Authentication Methods" registry. The
// type exists so seed clients (and library-internal lookups) can be
// expressed without stringly-typed comparisons; the wire form is
// preserved by the underlying string so [store.Client.TokenEndpointAuthMethod]
// continues to be `string` for storage compatibility.
//
// The closed set of values the library understands is enumerated by the
// constants below. [AuthMethod.Valid] reports membership; values
// outside the set may still be persisted on a [store.Client] (the
// storage layer is opaque) but the library will treat them as unknown
// when negotiating client authentication.
type AuthMethod string

const (
	// AuthClientSecretBasic is "client_secret_basic" (OpenID Connect
	// Core 1.0 §9). The client authenticates with HTTP Basic auth at
	// the token endpoint; the credential is the client_secret.
	AuthClientSecretBasic AuthMethod = "client_secret_basic"

	// AuthClientSecretPost is "client_secret_post" (OIDC Core 1.0 §9).
	// The credential is sent in the POST body. Discouraged in favour
	// of basic auth for new deployments.
	AuthClientSecretPost AuthMethod = "client_secret_post"

	// AuthPrivateKeyJWT is "private_key_jwt" (OIDC Core 1.0 §9 /
	// RFC 7523 §2.2). The client signs a JWT assertion with its
	// registered key; the OP verifies it against the client's JWKS.
	// FAPI 2.0 §3.1.3 lists this method in the preferred allow-list.
	AuthPrivateKeyJWT AuthMethod = "private_key_jwt"

	// AuthTLSClientAuth is "tls_client_auth" (RFC 8705 §2.1.1). The
	// client authenticates with a PKI-issued X.509 certificate
	// presented during the mTLS handshake.
	AuthTLSClientAuth AuthMethod = "tls_client_auth"

	// AuthSelfSignedTLSClientAuth is "self_signed_tls_client_auth"
	// (RFC 8705 §2.2.1). The client authenticates with a self-signed
	// certificate whose JWK is registered in the client's JWKS.
	AuthSelfSignedTLSClientAuth AuthMethod = "self_signed_tls_client_auth"

	// AuthNone is "none" (OIDC Core 1.0 §9). Public clients (SPAs,
	// native apps) MUST set this; PKCE compensates for the lack of
	// confidential authentication.
	AuthNone AuthMethod = "none"
)

// Valid reports whether m is one of the methods the library
// recognises. Unknown wire values that have been written to a
// [store.Client] return false; callers can use that to gate
// negotiation without panicking on a typo.
func (m AuthMethod) Valid() bool {
	switch m {
	case AuthClientSecretBasic,
		AuthClientSecretPost,
		AuthPrivateKeyJWT,
		AuthTLSClientAuth,
		AuthSelfSignedTLSClientAuth,
		AuthNone:
		return true
	default:
		return false
	}
}

// String returns the wire form of m verbatim. It is the value the
// library writes into [store.Client.TokenEndpointAuthMethod] and the
// value discovery advertises in
// `token_endpoint_auth_methods_supported`.
func (m AuthMethod) String() string {
	return string(m)
}
