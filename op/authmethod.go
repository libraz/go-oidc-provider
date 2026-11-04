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
//
// The two RFC 8705 mTLS methods — [AuthTLSClientAuth] and
// [AuthSelfSignedTLSClientAuth] — are selectable only with
// WithFeature(feature.MTLS); without it [New] rejects a static seed
// carrying one, dynamic registration rejects it, and discovery does not
// advertise it.
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
	// client authenticates with a PKI-issued X.509 certificate whose
	// chain is verified and whose subject DN or SAN matches the one
	// registered matcher. Seed it with [TLSClientAuthClient]; requires
	// [feature.MTLS].
	//
	// Certificate-BOUND tokens (RFC 8705 §3) do not require this method:
	// with [feature.MTLS] the OP stamps cnf.x5t#S256 onto tokens issued
	// to a client that presented a certificate, whichever method it
	// authenticated with.
	AuthTLSClientAuth AuthMethod = "tls_client_auth"

	// AuthSelfSignedTLSClientAuth is "self_signed_tls_client_auth"
	// (RFC 8705 §2.2.1). The client authenticates with a self-signed
	// certificate whose public key is in the client's JWKS or jwks_uri.
	// Seed it with [SelfSignedTLSClientAuthClient]; requires
	// [feature.MTLS].
	AuthSelfSignedTLSClientAuth AuthMethod = "self_signed_tls_client_auth"

	// AuthNone is "none" (OIDC Core 1.0 §9). Public clients (SPAs,
	// native apps) MUST set this; PKCE compensates for the lack of
	// confidential authentication.
	AuthNone AuthMethod = "none"
)

// Valid reports whether m is one of the method names this type
// enumerates. Unknown wire values that have been written to a
// [store.Client] return false, so the predicate is a cheap guard
// against a typo before a value is persisted or compared.
//
// It is NOT a test of whether this OP will accept the method on a
// client: [AuthTLSClientAuth] and [AuthSelfSignedTLSClientAuth] need
// [feature.MTLS], and a profile may narrow the set further. Nothing in
// the library gates negotiation on this predicate; the authoritative
// answer is whether the method appears in the OP's advertised
// token_endpoint_auth_methods_supported.
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
// library writes into [store.Client.TokenEndpointAuthMethod].
//
// For the methods this OP admits it is also the value discovery
// publishes in token_endpoint_auth_methods_supported; the conversion
// carries no such guarantee on its own.
func (m AuthMethod) String() string {
	return string(m)
}
