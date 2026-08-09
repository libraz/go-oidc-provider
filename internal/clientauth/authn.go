// Package clientauth implements OAuth 2.0 / OpenID Connect client
// authentication at the token endpoint. It covers the four methods the
// library accepts in v1.0:
//
//   - client_secret_basic (RFC 6749 §2.3.1)
//   - client_secret_post  (RFC 6749 §2.3.1)
//   - private_key_jwt     (OIDC Core §9, RFC 7521 + RFC 7523)
//   - none                (public clients with PKCE)
//
// client_secret_jwt (HS256-shared-secret JWT) is intentionally NOT
// supported: shared-secret JWTs broaden the
// blast radius of a leaked secret without offering anything the existing
// methods don't already cover.
//
// # Layering
//
// The package splits parsing (extracting credentials from an
// http.Request) from verification (deciding whether the credentials
// satisfy the registered client). Parsing is concrete; verification
// dispatches through interfaces so embedders can plug in their own
// secret-hash and JTI-replay backends without forking the library.
//
// # Errors
//
// Sentinel errors are exposed for the HTTP layer to map onto the
// standard OAuth wire codes:
//
//   - ErrNoCredentials           → invalid_request
//   - ErrAmbiguousCredentials    → invalid_request
//   - ErrUnsupportedMethod       → invalid_request
//   - ErrClientMismatch          → invalid_client
//   - ErrCredentialsInvalid      → invalid_client
//   - ErrAssertionMalformed      → invalid_client
//   - ErrAssertionReplayed       → invalid_client
package clientauth

import "errors"

// Method identifies which OAuth client authentication method the request
// presented. The set is closed; the parser rejects unknown values
// structurally rather than letting them pass through to a verifier.
type Method string

const (
	// MethodNone is the "none" method advertised by public clients.
	// PKCE is the structural protection in this case; the verifier
	// confirms the client is registered as PublicClient and rejects
	// every confidential client trying to use this method.
	MethodNone Method = "none"

	// MethodSecretBasic is HTTP Basic with client_id : client_secret
	// percent-encoded per RFC 6749 §2.3.1.
	MethodSecretBasic Method = "client_secret_basic"

	// MethodSecretPost is body-form authentication (client_id and
	// client_secret in the application/x-www-form-urlencoded body).
	MethodSecretPost Method = "client_secret_post"

	// MethodPrivateKeyJWT is the asymmetric assertion path:
	// client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
	// + client_assertion=<JWT signed with the client's private key>.
	MethodPrivateKeyJWT Method = "private_key_jwt"
)

// AssertionType is the literal value the OAuth specs assign to the
// "client_assertion_type" parameter when private_key_jwt is in use
// (RFC 7521 §4.2 / RFC 7523 §2.2).
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Sentinel errors. The HTTP layer maps them to OAuth wire codes; see the
// package godoc for the full mapping.
var (
	// ErrNoCredentials means the request did not present any client
	// credentials. The endpoint may still accept the request if the
	// client is registered with method=none and PKCE is in use.
	ErrNoCredentials = errors.New("authn: no client credentials presented")

	// ErrAmbiguousCredentials means the request presented credentials
	// through more than one channel (e.g. Basic + body). RFC 6749 §2.3
	// forbids the combination.
	ErrAmbiguousCredentials = errors.New("authn: multiple credential sources presented")

	// ErrUnsupportedMethod means the parsed method is outside the
	// library's allow-list (e.g. client_secret_jwt) or the client_id
	// was malformed.
	ErrUnsupportedMethod = errors.New("authn: unsupported authentication method")

	// ErrClientMismatch means the credentials authenticated successfully
	// against one client but the request claimed a different client_id
	// (typically Basic auth + a body client_id that disagrees).
	ErrClientMismatch = errors.New("authn: client_id mismatch")

	// ErrCredentialsInvalid means the credentials did not verify against
	// the stored client. It collapses several sub-cases (wrong secret,
	// signature mismatch, public client trying to use a secret method)
	// into a single sentinel so the HTTP layer cannot leak which one
	// occurred.
	ErrCredentialsInvalid = errors.New("authn: credentials did not verify")

	// ErrInsecureParams means the built-in Argon2id hasher was configured
	// below the verifier's OWASP-aligned policy floor.
	ErrInsecureParams = errors.New("authn: argon2id parameters are below policy floor")

	// ErrAssertionMalformed indicates the private_key_jwt assertion
	// failed structural validation (parsing, header, claims, exp/iat).
	ErrAssertionMalformed = errors.New("authn: client_assertion malformed")

	// ErrAssertionReplayed indicates the assertion's "jti" was already
	// consumed within its lifetime (RFC 7523 §3 replay defence).
	ErrAssertionReplayed = errors.New("authn: client_assertion replayed")
)
