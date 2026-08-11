package clientencjwks

import "errors"

// Sentinel errors returned by [Resolver.ResolveRecipient]. Callers
// branch on these via [errors.Is]; the wrapped detail is safe to log
// for diagnosis but MUST NOT be returned to clients verbatim.
var (
	// ErrNoEncryptionConfigured signals that the client did not
	// register any encryption metadata for the response path the
	// caller is processing (alg AND enc both empty). The caller
	// treats this as "encryption not requested" — emit the response
	// in plaintext / signed-only form — rather than a hard error.
	ErrNoEncryptionConfigured = errors.New("clientencjwks: client did not register encryption metadata")

	// ErrAlgNotAllowed signals that alg or enc falls outside the
	// v0.9.1 ship allow-list (internal/jose.AllowedJWEAlgs /
	// internal/jose.AllowedJWEEncs). The class is collapsed
	// because an attacker probing for sub-causes through the wire
	// response would learn nothing useful.
	ErrAlgNotAllowed = errors.New("clientencjwks: alg or enc not allowed")

	// ErrJWKSFetch signals that the client's keyset could not be
	// retrieved from [op/store.Client.JWKsURI]. Wraps the underlying
	// transport / parse / SSRF refusal so log readers can recover
	// the cause via [errors.Unwrap].
	ErrJWKSFetch = errors.New("clientencjwks: jwks fetch failed")

	// ErrJWKSConfigured signals that the client carries neither an
	// inline JWKs nor a JWKsURI. The caller maps this onto its own
	// "encryption requested but client cannot receive it"
	// diagnostic; the OP cannot proceed.
	ErrJWKSConfigured = errors.New("clientencjwks: client has no JWKs or JWKsURI")

	// ErrNoMatchingKey signals that the JWKS resolved successfully
	// but no `use=enc` (or empty `use`) key matched the requested
	// alg. The caller cannot encrypt to this client until the RP
	// publishes a compatible key.
	ErrNoMatchingKey = errors.New("clientencjwks: no matching encryption key in JWKS")

	// ErrWeakRecipientKey signals that the JWKS contains an encryption
	// key candidate for the requested alg, but the key shape is outside
	// the OP's cryptographic floor (for example RSA below 2048 bits or
	// an unsupported EC curve). The caller must fail closed rather than
	// encrypt to the weak key.
	ErrWeakRecipientKey = errors.New("clientencjwks: weak recipient encryption key")
)
