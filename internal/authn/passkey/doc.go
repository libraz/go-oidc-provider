// Package passkey wraps [github.com/go-webauthn/webauthn/webauthn] in a
// thin façade tailored to the OP's storage and session-state model. The
// package owns the registration and assertion ceremonies described in
// W3C WebAuthn Level 3 §7 and §7.2 — challenge generation,
// CredentialCreationOptions / CredentialRequestOptions assembly,
// SessionData lifecycle, and the post-verification translation from the
// library's [webauthn.Credential] to the project's flat
// [github.com/libraz/go-oidc-provider/op/store.PasskeyRecord].
//
// # Scope
//
// The package is **self-contained** in the sense documented in
// docs/plans/002-product-design.md §E: orchestrator wiring, HTTP
// handlers, cookie ferrying, and the future [op.WithPasskeyConfig] option
// live elsewhere. Callers compose the building blocks here into a
// passkey authenticator branch. The package does not import any other
// internal authn code: the existing
// [github.com/libraz/go-oidc-provider/internal/authn] package handles
// **client** authentication at the token endpoint and is unrelated.
//
// # Attestation policy
//
// v1.0 hard-codes attestation conveyance to "none"
// ([protocol.PreferNoAttestation]). That choice avoids shipping a FIDO
// metadata service (MDS) with the library: verifying "direct" or
// "enterprise" attestation requires either a maintained AAGUID
// allow-list or the FIDO MDS3 blob, both of which carry their own
// rotation and license-of-data concerns we are not prepared to take on
// for a v1.0 release. Embedders that need attestation enforcement today
// MUST stand it up out-of-band and reject the registration before
// calling [Verifier.FinishRegistration]; v1.x will introduce a
// constructor option that takes an explicit AAGUID allow-list (see
// docs/plans/002-product-design.md §M.5).
//
// As a consequence the [Config] struct deliberately does NOT expose an
// AttestationPreference field: a wrong setting would silently weaken
// the registration ceremony. The only path to "direct" attestation in
// v1.0 is to fork the package, which surfaces the deviation in code
// review.
//
// # Authenticator selection
//
// v1.0 also uses the library defaults for [protocol.AuthenticatorSelection]:
// no AuthenticatorAttachment filter (platform and cross-platform are
// both acceptable), ResidentKey is not required, UserVerification is
// "preferred". The choices favour the broadest possible authenticator
// reach for first-time embedders. v1.x will expose a constructor option
// for embedders who need a stricter policy (e.g. enterprise deployments
// that mandate cross-platform security keys).
//
// # SessionData lifetime
//
// Every ceremony emits a [Session] the caller MUST stash on the user's
// browser (typically inside the interaction-state cookie, encrypted via
// internal/cookie.Codec) and present back at the corresponding Finish
// call. The session carries the challenge bytes, the user handle, the
// allow-list of credential IDs (assertion only), and an absolute
// [Session.Expires] timestamp. The default TTL is five minutes —
// matching the library default — and can be tightened via
// [Config.SessionTTL]. The Verifier rejects a session whose Expires
// stamp is before its [timex.Clock] reading with [ErrChallengeExpired].
//
// # PasskeyStore vs. SessionData
//
// [github.com/libraz/go-oidc-provider/op/store.PasskeyRecord] is the
// **persistent** view of a registered authenticator: credential ID,
// COSE public key, sign counter, AAGUID, and the flag set the library
// observes during the most recent assertion. It survives reboots and
// is keyed on the credential ID for assertion lookups and on the
// subject for registration listings.
//
// The [Session] is a **per-ceremony** value. It only exists between a
// Begin call and the matching Finish call (typically tens of seconds)
// and never touches the persistent store. The two roles are kept
// separate in the type system so a caller cannot accidentally persist
// challenge bytes alongside credential records.
//
// # Concurrency
//
// [Verifier] is immutable after construction and safe for concurrent
// use. The persisted [PasskeyRecord] is the per-user mutable state; the
// caller is responsible for serialising writes (typically via the same
// transaction that records the AMR change).
package passkey
