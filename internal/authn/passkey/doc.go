// Package passkey wraps [github.com/go-webauthn/webauthn/webauthn] in a
// thin façade tailored to the OP's storage and session-state model. The
// package owns the registration and assertion ceremonies described in
// W3C WebAuthn Level 3 §7 and §7.2 — challenge generation,
// CredentialCreationOptions / CredentialRequestOptions assembly,
// SessionData lifecycle, and the post-verification translation from the
// library's [webauthn.Credential] to the project's flat
// [github.com/libraz/go-oidc-provider/op/store.PasskeyRecord].
// # Scope
// The package is **self-contained**: orchestrator wiring, HTTP
// handlers, cookie ferrying, and the future [op.WithPasskeyConfig] option
// live elsewhere. Callers compose the building blocks here into a
// passkey authenticator branch. The package does not import any other
// internal authn code: the existing
// internal/authn package handles
// **client** authentication at the token endpoint and is unrelated.
// # Attestation policy
// The default conveyance is "none" ([protocol.PreferNoAttestation]),
// which is the right posture for a deployment that accepts any
// authenticator: attestation is a privacy-relevant disclosure about the
// user's hardware, and without a policy to apply to it there is nothing
// to gain by collecting it. Under "none" no [Config.AAGUIDAllowlist]
// may be configured, because the AAGUID reported in that mode is
// self-asserted.
//
// A deployment that must restrict registration to approved
// authenticator models sets [Config.AttestationPreference] to
// [protocol.PreferDirectAttestation] together with a non-empty
// [Config.AAGUIDAllowlist] and [Config.AttestationRoots]; [New] refuses
// the allowlist without the other two. "indirect" and "enterprise" are
// not supported.
//
// Requesting direct conveyance only asks for an attestation statement —
// it does not guarantee one that identifies the model, and a signed
// statement only identifies it if the signer is trusted. Anyone can
// mint a CA and an attestation certificate naming any AAGUID.
// [Verifier.FinishRegistration] therefore compares the AAGUID only after
// the statement's x5c chain verifies up to a configured root; a
// self-attested, unattested or chainless response is refused.
//
// The package deliberately ships no FIDO Metadata Service (MDS3)
// client: the allowlist and the roots are the operator's own, so the
// library takes on no blob rotation or data-licensing obligation. An
// embedder that wants MDS-driven policy resolves the metadata
// out-of-band and supplies the resulting AAGUIDs and root certificates.
// # Authenticator selection
// v1.0 also uses the library defaults for [protocol.AuthenticatorSelection]:
// no AuthenticatorAttachment filter (platform and cross-platform are
// both acceptable), ResidentKey is not required, UserVerification is
// "preferred". The choices favour the broadest possible authenticator
// reach for first-time embedders. v1.x will expose a constructor option
// for embedders who need a stricter policy (e.g. enterprise deployments
// that mandate cross-platform security keys).
// # SessionData lifetime
// Every ceremony emits a [Session] the caller MUST stash on the user's
// browser (typically inside the interaction-state cookie, encrypted via
// internal/cookie.Codec) and present back at the corresponding Finish
// call. The session carries the challenge bytes, the user handle, the
// allow-list of credential IDs (assertion only), and an absolute
// [Session.Expires] timestamp. The default TTL is five minutes —
// matching the library default — and can be tightened via
// [Config.SessionTTL]. The Verifier rejects a session whose Expires
// stamp is before its [timex.Clock] reading with [ErrChallengeExpired].
// # PasskeyStore vs. SessionData
// [github.com/libraz/go-oidc-provider/op/store.PasskeyRecord] is the
// **persistent** view of a registered authenticator: credential ID,
// COSE public key, sign counter, AAGUID, and the flag set the library
// observes during the most recent assertion. It survives reboots and
// is keyed on the credential ID for assertion lookups and on the
// subject for registration listings.
// The [Session] is a **per-ceremony** value. It only exists between a
// Begin call and the matching Finish call (typically tens of seconds)
// and never touches the persistent store. The two roles are kept
// separate in the type system so a caller cannot accidentally persist
// challenge bytes alongside credential records.
// # Credential ownership
// A credential ID identifies one credential across the whole Relying
// Party, and the stored record is keyed on it alone. A registration
// allowed to name a credential another subject already holds would
// therefore not add a credential — it would move one, leaving the
// previous owner unable to log in with an authenticator that still
// works. [Verifier.FinishRegistration] takes the credential store as an
// argument for that reason: the exclude list only covers the registering
// subject's own credentials, so the cross-subject case is a question
// only the store can answer. The refusal reuses
// [ErrCredentialAlreadyExists] rather than a distinct sentinel, so a
// response cannot be read as "that credential belongs to someone else".
// # Concurrency
// [Verifier] is immutable after construction and safe for concurrent
// use. The persisted [PasskeyRecord] is the per-user mutable state; the
// caller is responsible for serialising writes (typically via the same
// transaction that records the AMR change).
package passkey
