// Package totp implements the RFC 6238 Time-based One-Time Password
// authenticator used as a second factor by the OP. It owns secret
// generation, otpauth provisioning URIs, code computation, constant-time
// verification, the AES-256-GCM at-rest envelope for the persisted secret,
// and the brute-force counter that protects the verifier.
// # Scope
// The package is **self-contained**: orchestrator wiring, HTTP handlers,
// and the [op.WithMFAEncryptionKeys] option live elsewhere. Callers compose
// the building blocks here into an authenticator chain. The package does
// not import any other internal authn code: the existing
// internal/authn package handles
// **client** authentication at the token endpoint and is unrelated.
// # Algorithm
// The implementation follows RFC 6238 with the interop defaults: SHA-1
// HMAC, 30-second time step, 6-digit decimal codes, T0 = Unix epoch.
// SHA-1 is used because every authenticator app on the market (Google
// Authenticator, 1Password, Authy, Microsoft Authenticator...) supports
// it; SP 800-63B does not deprecate HMAC-SHA-1 in the OTP profile, and
// the extra collision resistance of SHA-256 is not consumed by truncation
// to six decimal digits anyway.
// # Skew window
// The verifier accepts the current step plus one step on each side
// (T-1, T, T+1) to absorb authenticator clock drift. A larger window is
// not offered because every additional step doubles the brute-force
// surface; the 1-step window matches the RFC 6238 §5.2 example and the
// industry default. Callers SHOULD NOT widen Skew above 1 in production.
// # At-rest encryption
// The shared secret is wrapped with AES-256-GCM before persistence. The
// key is supplied at construction by the embedder and rotated through the
// rotation slot on [Codec], identical in shape to
// internal/cookie.Codec but with a
// distinct lifecycle: TOTP secrets persist for the lifetime of the
// enrolment, so the rotation history MUST be retained until every record
// has been re-encrypted under the current key. Storing a TOTP secret
// without encryption is a deployment-time bug; the
// [op.WithMFAEncryptionKeys] option will refuse to construct a [Provider]
// in production mode without a key.
// The Additional Authenticated Data (AAD) is the subject ID, so a record
// stolen from one user's row cannot be replayed under a different
// subject — the GCM tag fails to authenticate.
// # Brute-force defence
// The verifier maintains a 24-hour cumulative
// counter rather than a sliding window: the field FailedCount on the
// persisted record increments on every wrong code and resets on success
// or after the 24-hour rollover. When FailedCount reaches 30 the verifier
// stamps a 1-hour LockedUntil; at 90 it stamps a 24-hour lock and emits
// [ErrResetRequired] so the orchestrator can force a step-up reset of
// the factor. The verifier in this package never disables a factor on
// its own — that decision belongs to the orchestrator, which sees the
// whole chain.
// # Concurrency
// [Codec] and [Verifier] are immutable after construction and safe for
// concurrent use. The persisted record is the per-user mutable state; the
// caller is responsible for serialising writes (typically via the same
// transaction that issues the auth_time update).
package totp
