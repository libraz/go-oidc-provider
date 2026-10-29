// Package totpkit is the embedder-facing facade for RFC 6238 TOTP
// enrolment and re-verification. It complements [op.StepTOTP], which
// drives the verify path during login, with the registration path:
// turning a fresh authenticator app pairing into a [store.TOTPRecord]
// the embedder can persist through [store.TOTPStore.Put], and [Verify]
// for checking a code outside the login flow.
//
// # When to use this package
//
// Use totpkit when an embedder builds a "set up two-factor auth"
// screen. The package owns secret generation, the otpauth provisioning
// URI rendered as a QR code, and the proof-of-possession step that
// marks an enrolment confirmed. The login verify path lives in
// [op.StepTOTP] and the orchestrator's chain dispatcher.
//
// The package deliberately stays out of the HTTP surface: an embedder
// who wants to render a QR code, a manual-entry secret, and a code
// input field composes their own controller. totpkit returns the
// material; the embedder owns the UI.
//
// # Lifecycle
//
//  1. Embedder collects the user's identity (typically after primary
//     auth or an account-recovery prompt). totpkit authenticates no
//     one: require a recent sign-in before enrolling or replacing a
//     factor on an existing account.
//  2. Embedder calls [NewEnrolment] with the embedder-shared [Codec]
//     and the (subject, issuer, account) triple. The returned
//     [Pending] carries the otpauth URI (for the QR code), the raw
//     base32 secret (for "manual entry" UX), and a [store.TOTPRecord]
//     with the secret already AES-256-GCM-sealed under the codec's
//     current key, with the subject ID bound as additional
//     authenticated data.
//  3. Embedder stores the [Pending] in a short-lived enrolment
//     session (cookie or server-side) and renders the QR code.
//  4. The user scans the QR code in their authenticator app and
//     types the displayed code back into the embedder's confirm form.
//  5. Embedder calls [Confirm] with the same [Pending] and the
//     submitted code. On success [Confirm] stamps ConfirmedAt and
//     LastAcceptedStep on the record and returns it.
//  6. Embedder persists the returned record through
//     [store.TOTPStore.Put]. From that moment the verify path
//     ([op.StepTOTP]) accepts codes against the same secret.
//
// On confirmation failure the embedder MUST NOT persist the record;
// the secret never leaves the enrolment session and the user retries.
//
// # Re-proving the factor
//
// [Verify] checks a code against a confirmed record and persists the
// outcome through the same failure counter and replay guard as the login
// step, so the two paths cannot be used to double a guess budget or to
// redeem one code twice. Use it before replacing or removing a factor.
//
// Verify is bounded only by the TOTP record's own counters (30 failures
// in 24 hours lock the record for 1 hour). It does not take part in the
// login cross-factor lockout. Put the account page behind a recent
// auth_time and its own rate limit.
//
// # Codec sharing
//
// The [Codec] type is a re-export (type alias) of the verify-path
// codec, so an embedder can construct one [Codec] at startup and
// share it between [op.StepTOTP] (which builds its own codec from the
// same key bytes) and [NewEnrolment]/[Confirm]. No state is shared
// between the two paths; the alias exists only so that errors and
// rotation semantics line up.
//
// # AAD binding
//
// Both Seal (in [NewEnrolment]) and Open (in [Confirm]) bind the
// subject ID as additional authenticated data. A row exfiltrated from
// one user's enrolment session cannot be replayed under a different
// subject — the GCM tag verification rejects the AAD mismatch. The
// same property holds at verify time because [op.StepTOTP] uses the
// same AAD shape.
//
// # Concurrency
//
// [Codec] is safe for concurrent use. [Pending] carries no shared
// state; it is owned by the embedder's enrolment-session record and
// MUST NOT be shared across requests. [NewEnrolment] and [Confirm]
// are pure functions of their inputs and are safe to call from any
// goroutine.
package totpkit
