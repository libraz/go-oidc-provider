// Package emailotp implements the [op.FactorEmailOTP] reference
// authenticator: a two-screen email-delivery one-time password factor.
// # Shape
// The factor emits two prompts:
//   - "auth.email_otp.send"    — the SPA collects the user's email
//     address. The authenticator confirms the address matches the
//     subject's bound "email" claim, generates a 6-digit code,
//     dispatches the code through a [Mailer] hook, and persists a
//     SHA-256 hash of the (salt || subject || code) tuple in the
//     [store.EmailOTPStore] substore.
//   - "auth.email_otp.verify"  — the SPA collects the code. The
//     authenticator hashes the submission, compares constant-time
//     against the persisted record, and either emits a
//     [interaction.Result] (success) or re-emits the prompt with the
//     brute-force counter decremented (wrong code).
//
// # Subject pre-binding
// Email OTP is a second factor in v1.0: the orchestrator pre-binds
// [op.ContinueInput.Subject] from the previous factor's
// [interaction.Result], and the authenticator looks up the bound
// email claim through [store.UserStore]. The user-typed email field
// on the send prompt is a UX confirmation — server-side, the
// authoritative destination is always the subject's bound email.
// # Enumeration defence
// The send step always emits the verify prompt regardless of whether
// the user-typed address matches the bound claim. On a mismatch the
// authenticator persists a record whose [store.EmailOTPRecord.SentAt]
// is zero so verify deterministically fails — the SPA cannot
// distinguish "wrong email typed" from "user typed correctly but
// guessed the code wrong" through prompt shape or response timing.
// # Brute-force counter
// The verifier maintains the same 24-hour rolling counter as the TOTP
// adapter: 30 wrong codes
// inside the window stamp a 1-hour [LockedUntil]; 90 wrong codes
// stamp a 24-hour lock and surface [ErrResetRequired] so the
// orchestrator can route the user to the recovery flow.
// # Mailer SPI
// Code delivery is the embedder's responsibility: the package only
// wires the [Mailer] interface and never opens an SMTP / API
// connection itself. Implementations MUST treat [Message.Code] as
// plaintext-equivalent material — never log, audit, or persist it.
package emailotp
