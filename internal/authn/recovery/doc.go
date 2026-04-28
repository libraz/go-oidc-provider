// Package recovery implements the single-use recovery-code authenticator
// the OP offers as a last-resort access path when a user has lost their
// primary MFA device. It owns batch generation (10 plaintext codes drawn
// from Crockford's base32 alphabet), argon2id hashing of every code,
// constant-time verification, and the slot-consumption bookkeeping that
// enforces single-use semantics.
// # Scope
// The package is **self-contained** in the sense documented in
// 02-product-design.md §E: orchestrator wiring, HTTP
// handlers, and any user-facing display logic live elsewhere. Callers
// compose the building blocks here into a fall-back authenticator
// branch. The package does not import any other internal authn code:
// the existing [github.com/libraz/go-oidc-provider/internal/authn]
// package handles **client** authentication at the token endpoint and
// is unrelated; the argon2id helpers here intentionally duplicate the
// minimal subset needed rather than depending on that package.
// # Display-once invariant
// Plaintext codes leave the package exactly once, on the
// [GenerationResult] returned from [Verifier.Generate]. Thereafter only
// the argon2id hashes are persisted on the [github.com/libraz/go-oidc-provider/op/store.RecoveryBatch].
// Callers MUST surface the plaintext list to the user immediately
// (download / print / copy-once UI) and MUST NOT log or audit it. The
// type system enforces the invariant by carrying the plaintext on a
// separate field from the persisted batch: a caller that hands the
// batch alone to [github.com/libraz/go-oidc-provider/op/store.RecoveryStore.Put]
// cannot accidentally persist plaintext.
// # Regeneration semantics
// Generating a fresh batch replaces the whole previous batch — there is
// no concept of "appending" codes. Callers that want to extend the
// remaining count for a user MUST regenerate; the previously stored
// hashes are wiped and the user has to reconcile their print-out. This
// matches the threat model: a stolen unconsumed code from an old batch
// cannot be redeemed once the user has noticed and regenerated.
// # Why this is NOT a primary auth path
// Recovery codes exist for the narrow case of "I have a session
// device-lost gap and need to bootstrap a new authenticator". Per
// 02-product-design.md §O.3, **full account recovery** —
// the user has lost both their primary authenticator AND every recovery
// code — is intentionally not automated by the library: it requires
// human-driven identity proofing (support ticket, government ID, etc.)
// that no embedded library can safely standardise. Embedders that want
// a self-service "forgot everything" path MUST build it on top of their
// own out-of-band channel; this package will not provide one.
// # Algorithm
// Each batch contains exactly 10 codes. A code is 10 characters drawn
// uniformly at random from Crockford's base32 alphabet
// (0-9, A-H, J-N, P-Z; with I, L, O, U deliberately excluded to avoid
// transcription ambiguity), formatted with a hyphen splitting the
// middle as XXXXX-XXXXX for human readability. Entropy comes from
// crypto/rand.
// Codes are hashed with argon2id at the OWASP-2024 parameter set
// (m=64MiB, t=3, p=1, salt=16, key=32). The parameters are intentionally
// not configurable in v1.0: tuning them per-deployment would silently
// weaken the defence and complicate verifier compatibility across
// rotation. The encoding is the modular-crypt `$argon2id$...$salt$hash`
// form so an embedder running custom diagnostics can recognise it.
// # Concurrency
// [Verifier] is immutable after construction and safe for concurrent
// use. The persisted batch is the per-user mutable state; the caller is
// responsible for serialising writes (typically via the same
// transaction that records the AMR change).
package recovery
