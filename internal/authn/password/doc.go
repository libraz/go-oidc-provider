// Package password is the internal primitive that drives the built-in
// PrimaryPassword Step. It carries the Argon2id verifier with the
// library's pinned parameter set (m=64MiB, t=3, p=1, salt=16, key=32 —
// matching OWASP 2024 password-hashing guidance) and the
// [authn.Authenticator] adapter the LoginFlow compiler wires up at
// op.New time.
//
// The package is internal-only — embedders compose password through
// [github.com/libraz/go-oidc-provider/op.PrimaryPassword] and a
// [github.com/libraz/go-oidc-provider/op/store.UserPasswordStore]
// implementation. The split keeps the verifier path branch-free
// (parameters are immutable) and avoids a footgun where embedders
// pick weaker Argon2id parameters than they realise.
//
// Hash format: the verifier accepts the modular-crypt encoding
// `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`. Most popular
// password-hashing libraries (Python passlib, Node argon2, Go
// alexedwards/argon2id, …) emit this format directly, so embedders
// can store hashes from existing user-management plumbing.
//
// What this package does NOT do:
//
//   - Enrolment: registering or rotating a user's password is the
//     embedder's responsibility (UI, audit hooks, MFA re-prompting).
//   - Per-attempt throttling: when the Provider has a lockout store, a
//     wrong password is counted on the per-subject counter shared with
//     the second factors (1h lock at 30 failures in 24h, 24h at 90). A
//     locked subject is refused even with the right password, with the
//     same error as a wrong one, and a successful login does not reset
//     the counter. Session-level retry rules (RuleAfterFailedAttempts)
//     are independent of it.
//   - Hash migration: bcrypt → argon2id rehash on successful login is
//     a future surface; embedders with legacy formats wrap their own
//     [authn.Authenticator] in op.ExternalStep until then.
package password
