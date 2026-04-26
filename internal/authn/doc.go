// Package authn is the user-authenticator orchestration layer of
// go-oidc-provider. It owns the type vocabulary the eventual chain
// runner uses to record per-step authentications and the aggregation
// that turns those records into the (acr, amr) pair persisted onto
// [op/store.Session].
//
// This package is distinct from internal/clientauth: clientauth verifies
// the OAuth client at the token endpoint, whereas authn verifies the
// human end-user at the authorization endpoint. The two never share
// types; mixing them would let a client authentication method bleed
// into the id_token's amr claim.
//
// # v1.0 surface
//
// v1.0 ships the claim-aggregation primitives only:
//
//   - [Factor] is one successful authentication step (its method, the
//     assurance level it asserts, and whether the authenticator
//     verified the user).
//   - [Aggregate] folds a slice of factors into a single (acr, amr,
//     [op.AAL]) triple. The result is what the orchestrator will
//     write onto the session record.
//
// The chain runner that executes per-step authenticators through the
// [op/interaction.Driver] boundary is wired in a follow-up task; this
// package intentionally exposes no [op.Authenticator] interface yet,
// because doing so before the runner exists would freeze the contract
// against an unproven design.
//
// # Subpackages
//
// The per-method primitives live under authn/:
//
//   - [internal/authn/totp] — RFC 6238 generator and verifier with
//     AES-256-GCM at-rest secret encryption.
//   - [internal/authn/recovery] — argon2id-hashed single-use recovery
//     codes.
//   - [internal/authn/passkey] — WebAuthn Level 3 registration and
//     assertion.
//
// Each subpackage emits its own per-method record (a [Factor]) when a
// step succeeds; the orchestrator aggregates them through [Aggregate].
package authn
