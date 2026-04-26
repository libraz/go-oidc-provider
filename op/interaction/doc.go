// Package interaction defines the contract between the [op.Provider] and the
// caller-supplied UI that drives login, consent, and account-selection
// prompts. The library performs every protocol-visible decision; the Driver
// implementation only owns the user-facing surface.
//
// The contract is intentionally narrow: the OP exposes a JSON interaction
// API at /interaction/{uid} for SPA front ends to consume, and the [Driver]
// supplies the data those endpoints need (registered authenticators, scope
// metadata, auto-consent rules) without the library learning anything about
// the rendering technology.
//
// # Status
//
// Experimental: the Driver interface and surrounding types are subject to
// change in any minor release before v1.0. The intent is locked, but the
// signatures will evolve as the SPA endpoints (L2) are wired in Phase 2/3.
package interaction
