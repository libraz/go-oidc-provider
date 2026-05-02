package subject

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Subject is the OP-internal identifier the library writes into the
// "sub" claim of issued ID tokens and JWT access tokens. The op
// package re-exports the type as op.Subject; the canonical definition
// lives here so the [SubjectGenerator] surface can name its return
// type without importing the op package and creating an import cycle.
type Subject string

// String returns the underlying identifier.
func (s Subject) String() string { return string(s) }

// IsZero reports whether s is the zero value.
func (s Subject) IsZero() bool { return s == "" }

// FederatedSubject is the typed wrapper for an upstream identifier
// returned by an external IdP. The op package re-exports the type as
// op.FederatedSubject; the canonical definition lives here for the
// same reason as [Subject].
type FederatedSubject struct {
	// Provider is the registered upstream identifier (e.g. "google").
	Provider string

	// ExternalID is the opaque identifier the upstream IdP returned.
	ExternalID string
}

// IsZero reports whether the FederatedSubject is unset.
func (f FederatedSubject) IsZero() bool { return f.Provider == "" && f.ExternalID == "" }

// Generator computes the value the OP writes into the "sub" claim of
// issued ID tokens and JWT access tokens for an authenticated end-user.
// The op package re-exports the type as op.SubjectGenerator.
//
// Implementations MUST be deterministic for a given input: calling
// Generate twice with identical [GeneratorInput] MUST return the same
// [Subject]. The library calls Generate once per (user, client) pair
// at grant-creation time and persists the result on the
// [store.Grant]; subsequent token issuance under the same grant
// reuses the persisted value verbatim. Switching the active Generator
// after grants have been issued is rejected at construction time per
// ADR 0029.
//
// The package ships two reference implementations: [UUIDv7] (the v0.x
// default; passes InternalUserID through verbatim) and [Pairwise]
// (OIDC Core 1.0 §8.1, scoped by the client's sector host).
type Generator interface {
	// Generate returns the subject identifier for the supplied input.
	// It MUST NOT block on network I/O for the UUIDv7 path; the
	// pairwise path MAY consult an internal sector cache populated by
	// the library.
	//
	// Returning an empty Subject is treated as a server-side
	// configuration error and propagated to the caller as
	// codeServerError; the library does not silently substitute a
	// default value.
	Generate(ctx context.Context, in GeneratorInput) (Subject, error)
}

// GeneratorInput is the bundle the library hands to a [Generator] at
// grant-creation time. Exactly one of InternalUserID and Federated
// MUST be non-zero; both being set or both being zero is a programmer
// error in the calling site and the library reports it via the audit
// chain.
type GeneratorInput struct {
	// InternalUserID is the OP-internal stable identifier of the end
	// user. Non-empty for users that authenticated through the OP's
	// own UserStore.
	InternalUserID string

	// Federated is the upstream identifier returned by an external
	// IdP. Non-zero when the user authenticated through federation.
	Federated FederatedSubject

	// Client is the requesting client. Pairwise generators consult
	// [store.Client.SectorIdentifierURI] and the registered redirect
	// URIs to derive the sector host; UUID-passthrough generators
	// ignore the field.
	//
	// The library guarantees Client is non-nil when calling Generate.
	Client *store.Client
}
