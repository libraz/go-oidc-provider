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

// Generator computes the value the OP writes into the "sub" claim of
// issued ID tokens and JWT access tokens for an authenticated end-user.
// The op package re-exports the type as op.SubjectGenerator.
//
// Implementations MUST be deterministic for a given input: calling
// Generate twice with identical [GeneratorInput] MUST return the same
// [Subject].
//
// Determinism is load-bearing rather than an optimisation, because the
// library does not persist the projected value. A grant records the
// OP-internal subject, and every surface that releases a "sub" — token
// issuance, /userinfo, introspection, end-session and back-channel
// logout — projects that recorded value again through the Generator
// when it answers. Generate is therefore called on each of those
// requests, not once when the grant is created: an implementation that
// returns a fresh value per call, or that carries a side effect priced
// as "once per (user, client)", will misbehave. Switching the active
// Generator after grants have been issued is rejected at construction
// time by the subject-mode immutability gate.
//
// The package ships two reference implementations: [UUIDv7] (the
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

// GeneratorInput is the bundle the library hands to a [Generator] on
// every projection. InternalUserID MUST be non-empty; an empty value is
// a programmer error in the calling site and the library reports it via
// the audit chain.
//
// There is no separate field for an identity minted by an upstream IdP.
// The library has no federation surface of its own: an embedder
// federates by wrapping its own authenticator in an external step,
// which reports the authenticated user as a single opaque string, and
// that string arrives here as InternalUserID. An embedder whose users
// can come from more than one upstream must therefore make the string
// distinguish them — "provider:external-id" is the conventional
// shape — because two upstreams returning the same opaque identifier
// for unrelated people would otherwise project onto one subject.
type GeneratorInput struct {
	// InternalUserID is the stable identifier of the end user as the
	// OP knows it: either from the OP's own UserStore, or as reported
	// by the embedder's external authentication step.
	InternalUserID string

	// Client is the requesting client. Pairwise generators consult
	// [store.Client.SectorIdentifierURI] and the registered redirect
	// URIs to derive the sector host; UUID-passthrough generators
	// ignore the field.
	//
	// The library guarantees Client is non-nil when calling Generate.
	Client *store.Client
}
