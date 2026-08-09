package store

import "context"

// MetadataStore persists OP-internal key/value state that is neither
// user data nor token material. The substore exists so the OP can
// remember coarse construction-time decisions across process restarts
// without inventing new tables for one-off facts.
//
// The OP currently uses the substore for a single key,
// [SubjectModeKey], which the pairwise immutability gate consults at
// op.New: the gate writes the active subject-issuance mode on first
// construction and refuses to start when a subsequent construction
// asks for a different mode against a non-empty grant store. Further
// keys (generator name, salt fingerprint, schema version markers)
// compose on the same surface without an interface change.
//
// Backends MAY return nil from [Store.Metadata] when the persistence
// layer has not yet provisioned the substore; the library detects
// nil at op.New and skips the gate with a startup warning so the
// process boots. Every adapter in this repository — inmem, sql,
// redis, and dynamodb — implements MetadataStore in full, so the nil
// path exists for bespoke backends rather than for the bundled ones.
// Note what skipping the gate costs: with no place to record the
// subject-issuance mode, nothing detects a switch between public and
// pairwise subjects against an existing grant store, and every
// affected user's sub changes silently.
type MetadataStore interface {
	// Get returns the value stored under key. Implementations MUST
	// return [ErrNotFound] when the key is absent; callers
	// distinguish "no record" from "value happens to be the empty
	// string" so the marker semantics remain unambiguous.
	Get(ctx context.Context, key string) (string, error)

	// Set persists value under key, replacing any existing value.
	// The operation is idempotent: a Set that re-asserts the prior
	// value is a no-op from the caller's perspective.
	Set(ctx context.Context, key, value string) error
}

// SubjectModeKey is the [MetadataStore] key under which the OP
// records the active subject-issuance mode. The value is one of
// [SubjectModePublic] / [SubjectModePairwise] / [SubjectModeCustom];
// the immutability gate compares the persisted value with the
// constructed value and refuses op.New on mismatch.
const SubjectModeKey = "subject_mode"

// SubjectModePublic is the [SubjectModeKey] value the OP writes when
// neither op.WithPairwiseSubject nor op.WithSubjectGenerator was
// supplied. The library default UUIDv7 passthrough behaves like the
// OIDC Core 1.0 §8 "public" subject_type from the embedder's point
// of view (the OP-internal user identifier flows through to "sub"
// verbatim) so the marker uses the spec-aligned name.
const SubjectModePublic = "public"

// SubjectModePairwise is the [SubjectModeKey] value the OP writes
// when op.WithPairwiseSubject is supplied. Switching away from this
// value once any grant exists in the store yields a configuration
// error at op.New.
const SubjectModePairwise = "pairwise"

// SubjectModeCustom is the [SubjectModeKey] value the OP writes
// when op.WithSubjectGenerator is supplied with an embedder-defined
// generator. The marker is intentionally coarse — the gate refuses
// any switch between (public / pairwise / custom) once grants exist
// — because the library cannot reason about whether two distinct
// custom generators emit equivalent subject identifiers.
const SubjectModeCustom = "custom"

// OpInitKey is the [MetadataStore] key under which the OP records a
// presence sentinel on every successful op.New construction. The
// subject-mode immutability gate consults the sentinel as a
// "this store has been used by an OP before" probe so a re-used
// store whose [SubjectModeKey] entry was wiped (deliberately or by
// truncation) still rejects a non-matching subject-issuance mode
// rather than silently re-keying every future "sub". The value the
// OP writes is intentionally fixed to [OpInitMarker] so the sentinel
// is presence-only; backends MAY treat the key as opaque.
const OpInitKey = "__op_init"

// OpInitMarker is the value the OP writes under [OpInitKey] on every
// successful construction. The string is fixed so the gate's presence
// check is unambiguous: the marker MUST equal this constant when read
// back, otherwise the gate treats the row as foreign and refuses to
// boot.
const OpInitMarker = "v1"
