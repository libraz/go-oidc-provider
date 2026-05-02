// Package subject ships the reference [op.SubjectGenerator]
// implementations the library wires when an embedder selects a
// non-default subject strategy.
//
// The package intentionally exposes a small surface: factory functions
// only, no exported state. Implementations are unexported so the
// invariants documented on [op.SubjectGenerator] (determinism, no
// surprise I/O, sector-scoped pairwise output) cannot drift across
// future revisions.
//
// # Choosing a generator
//
// The default — [UUIDv7] — returns the embedder-supplied
// InternalUserID verbatim. Embedders that already use stable UUIDv7
// values for their user records get OIDC Core 1.0 §8.1 "public"
// subject behaviour without further configuration.
//
// [Pairwise] returns SHA-256-derived sub values per OIDC Core 1.0
// §8.1, scoped by the client's sector_identifier_uri host so the
// same end-user receives different sub values across sectors. Salt
// supply, sector resolution, and the migration-immutability gate are
// configured at the [op.WithPairwiseSubject] call site.
package subject
