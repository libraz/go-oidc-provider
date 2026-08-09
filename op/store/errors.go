package store

import "errors"

// ErrNotFound is returned by Find-style methods when the requested record does
// not exist. Backends MUST return ErrNotFound (directly or wrapped with
// [errors.Is]-compatible chaining) rather than a backend-specific "no rows"
// error, so that handler code can use [errors.Is] uniformly across backends.
var ErrNotFound = errors.New("store: record not found")

// ErrAlreadyExists is returned by Save-style methods when a record with the
// same primary key (or a unique secondary key) already exists. Backends MUST
// return ErrAlreadyExists in preference to backend-specific duplicate-key
// errors so that grant handlers can distinguish "first write wins" cases from
// transport faults.
var ErrAlreadyExists = errors.New("store: record already exists")

// ErrAlreadyConsumed is returned by Consume-style methods when the targeted
// one-time record has already been marked consumed by an earlier call. It is
// the signal that grant handlers use to detect replay of single-use tokens
// such as authorization codes (RFC 6749 §4.1.2) and pushed authorization
// requests (RFC 9126 §2.2). Backends MUST distinguish ErrAlreadyConsumed
// from [ErrNotFound]: the former proves the record existed and was used,
// while the latter is silent on prior usage.
//
// [RefreshTokenStore.Save] reuses the same sentinel to refuse a rotation
// onto an already-revoked chain, because the caller's response is
// identical: the presented credential belongs to a chain that has been
// retired.
var ErrAlreadyConsumed = errors.New("store: record already consumed")

// ErrConflict is returned when an optimistic-locking or compare-and-swap
// update fails because another writer modified the record concurrently.
// Callers MAY retry the operation after re-reading the record. Backends that
// have no concept of versioned updates need never return ErrConflict.
var ErrConflict = errors.New("store: concurrent modification")

// ErrTxRequired is returned by transactional backends when a transaction
// handle has already been closed, or when an embedder calls a backend-specific
// operation that the backend intentionally exposes only through a transaction.
// The OP runtime does not require ordinary Store substore calls to return this
// error.
var ErrTxRequired = errors.New("store: operation requires a transaction")
