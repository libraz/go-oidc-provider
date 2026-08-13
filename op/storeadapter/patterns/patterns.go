// Package patterns hosts small, behaviour-pinned helpers for store
// adapters. Every helper has a single, well-documented behavioural
// contract and is meant to be called verbatim rather than wrapped.
//
// # Audience
//
// The package is exported so adapter implementers (inmem, SQL, Redis,
// and any third-party backend) can reach it. It is NOT part of the
// public OP API: embedders do not call patterns helpers directly.
//
// # What is actually shared
//
// Two categories are shared by the in-tree adapters. Expiry:
// [IsExpiredStrict] backs inmem, SQL and DynamoDB, [IsExpiredInclusive]
// backs Redis. And the hash-on-store contract: [Digest] is called from
// every adapter that persists an opaque bearer secret, with
// [ConstantTimeKeyMatch] where the lookup is not an exact-key one.
//
// The rest of the package is offered to third-party adapters rather than
// relied on here, and the two paragraphs below say why for the cases
// where that is a decision rather than an accident. [DigestBytes] is
// simply the byte-form companion to [Digest] for a backend that stores
// the digest as BYTEA / BLOB; no in-tree adapter does.
//
// The not-found mappers are deliberately not used in-tree. Every
// in-tree lookup either labels a non-sentinel failure with the
// operation it came from ("users.ReadPasswordHash", "oidcredis: HGET
// op_metadata") — which a helper returning the error verbatim would
// erase — or answers absence as a plain false rather than as an error
// at all. Those are different obligations wearing a similar shape, and
// routing them through one helper would cost error attribution to
// remove a two-line errors.Is. An adapter with no such convention can
// still use them.
//
// [Paginate] is likewise not the in-tree pagination: the store contract
// pages by opaque cursor ([store.GrantClientPage.NextCursor]), and the
// adapters build a page as they scan rather than slicing one out of a
// fully materialised list. The helper is an integer-offset fallback for
// backends whose native paging has that shape.
//
// # Behavioural floors
//
// Every helper documents the exact wall-clock comparison or set
// semantics it implements so adapters can pick the variant that
// matches their backend's native behaviour. In particular,
// [IsExpiredStrict] and [IsExpiredInclusive] differ at the boundary
// instant (t == now): the strict variant treats a record dated exactly
// at "now" as live (matching the inmem reference and the SQL
// adapter's filtering query), the inclusive variant treats it as
// expired (matching Redis' SET-with-TTL semantics where the engine
// evicts at-or-after). Adapters MUST pick the variant that matches
// their backend's native behaviour and MUST NOT mix the two.
package patterns

import (
	"errors"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// IsExpiredStrict reports whether t is strictly before now. The zero
// time encodes "no expiry" and always reports as live.
//
// This is the helper the inmem and SQL adapters use: their
// underlying Find paths intentionally treat a record dated exactly at
// "now" as live so a caller racing the millisecond boundary observes
// the same record either way. SQL's filtering query uses the same
// strict-less-than semantic.
func IsExpiredStrict(t, now time.Time) bool {
	if t.IsZero() {
		return false
	}
	return t.Before(now)
}

// IsExpiredInclusive reports whether t is at or before now. The zero
// time encodes "no expiry" and always reports as live.
//
// This is the helper the Redis adapter uses: Redis SET with TTL
// evicts the key once the TTL elapses, so the at-the-boundary case
// (t == now) maps to "engine has already removed the record". The
// adapter's defence-in-depth re-check against the configured clock
// preserves the same boundary semantic so a clock skew between the
// adapter and the Redis server cannot widen the live window.
func IsExpiredInclusive(t, now time.Time) bool {
	if t.IsZero() {
		return false
	}
	return !t.After(now)
}

// MapSQLNotFound rewrites the supplied database/sql.ErrNoRows
// sentinel into [store.ErrNotFound]. The helper takes the sentinel
// as a parameter rather than importing database/sql so the patterns
// package stays driver-free (it lives in the main module while the
// SQL adapter is a sub-module). Callers pass database/sql.ErrNoRows
// from their own package.
//
// The helper returns nil when err is nil, the supplied sqlNoRows when
// err is anything else, and [store.ErrNotFound] specifically when err
// matches sqlNoRows via [errors.Is].
func MapSQLNotFound(err, sqlNoRows error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sqlNoRows) {
		return store.ErrNotFound
	}
	return err
}

// MapRedisNotFound rewrites the supplied redis.Nil sentinel into
// [store.ErrNotFound]. Callers pass redis.Nil from the redis client
// package; the helper stays driver-free for the same reason
// [MapSQLNotFound] does.
func MapRedisNotFound(err, redisNil error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, redisNil) {
		return store.ErrNotFound
	}
	return err
}

// DedupBatch returns a fresh slice that preserves the first occurrence
// of each value in items, in order of first appearance.
//
// The helper is for a backend whose secondary index can hand back the
// same identifier twice. The in-tree Redis adapter is not one: its
// chooser-group index is a Redis SET, which cannot hold a duplicate
// member, so its lookup has nothing to dedup.
//
// items may be nil, in which case the helper returns nil. A non-nil
// empty input returns a non-nil empty result so callers can rely on
// (out != nil) to signal "intentionally empty" vs. "absent".
func DedupBatch[T comparable](items []T) []T {
	if items == nil {
		return nil
	}
	seen := make(map[T]struct{}, len(items))
	out := make([]T, 0, len(items))
	for _, v := range items {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Paginate returns the page of items starting at offset with at most
// pageSize entries and the next offset the caller should pass on the
// follow-up request. hasMore reports whether the input has further
// entries beyond the returned page.
//
// The helper is an integer-offset fallback for a backend whose native
// paging works that way. It is not what the in-tree adapters do: the
// store contract pages by opaque cursor, and inmem / SQL build each
// page as they scan rather than slicing one out of a list they
// materialised in full. The helper is generically typed so it works
// against any record type without per-store ceremony.
//
// The returned page is a fresh slice, not a window onto items, so a
// caller that sorts or rewrites a page cannot reach back into the
// input — matching [DedupBatch], whose result is likewise independent.
//
// pageSize <= 0 collapses to "return everything from offset onward",
// which keeps the API ergonomic for tests that want a single page.
// offset < 0 is clamped to 0 so a buggy caller does not panic on a
// negative slice index. offset >= len(items) returns an empty page
// and hasMore=false.
func Paginate[T any](items []T, offset, pageSize int) (page []T, nextOffset int, hasMore bool) {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return nil, len(items), false
	}
	end := len(items)
	if pageSize > 0 && offset+pageSize < end {
		end = offset + pageSize
	}
	page = slices.Clone(items[offset:end])
	nextOffset = end
	hasMore = end < len(items)
	return page, nextOffset, hasMore
}
