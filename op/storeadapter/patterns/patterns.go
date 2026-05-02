// Package patterns hosts the small, behaviour-pinned helpers that the
// in-memory, SQL, and Redis store adapters were independently
// re-implementing before Wave 2C of the v0.9.1 refactor folded the
// duplicates together. The package is intentionally tiny: every helper
// has a single, well-documented behavioural contract, and adapter code
// is expected to call the helpers verbatim rather than wrap them.
//
// # Audience
//
// The package is exported so adapter implementers (inmem, SQL, Redis,
// and any third-party backend) can share the same expiry / not-found /
// dedup / pagination semantics. It is NOT part of the public OP API:
// embedders do not call patterns helpers directly.
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
// of each value in items. The order of survivors matches the order of
// first appearance in the input, which is the property the Redis
// chooser-group lookup needs: the secondary index may surface the
// same session ID twice if a stale entry is re-added before the
// cleanup pass lands, and the caller wants the first hit.
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
// The helper is the slice-based fallback in-memory backends use to
// approximate cursor pagination. SQL and Redis backends drive
// pagination through their native cursor primitives (LIMIT / OFFSET
// or SCAN respectively); they are expected to use this helper only
// for unit-test fixtures, not in the hot path. The helper is
// generically typed so it works against any record type without
// per-store ceremony.
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
	page = items[offset:end]
	nextOffset = end
	hasMore = end < len(items)
	return page, nextOffset, hasMore
}
