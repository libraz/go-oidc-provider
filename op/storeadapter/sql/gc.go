package oidcsql

import (
	"context"
	"time"
)

// GCStats reports how many rows a single [Store.GC] sweep deleted from
// each table. The counts are per-table so an embedder can publish them
// as a metric and notice a table whose retention has stopped keeping
// up before it becomes an outage.
type GCStats struct {
	// AuthorizationCodes is the number of expired authorization codes
	// deleted. One row is written per completed authorization request,
	// so this is normally the largest count.
	AuthorizationCodes int64

	// PushedAuthRequests is the number of expired PAR records deleted,
	// including records that were never redeemed.
	PushedAuthRequests int64

	// Interactions is the number of expired interaction records
	// deleted. A user who abandons a login leaves one behind.
	Interactions int64

	// Sessions is the number of expired sessions deleted. A session
	// that the user logged out of is removed at logout and never
	// reaches the sweep.
	Sessions int64

	// RefreshTokens is the number of refresh-token rotation records
	// deleted. The count lags the others: a record is reclaimed only
	// once every refresh token issued under the same grant has expired,
	// so a grant a client keeps refreshing contributes nothing to this
	// figure however many rotations it has been through.
	RefreshTokens int64

	// AccessTokens is the number of expired rows deleted from the
	// access-token registry.
	AccessTokens int64

	// OpaqueAccessTokens is the number of expired opaque access tokens
	// deleted.
	OpaqueAccessTokens int64

	// GrantRevocations is the number of expired grant tombstones and
	// revoked-jti denylist rows deleted, counted together.
	GrantRevocations int64

	// ConsumedJTIs is the number of expired consumed-jti markers deleted.
	ConsumedJTIs int64
}

// Total returns the sum of every per-table count.
func (s GCStats) Total() int64 {
	return s.AuthorizationCodes + s.PushedAuthRequests + s.Interactions + s.Sessions + s.RefreshTokens +
		s.AccessTokens + s.OpaqueAccessTokens + s.GrantRevocations + s.ConsumedJTIs
}

// GC deletes rows whose expires_at has passed from the nine tables that
// accumulate rows the request path never reclaims itself: authorization
// codes, PAR records, interactions, sessions, refresh-token rotation
// records, access-token registry rows, opaque access tokens, grant
// revocations (tombstones and the revoked-jti denylist), and consumed
// JTIs. A row is deleted only when its expires_at is strictly
// before cutoff, so passing a cutoff in the past retains a grace window
// for forensics; passing the current time reclaims everything expired.
// Rows whose expires_at is zero are treated as "no expiry" and are
// never deleted.
//
// Deleting an expired access-token, revocation or consumed-JTI row never
// weakens replay detection or revocation: an expired row is by contract
// the same as an absent one, and a tombstone's expiry is computed by the
// OP with a grace window past the last token it can revoke.
//
// Refresh tokens carry one further condition, because their own expiry
// is not what decides whether they are still needed. Replay revocation
// (RFC 9700 §2.2.2) resolves a chain root before cascading, and the root
// is the oldest token in its chain and so the first to expire; deleting
// it while a descendant is still redeemable would make every later
// replay on that chain unresolvable. The sweep therefore reclaims an
// expired record only once no refresh token issued under the same grant
// is still live. That is coarser than the chain — a grant can carry more
// than one chain — which over-retains and never under-retains. A client
// that keeps refreshing holds its whole rotation history; the history is
// reclaimed when it stops.
//
// The refresh sweep is the expensive one: the condition is a
// per-grant anti-join rather than a range scan on expires_at. Schedule
// it accordingly on a large table.
//
// A refresh-token row retained that way may still carry the sealed
// response the RFC 9700 delivery grace window cached against it. That
// response is bounded by the predecessor's own expiry, not by the
// grant's, so GC clears the column on the row's own expiry rather than
// waiting for the row to go. Clearing it removes no row and therefore
// contributes to no count.
//
// The adapter does not sweep on its own. It starts no goroutine and
// owns no timer, because a library that is handed a *sql.DB has no
// standing to decide when the process it lives in should do background
// work: the embedder knows whether this replica is the one that should
// sweep, how the work interleaves with their traffic, and when to stop.
// Call GC from an existing scheduler — a cron job, a leader-elected
// worker, a ticker in main. It runs on the *sql.DB the Store was
// constructed with, so scheduling it needs no second connection pool
// and no second Store.
//
// GC stops at the first failing table and returns the counts collected
// so far alongside the error, so a caller that publishes the stats
// records the work that did land. A partial sweep is safe to repeat:
// every statement is an unconditional DELETE of already-dead rows.
//
// The substores behind the last four sweeps also expose their own GC
// method, reachable through the matching accessor, for a caller that
// wants to reclaim one table on its own schedule; [store.ConsumedJTIStore]
// does not declare GC on its interface, so that one is reachable only
// through this method. Device codes and CIBA requests need no scheduling
// at all: their substores evict expired rows on the insert path.
//
// GC must not be reachable from an HTTP route; run it from the
// embedder's scheduler.
func (s *Store) GC(ctx context.Context, cutoff time.Time) (GCStats, error) {
	var stats GCStats
	// cutoff appears twice in the refresh sweep: once to select the
	// expired rows and once to decide which grants are still live. Both
	// readings must be the same instant, or a row could be reclaimed
	// against a liveness answer computed at a different time.
	query := func(q string, args ...any) func(context.Context, time.Time) (int64, error) {
		return func(ctx context.Context, _ time.Time) (int64, error) { return s.sweep(ctx, q, args) }
	}
	cut := timeToInt64(cutoff)
	widen := func(f func(context.Context, time.Time) (int, error)) func(context.Context, time.Time) (int64, error) {
		return func(ctx context.Context, c time.Time) (int64, error) {
			n, err := f(ctx, c)
			return int64(n), err
		}
	}
	sweeps := []struct {
		name  string
		run   func(ctx context.Context, cutoff time.Time) (int64, error)
		count *int64
	}{
		{"authorizationCodes", query(s.queries.authCodeGC, cut), &stats.AuthorizationCodes},
		{"pushedAuthRequests", query(s.queries.parGC, cut), &stats.PushedAuthRequests},
		{"interactions", query(s.queries.interactionGC, cut), &stats.Interactions},
		{"sessions", query(s.queries.sessionGC, cut), &stats.Sessions},
		{"refreshTokens", query(s.queries.refreshGC, cut, cut), &stats.RefreshTokens},
		// Clearing the cached retry responses runs after the deletes so it
		// only touches rows the refresh sweep decided to keep; it removes
		// no row, so it has no counter.
		{"refreshRetryResponses", query(s.queries.refreshRetryGC, cut), nil},
		{"accessTokens", widen(s.accessTokensImpl.GC), &stats.AccessTokens},
		{"opaqueAccessTokens", widen(s.opaqueAccessTokensImpl.GC), &stats.OpaqueAccessTokens},
		{"grantRevocations", widen(s.grantRevocationsImpl.GC), &stats.GrantRevocations},
		{"consumedJTIs", s.jtisImpl.GC, &stats.ConsumedJTIs},
	}
	for _, sweep := range sweeps {
		n, err := sweep.run(ctx, cutoff)
		if err != nil {
			return stats, wrapErr("gc."+sweep.name, err)
		}
		if sweep.count != nil {
			*sweep.count = n
		}
	}
	return stats, nil
}

// sweep runs one DELETE and reports the number of rows it removed. It
// reads the row count through the driver rather than counting first and
// deleting second: a row that expires between a count and a delete
// would otherwise make the reported figure disagree with what the
// table actually lost.
func (s *Store) sweep(ctx context.Context, query string, args []any) (int64, error) {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
