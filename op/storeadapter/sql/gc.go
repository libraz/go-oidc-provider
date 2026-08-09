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
}

// Total returns the sum of every per-table count.
func (s GCStats) Total() int64 {
	return s.AuthorizationCodes + s.PushedAuthRequests + s.Interactions + s.Sessions
}

// GC deletes rows whose expires_at has passed from the four tables that
// accumulate one row per request and are never reclaimed by the request
// path itself: authorization codes, PAR records, interactions, and
// sessions. A row is deleted only when its expires_at is strictly
// before cutoff, so passing a cutoff in the past retains a grace window
// for forensics; passing the current time reclaims everything expired.
// Rows whose expires_at is zero are treated as "no expiry" and are
// never deleted.
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
// The other substores that retain rows past their usefulness expose
// their own sweeps on the interfaces they implement, because their
// retention is a policy question the OP itself answers rather than a
// pure expiry: [store.AccessTokenRegistry], [store.OpaqueAccessTokenStore],
// [store.GrantRevocationStore], and [store.ConsumedJTIStore] each carry
// a GC method reachable through the matching accessor on this Store.
// Device codes and CIBA requests need no scheduling at all: their
// substores evict expired rows on the insert path.
func (s *Store) GC(ctx context.Context, cutoff time.Time) (GCStats, error) {
	var stats GCStats
	sweeps := []struct {
		name  string
		query string
		count *int64
	}{
		{"authorizationCodes", s.queries.authCodeGC, &stats.AuthorizationCodes},
		{"pushedAuthRequests", s.queries.parGC, &stats.PushedAuthRequests},
		{"interactions", s.queries.interactionGC, &stats.Interactions},
		{"sessions", s.queries.sessionGC, &stats.Sessions},
	}
	for _, sweep := range sweeps {
		n, err := s.sweep(ctx, sweep.query, cutoff)
		if err != nil {
			return stats, wrapErr("gc."+sweep.name, err)
		}
		*sweep.count = n
	}
	return stats, nil
}

// sweep runs one DELETE and reports the number of rows it removed. It
// reads the row count through the driver rather than counting first and
// deleting second: a row that expires between a count and a delete
// would otherwise make the reported figure disagree with what the
// table actually lost.
func (s *Store) sweep(ctx context.Context, query string, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, query, timeToInt64(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
