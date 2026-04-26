package op

import "time"

// Clock returns the current wall-clock time. The library reads the wall
// clock through this interface so that tests can inject deterministic
// timestamps and so that token TTLs, audit log records, and rate-limit
// windows all advance together.
//
// Implementations MUST be safe for concurrent use by multiple goroutines.
//
// Stable since v0.1.
type Clock interface {
	Now() time.Time
}
