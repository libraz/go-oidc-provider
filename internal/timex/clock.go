// Package timex centralises every read of the wall clock used by the
// library. All other packages MUST obtain the current time through a [Clock]
// rather than calling [time.Now] directly so that tests can inject a fake
// clock and so that token TTLs, audit timestamps, and rate limits remain
// consistent across the codebase. The forbidigo lint rule blocks direct
// `time.Now()` calls so the only sanctioned caller is [systemClock.Now].
package timex

import "time"

// Clock returns the current wall-clock time. Implementations MUST be safe
// for concurrent use.
type Clock interface {
	Now() time.Time
}

// ClockFunc lets a plain function satisfy [Clock]. It is the preferred way
// to inject deterministic timestamps in tests.
type ClockFunc func() time.Time

// Now implements [Clock].
func (f ClockFunc) Now() time.Time { return f() }

// SystemClock is the default [Clock] backed by [time.Now]. It is the only
// place in the codebase permitted to call [time.Now] directly. Exposed as
// a global because every caller wants the same wall clock; tests inject a
// distinct [Clock] through dependency injection rather than swapping this
// value.
//
//nolint:gochecknoglobals // singleton wall-clock; intentionally global.
var SystemClock Clock = systemClock{}

type systemClock struct{}

//nolint:forbidigo // SystemClock is the single permitted time.Now caller.
func (systemClock) Now() time.Time { return time.Now() }

// Now is a convenience wrapper around [SystemClock]. Library code SHOULD
// depend on a [Clock] passed in via configuration rather than calling this
// helper, so that tests can substitute a fake clock; the helper exists for
// rare top-level code paths (e.g. server start-up logging) where injection
// would be overkill.
func Now() time.Time { return SystemClock.Now() }
