package lockout

import "time"

// Brute-force escalation policy shared by the cross-factor [Counter] and
// the per-factor TOTP / email-OTP verifiers. The values are not
// configurable: tuning them per-deployment would silently weaken the
// defence, and a single definition keeps every factor on the same curve
// so an attacker pivoting between factors cannot reset it.
const (
	// ThresholdShort triggers a [DurationShort] LockedUntil stamp once
	// the windowed failure count reaches it.
	ThresholdShort = 30

	// ThresholdLong triggers a [DurationLong] LockedUntil stamp and
	// reports that a reset of the factor is required.
	ThresholdLong = 90

	// DurationShort is the LockedUntil offset applied at [ThresholdShort].
	DurationShort = 1 * time.Hour

	// DurationLong is the LockedUntil offset applied at [ThresholdLong].
	DurationLong = 24 * time.Hour

	// CounterWindow is the rolling window over which the failure count
	// accumulates. A failure recorded more than CounterWindow ago is
	// dropped: the next failure restarts the window and the count at 1.
	CounterWindow = 24 * time.Hour
)

// WindowExpired reports whether firstFailureAt starts a window that has
// run out at now. A zero firstFailureAt means no window is open and is
// not expired.
func WindowExpired(firstFailureAt, now time.Time) bool {
	return !firstFailureAt.IsZero() && now.Sub(firstFailureAt) > CounterWindow
}

// Escalate maps the post-increment failure count to the lock it earns at
// now. lockedUntil is the zero time below [ThresholdShort];
// resetRequired is true from [ThresholdLong] on.
func Escalate(failedCount int, now time.Time) (lockedUntil time.Time, resetRequired bool) {
	switch {
	case failedCount >= ThresholdLong:
		return now.Add(DurationLong), true
	case failedCount >= ThresholdShort:
		return now.Add(DurationShort), false
	}
	return time.Time{}, false
}

// Advance folds one wrong-code failure into a per-factor record's counter
// fields at now: it opens a fresh window when none is open or the open one
// has expired, increments the count, and stamps the earned lock over any
// earlier one. resetRequired mirrors [Escalate].
func Advance(failedCount *int, firstFailureAt, lockedUntil *time.Time, now time.Time) (resetRequired bool) {
	if firstFailureAt.IsZero() || WindowExpired(*firstFailureAt, now) {
		*firstFailureAt = now
		*failedCount = 0
	}
	*failedCount++
	until, resetRequired := Escalate(*failedCount, now)
	if !until.IsZero() {
		*lockedUntil = until
	}
	return resetRequired
}
