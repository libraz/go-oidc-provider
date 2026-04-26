package passkey

import "time"

// checkSessionFresh returns [ErrChallengeExpired] when the session's
// Expires stamp is at or before the verifier's clock reading. A zero
// Expires (which the package never emits but a malicious cookie might
// carry) is rejected as well: a legitimate session always has a
// non-zero stamp.
func (v *Verifier) checkSessionFresh(s *Session) error {
	if s.Expires.IsZero() {
		return ErrChallengeExpired
	}
	now := v.clock().Now()
	if !s.Expires.After(now) {
		return ErrChallengeExpired
	}
	return nil
}

// sessionZeroTime returns the time.Time zero value. The helper exists
// so the call sites in register.go / authenticate.go read more clearly
// — the intent is "skip the upstream library's wall-clock check by
// blanking Expires" — and so a future change of strategy (e.g. setting
// a far-future stamp instead of zero) lives in one place.
func sessionZeroTime() time.Time { return time.Time{} }
