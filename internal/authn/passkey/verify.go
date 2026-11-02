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

// sessionExpiry is the absolute stamp for a Session created now.
func (v *Verifier) sessionExpiry() time.Time {
	return v.clock().Now().Add(v.SessionTTL).UTC()
}

// aaguidRecheckActive reports whether assertions must re-check the AAGUID
// allowlist: the toggle is on and the allowlist is non-empty.
func (v *Verifier) aaguidRecheckActive() bool {
	return v.aaguidReCheckOnAssertion && len(v.aaguidAllowlist) > 0
}
