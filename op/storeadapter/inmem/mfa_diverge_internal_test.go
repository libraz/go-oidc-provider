package inmem

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// The authentication-factor contracts ask a backend to produce a record
// whose values moved while its Version stayed put, so they can tell a
// compare-and-swap that matches the whole record from one that matches
// Version alone. No exported call reaches that state — every write the
// store performs stamps a fresh Version — so the reference
// implementation writes its own map here, under the same lock its
// methods take. The hooks live in a test file, so they are not part of
// the package's surface.

// DivergeTOTPRecord moves one value of the stored enrolment for subject
// without allocating a new Version, as a writer that bypassed the store
// would. It is the TOTP contract suite's Diverge hook for this adapter.
func (s *Store) DivergeTOTPRecord(t *testing.T, subject string) {
	t.Helper()
	s.totps.mu.Lock()
	defer s.totps.mu.Unlock()
	rec, ok := s.totps.m[subject]
	if !ok {
		t.Fatalf("DivergeTOTPRecord(%q): %v", subject, store.ErrNotFound)
	}
	rec.FailedCount++
}

// DivergeEmailOTPRecord moves one value of the stored challenge for
// subject without allocating a new Version. It is the
// email-OTP contract suite's Diverge hook for this adapter.
func (s *Store) DivergeEmailOTPRecord(t *testing.T, subject string) {
	t.Helper()
	s.emailotps.mu.Lock()
	defer s.emailotps.mu.Unlock()
	rec, ok := s.emailotps.m[subject]
	if !ok {
		t.Fatalf("DivergeEmailOTPRecord(%q): %v", subject, store.ErrNotFound)
	}
	rec.SendCount++
}
