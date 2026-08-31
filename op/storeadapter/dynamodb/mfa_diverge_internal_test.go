package oidcdynamo

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// The authentication-factor contracts ask a backend to produce a record
// whose values moved while its Version stayed put, so they can tell a
// compare-and-swap that matches the whole record from one that matches
// Version alone. No exported call reaches that state — every write the
// adapter performs allocates a fresh token — so the hooks below issue an
// unconditional PutItem that re-encodes the item with the token it
// already carried. They live in a test file, so they are not part of the
// package's surface.

// DivergeTOTPRecord moves one value of the stored enrolment for subject
// while writing back the opaque token the item already held, as a writer
// that bypassed the adapter would. It is the TOTP
// contract suite's Diverge hook for this adapter.
func (s *Store) DivergeTOTPRecord(t *testing.T, subject string) {
	t.Helper()
	rec, err := s.totpsImpl.Get(t.Context(), subject)
	if err != nil {
		t.Fatalf("DivergeTOTPRecord(%q) read: %v", subject, err)
	}
	rec.FailedCount++
	entry, err := totpItem(rec)
	if err != nil {
		t.Fatalf("DivergeTOTPRecord(%q) encode: %v", subject, err)
	}
	s.putDivergedMFAItem(t, s.names.totpSecrets, entry)
}

// DivergeEmailOTPRecord moves one value of the stored challenge for
// subject while writing back the opaque token the item already held. It
// is the email-OTP contract suite's Diverge hook for this adapter.
func (s *Store) DivergeEmailOTPRecord(t *testing.T, subject string) {
	t.Helper()
	rec, err := s.emailOTPsImpl.Get(t.Context(), subject)
	if err != nil {
		t.Fatalf("DivergeEmailOTPRecord(%q) read: %v", subject, err)
	}
	rec.SendCount++
	entry, err := emailOTPItem(rec)
	if err != nil {
		t.Fatalf("DivergeEmailOTPRecord(%q) encode: %v", subject, err)
	}
	s.putDivergedMFAItem(t, s.names.emailOTPs, entry)
}

// putDivergedMFAItem overwrites the item unconditionally: the adapter's
// own writers all go through a version-plus-document predicate, which is
// exactly the guard this hook has to sidestep.
func (s *Store) putDivergedMFAItem(t *testing.T, table string, entry item) {
	t.Helper()
	if _, err := s.api.PutItem(t.Context(), &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item:      entry,
	}); err != nil {
		t.Fatalf("out-of-band PutItem into %s: %v", table, err)
	}
}
