package totp_test

import (
	"context"
	"testing"
	"time"
)

// TestEnrolled_ConfirmedRecord pins that only a confirmed record counts
// as enrolled.
func TestEnrolled_ConfirmedRecord(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	if err := f.store.Put(context.Background(), newRecord(t, f.codec, "user-pending", f.secret, time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for subject, want := range map[string]bool{f.subject: true, "user-pending": false, "user-unknown": false} {
		got, err := f.adapter.Enrolled(context.Background(), subject)
		if err != nil {
			t.Fatalf("Enrolled(%q): %v", subject, err)
		}
		if got != want {
			t.Errorf("Enrolled(%q) = %v, want %v", subject, got, want)
		}
	}
}
