package recovery_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestEnrolled_UnusedCodeLeft pins that a batch counts as enrolled only
// while at least one code is unused.
func TestEnrolled_UnusedCodeLeft(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdapterFixture(t)
	issued, err := f.store.Get(ctx, f.subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	spent := &store.RecoveryBatch{Subject: "user-spent", GeneratedAt: issued.GeneratedAt}
	for _, c := range issued.Codes {
		spent.Codes = append(spent.Codes, store.RecoveryCode{Hash: c.Hash, ConsumedAt: f.authTime})
	}
	if err := f.store.Put(ctx, spent); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for subject, want := range map[string]bool{f.subject: true, "user-spent": false, "user-unknown": false} {
		got, err := f.adapter.Enrolled(ctx, subject)
		if err != nil {
			t.Fatalf("Enrolled(%q): %v", subject, err)
		}
		if got != want {
			t.Errorf("Enrolled(%q) = %v, want %v", subject, got, want)
		}
	}
}
