package clone_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clone"
)

func TestInt64PtrPreservesNil(t *testing.T) {
	t.Parallel()

	if got := clone.Int64Ptr(nil); got != nil {
		t.Fatalf("Int64Ptr(nil) = %v, want nil", got)
	}
}

func TestInt64PtrReturnsIndependentCopy(t *testing.T) {
	t.Parallel()

	original := int64(42)
	got := clone.Int64Ptr(&original)
	if got == nil {
		t.Fatal("Int64Ptr returned nil for non-nil input")
	}
	if *got != original {
		t.Fatalf("*Int64Ptr = %d, want %d", *got, original)
	}
	if got == &original {
		t.Fatal("Int64Ptr returned the input pointer; want a defensive copy")
	}

	original = 7
	if *got != 42 {
		t.Fatalf("copy changed after original mutation: got %d, want 42", *got)
	}
	*got = 99
	if original != 7 {
		t.Fatalf("original changed after copy mutation: got %d, want 7", original)
	}
}
