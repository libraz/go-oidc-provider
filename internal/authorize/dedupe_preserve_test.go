package authorize_test

import (
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

func TestDedupePreserve(t *testing.T) {
	t.Parallel()
	got := authorize.DedupePreserve([]string{"read", "write", "read", "profile", "write"})
	if want := []string{"read", "write", "profile"}; !slices.Equal(got, want) {
		t.Fatalf("DedupePreserve = %v, want %v", got, want)
	}
	if got := authorize.DedupePreserve(nil); got != nil {
		t.Fatalf("DedupePreserve(nil) = %v, want nil", got)
	}
}
