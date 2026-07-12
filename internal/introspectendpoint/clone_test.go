package introspectendpoint_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
)

func TestCloneStringMapReturnsIndependentCopy(t *testing.T) {
	t.Parallel()

	src := map[string]string{
		"jkt":      "thumbprint-1",
		"x5t#S256": "cert-thumbprint-1",
	}
	got := introspectendpoint.CloneStringMapForTest(src)
	if len(got) != len(src) {
		t.Fatalf("clone len = %d, want %d", len(got), len(src))
	}
	for k, want := range src {
		if got[k] != want {
			t.Fatalf("clone[%q] = %q, want %q", k, got[k], want)
		}
	}

	got["jkt"] = "mutated"
	if src["jkt"] != "thumbprint-1" {
		t.Fatalf("mutating clone changed source: %v", src)
	}
	src["x5t#S256"] = "source-mutated"
	if got["x5t#S256"] != "cert-thumbprint-1" {
		t.Fatalf("mutating source changed clone: %v", got)
	}
}

func TestCloneStringMapHandlesNilAndEmptyInput(t *testing.T) {
	t.Parallel()

	if got := introspectendpoint.CloneStringMapForTest(nil); got == nil || len(got) != 0 {
		t.Fatalf("clone nil = %#v, want non-nil empty map", got)
	}
	if got := introspectendpoint.CloneStringMapForTest(map[string]string{}); got == nil || len(got) != 0 {
		t.Fatalf("clone empty = %#v, want non-nil empty map", got)
	}
}
