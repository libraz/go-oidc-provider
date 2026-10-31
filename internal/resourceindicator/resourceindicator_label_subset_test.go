package resourceindicator_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
)

func TestSubsetLabelCanonicalisesBothSides(t *testing.T) {
	t.Parallel()

	if !resourceindicator.SubsetLabel(
		[]string{"HTTPS://API.EXAMPLE/foo/", "https://other.example/"},
		[]string{"https://api.example/foo", "HTTPS://OTHER.EXAMPLE"},
	) {
		t.Fatal("SubsetLabel rejected equivalent canonical resources")
	}
	if resourceindicator.SubsetLabel(
		[]string{"https://api.example", "https://extra.example"},
		[]string{"https://api.example"},
	) {
		t.Fatal("SubsetLabel accepted an audience broader than allowed")
	}
	if !resourceindicator.SubsetLabel(nil, []string{"https://api.example"}) {
		t.Fatal("empty want should be a subset")
	}
}

func TestSubsetLabelTable(t *testing.T) {
	t.Parallel()
	allowed := []string{"https://api.example/", "HTTPS://Other.example:443", "logical-name", "https://u@bad.example"}
	tests := []struct {
		name string
		want []string
		ok   bool
	}{
		{"empty want", nil, true},
		{"single canonical", []string{"https://api.example"}, true},
		{"multiple equivalent", []string{"https://API.example", "https://other.example/", "logical-name"}, true},
		{"one outside", []string{"https://api.example", "https://nope.example"}, false},
		{"userinfo never matches", []string{"https://api.example", "https://u@bad.example"}, false},
		{"empty entry never matches", []string{"https://api.example", ""}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resourceindicator.SubsetLabel(tc.want, allowed); got != tc.ok {
				t.Errorf("SubsetLabel(%v) = %v, want %v", tc.want, got, tc.ok)
			}
		})
	}
	if resourceindicator.SubsetLabel([]string{"a", "b"}, nil) {
		t.Error("non-empty want against empty allowed must fail")
	}
}

// TestSubsetLabelCanonicalisesAllowedOnce pins that the allowed list is
// parsed once per call rather than once per wanted entry.
//
//nolint:paralleltest // testing.AllocsPerRun pins GOMAXPROCS and panics when called from a parallel test.
func TestSubsetLabelCanonicalisesAllowedOnce(t *testing.T) {
	allowed := make([]string, 16)
	want := make([]string, 16)
	for i := range allowed {
		allowed[i] = "https://api" + string(rune('a'+i)) + ".example/path"
		want[i] = allowed[i]
	}
	perEntry := testing.AllocsPerRun(20, func() {
		for _, w := range want {
			if !resourceindicator.ContainsLabel(allowed, w) {
				t.Fatal("unexpected miss")
			}
		}
	})
	once := testing.AllocsPerRun(20, func() {
		if !resourceindicator.SubsetLabel(want, allowed) {
			t.Fatal("unexpected miss")
		}
	})
	if once*3 > perEntry {
		t.Errorf("SubsetLabel allocs = %v, per-entry ContainsLabel allocs = %v; want at least 3x fewer", once, perEntry)
	}
}
