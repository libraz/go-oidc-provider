package hygiene_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
)

// The transactional cluster is a closed set that has grown at least
// once, and the documents that teach embedders how to split hot from
// cold storage enumerate its members in prose. Prose does not compile:
// when the set grew, they kept naming a membership that no longer
// existed.
//
// The failure is not cosmetic for a reader following them. Two members
// routed to different backends split the consistency domain for replay
// detection and refresh rotation, and composite.New refuses to start on
// it — so an under-listed member reads as "this one is free to move" and
// produces a wiring that fails at boot, while an over-listed one
// (Sessions) hides that a deployment is allowed to put sessions on the
// volatile side.

// clusterEnumerationMarker introduces an enumeration inside a doc
// comment. The names follow it up to the closing parenthesis, so any
// document that wants to be checked writes the marker before its list.
const clusterEnumerationMarker = "composite.TxClusterKinds —"

// clusterEnumerationSites are the documents that spell the cluster out
// for a reader who is deciding where each substore lives. Both are one
// wrong name away from a wiring that either refuses to boot or gives up
// a co-location the adapter never required.
var clusterEnumerationSites = []string{
	"../../examples/08-composite-hot-cold/main.go",
	"../../op/storeadapter/redis/doc.go",
}

// TestCompositeClusterEnumerations pins every prose enumeration against
// [composite.TxClusterKinds] itself, in both directions: a member the
// document omits and a non-member it invents are equally misleading to
// someone wiring a deployment from it.
func TestCompositeClusterEnumerations(t *testing.T) {
	t.Parallel()

	want := make([]string, 0, len(composite.TxClusterKinds))
	for _, kind := range composite.TxClusterKinds {
		want = append(want, kind.String())
	}

	for _, path := range clusterEnumerationSites {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			t.Parallel()

			src, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			listed := enumeratedClusterKinds(t, string(src))
			if len(listed) == 0 {
				t.Fatalf("%s enumerates no cluster member; the scan is broken, not the document", path)
			}
			for _, name := range want {
				if !slices.Contains(listed, name) {
					t.Errorf("%s is a member of composite.TxClusterKinds but %s does not list it: "+
						"a reader routes it to the volatile backend and composite.New refuses to start "+
						"(listed: %v)", name, path, listed)
				}
			}
			for _, name := range listed {
				if !slices.Contains(want, name) {
					t.Errorf("%s lists %s as a member of composite.TxClusterKinds, which it is not: "+
						"a reader pins it to the durable backend for a co-location the adapter never "+
						"required (members: %v)", path, name, want)
				}
			}
		})
	}
}

// enumeratedClusterKinds extracts the member names a document lists
// after the marker, up to the closing parenthesis. The
// enumeration spans comment lines, so the leading "//" of each
// continuation is stripped before splitting.
func enumeratedClusterKinds(t *testing.T, src string) []string {
	t.Helper()

	start := strings.Index(src, clusterEnumerationMarker)
	if start < 0 {
		t.Fatalf("this document no longer introduces its enumeration with %q; "+
			"either restore the marker or drop the enumeration in favour of the symbol",
			clusterEnumerationMarker)
	}
	rest := src[start+len(clusterEnumerationMarker):]
	end := strings.Index(rest, ")")
	if end < 0 {
		t.Fatal("the enumeration has no closing parenthesis; the scan cannot find its end")
	}
	var out []string
	for _, name := range strings.Split(rest[:end], ",") {
		cleaned := strings.TrimSpace(strings.ReplaceAll(name, "//", " "))
		cleaned = strings.Join(strings.Fields(cleaned), "")
		if cleaned != "" {
			out = append(out, cleaned)
		}
	}
	return out
}
