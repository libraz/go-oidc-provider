package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePackage lays out a one-file package under dir and returns the root to
// scan. Each case supplies its own source so the fixtures stay next to the
// behaviour they pin.
func writePackage(t *testing.T, src string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "api.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return root
}

func symbolsOf(t *testing.T, src string) []string {
	t.Helper()
	entries, err := scan(writePackage(t, src), "example.com/pkg")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Symbol)
	}
	return got
}

func TestScan_CollectsMarkedSymbolsAcrossDeclarationForms(t *testing.T) {
	t.Parallel()

	got := symbolsOf(t, `package pkg

// WithThing configures a thing.
//
// Experimental: the option may change before the next major release.
func WithThing() {}

// Settled is documented but not marked.
func Settled() {}

// Knob is a tuning knob.
//
// Experimental: the field set is still moving.
type Knob struct{}

// Mode selects behaviour.
//
// Experimental: the constant set is still moving.
const Mode = "mode"

// Apply applies the knob.
//
// Experimental: the receiver contract is still moving.
func (Knob) Apply() {}

// apply is unexported and cannot be part of the public surface even when
// the marker is present.
//
// Experimental: not public.
func apply() {}
`)

	want := []string{"Knob", "Knob.Apply", "Mode", "WithThing"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("symbols = %v, want %v", got, want)
	}
}

// The marker's rationale routinely wraps onto following lines, so a bare
// first line is not by itself malformed.
func TestScan_AcceptsRationaleContinuedOnTheNextLine(t *testing.T) {
	t.Parallel()

	got := symbolsOf(t, `package pkg

// WithThing configures a thing.
//
// Experimental:
// the option may change before the next major release.
func WithThing() {}
`)

	if len(got) != 1 || got[0] != "WithThing" {
		t.Errorf("symbols = %v, want [WithThing]", got)
	}
}

func TestScan_RejectsMarkerWithoutRationale(t *testing.T) {
	t.Parallel()

	_, err := scan(writePackage(t, `package pkg

// WithThing configures a thing.
//
// Experimental:
func WithThing() {}
`), "example.com/pkg")
	if err == nil {
		t.Fatal("expected an error for a marker with no rationale")
	}
	if !strings.Contains(err.Error(), "no rationale") {
		t.Errorf("err = %v, want it to mention the missing rationale", err)
	}
}

// A symbol cannot be both exempt and covered; saying so is a documentation
// bug that would otherwise silently resolve in the exempt direction.
func TestScan_RejectsContradictoryMarkers(t *testing.T) {
	t.Parallel()

	_, err := scan(writePackage(t, `package pkg

// WithThing configures a thing.
//
// Stable since v1.0.
//
// Experimental: the option may change.
func WithThing() {}
`), "example.com/pkg")
	if err == nil {
		t.Fatal("expected an error for contradictory markers")
	}
	if !strings.Contains(err.Error(), "carries both") {
		t.Errorf("err = %v, want it to report the contradiction", err)
	}
}

// A package can declare its whole surface exempt. The report has to be able
// to say so, because its contract is that anything absent is stable.
func TestScan_CollectsAPackageScopedMarker(t *testing.T) {
	t.Parallel()

	got := symbolsOf(t, `// Package pkg does a thing.
//
// # Status
//
// Experimental: the whole surface is still moving.
package pkg

// Settled is documented but not marked.
func Settled() {}
`)

	if len(got) != 1 || got[0] != packageSymbol {
		t.Errorf("symbols = %v, want [%s]", got, packageSymbol)
	}
}

// The convention is described in prose in the very kind of doc comment the
// scan now reads. Matching that sentence would exempt the entire public API
// from the SemVer promise while the report still looked generated.
func TestScan_IgnoresTheConventionDescribedInProse(t *testing.T) {
	t.Parallel()

	got := symbolsOf(t, `// Package pkg does a thing.
//
// # Status
//
// The public API follows Semantic Versioning. There is one exemption: a
// symbol whose godoc begins with "Experimental:" may change in a minor
// release, and the complete set is generated from those markers.
package pkg

// Settled is documented but not marked.
func Settled() {}
`)

	if len(got) != 0 {
		t.Errorf("symbols = %v, want none; the marker is named, not applied", got)
	}
}

// Same rule on a declaration: naming the marker mid-sentence is not
// claiming it.
func TestScan_IgnoresAMarkerThatDoesNotBeginALine(t *testing.T) {
	t.Parallel()

	got := symbolsOf(t, `package pkg

// WithThing configures a thing. It is not marked "Experimental:" because
// its shape is settled.
func WithThing() {}
`)

	if len(got) != 0 {
		t.Errorf("symbols = %v, want none", got)
	}
}

// A package comment may legally appear in more than one file. The report
// must depend on the markers, not on how the package is split up.
func TestScan_EmitsThePackageRowOnce(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	src := `// Package pkg does a thing.
//
// Experimental: the whole surface is still moving.
package pkg
`
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	entries, err := scan(root, "example.com/pkg")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("entries = %v, want a single package row", entries)
	}
}

func TestScan_SkipsTestFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	src := `package pkg

// WithThing configures a thing.
//
// Experimental: the option may change.
func WithThing() {}
`
	if err := os.WriteFile(filepath.Join(root, "api_test.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	entries, err := scan(root, "example.com/pkg")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want none from a test file", entries)
	}
}

func TestCheck_ReportsAddedAndRemovedSymbols(t *testing.T) {
	t.Parallel()

	recorded := render([]entry{
		{ImportPath: "example.com/pkg", Symbol: "Gone"},
		{ImportPath: "example.com/pkg", Symbol: "Kept"},
	})
	path := filepath.Join(t.TempDir(), "experimental.txt")
	if err := os.WriteFile(path, []byte(recorded), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	current := render([]entry{
		{ImportPath: "example.com/pkg", Symbol: "Fresh"},
		{ImportPath: "example.com/pkg", Symbol: "Kept"},
	})
	err := check(path, current)
	if err == nil {
		t.Fatal("expected drift to be reported")
	}
	for _, want := range []string{"+ example.com/pkg\tFresh", "- example.com/pkg\tGone"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
}

func TestCheck_PassesOnIdenticalReport(t *testing.T) {
	t.Parallel()

	report := render([]entry{{ImportPath: "example.com/pkg", Symbol: "Kept"}})
	path := filepath.Join(t.TempDir(), "experimental.txt")
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := check(path, report); err != nil {
		t.Errorf("check on an identical report: %v", err)
	}
}

// The header is prose and gets reworded; only the symbol lines are the
// contract, so a header edit must not read as an API change.
func TestParseReport_IgnoresTheHeader(t *testing.T) {
	t.Parallel()

	got := parseReport("# something\n# else\nexample.com/pkg\tKept\n")
	if len(got) != 1 || got[0] != "example.com/pkg\tKept" {
		t.Errorf("parseReport = %q, want just the symbol line", got)
	}
}
