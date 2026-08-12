package main

import (
	"io"
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
	return symbolsOfKind(t, kindExperimental, src)
}

func symbolsOfKind(t *testing.T, kind reportKind, src string) []string {
	t.Helper()
	entries, err := scan(writePackage(t, src), "example.com/pkg", kind)
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
`), "example.com/pkg", kindExperimental)
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
`), "example.com/pkg", kindExperimental)
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
	entries, err := scan(root, "example.com/pkg", kindExperimental)
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
	entries, err := scan(root, "example.com/pkg", kindExperimental)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want none from a test file", entries)
	}
}

func TestCheck_ReportsAddedAndRemovedSymbols(t *testing.T) {
	t.Parallel()

	recorded := render(kindExperimental, []entry{
		{ImportPath: "example.com/pkg", Symbol: "Gone"},
		{ImportPath: "example.com/pkg", Symbol: "Kept"},
	})
	path := filepath.Join(t.TempDir(), "experimental.txt")
	if err := os.WriteFile(path, []byte(recorded), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	current := render(kindExperimental, []entry{
		{ImportPath: "example.com/pkg", Symbol: "Fresh"},
		{ImportPath: "example.com/pkg", Symbol: "Kept"},
	})
	err := check(path, current, kindExperimental)
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

	report := render(kindExperimental, []entry{{ImportPath: "example.com/pkg", Symbol: "Kept"}})
	path := filepath.Join(t.TempDir(), "experimental.txt")
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := check(path, report, kindExperimental); err != nil {
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

// A struct field is a public surface of its own and the markers on this
// repository's configuration structs sit on fields rather than on the
// enclosing type. Both kinds descend, so neither can develop a blind spot
// the other does not have.
func TestScan_CollectsAMarkedStructField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		kind   reportKind
		marker string
	}{
		{name: "experimental", kind: kindExperimental, marker: "Experimental: the field may change."},
		{name: "stable", kind: kindStable, marker: "Stable since v1.0."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := symbolsOfKind(t, tc.kind, `package pkg

// Config configures a thing.
type Config struct {
	// Knob tunes the thing.
	//
	// `+tc.marker+`
	Knob string

	// Settled is documented but not marked.
	Settled string

	// hidden cannot be part of the public surface even when marked.
	//
	// `+tc.marker+`
	hidden string
}

// unexportedConfig is not public, so neither are its fields.
type unexportedConfig struct {
	// Knob tunes the thing.
	//
	// `+tc.marker+`
	Knob string
}
`)

			if len(got) != 1 || got[0] != "Config.Knob" {
				t.Errorf("symbols = %v, want [Config.Knob]", got)
			}
		})
	}
}

// A field's marker is sometimes written sideways as the trailing comment.
func TestScan_ReadsAFieldsTrailingComment(t *testing.T) {
	t.Parallel()

	got := symbolsOfKind(t, kindStable, `package pkg

// Config configures a thing.
type Config struct {
	Knob string // Stable since v1.0.
}
`)

	if len(got) != 1 || got[0] != "Config.Knob" {
		t.Errorf("symbols = %v, want [Config.Knob]", got)
	}
}

func TestScan_RecordsTheVersionOfAStableMarker(t *testing.T) {
	t.Parallel()

	entries, err := scan(writePackage(t, `package pkg

// WithThing configures a thing.
//
// Stable since v1.0.
func WithThing() {}

// WithLater configures a later thing.
//
// Stable since v1.1. The option gained a second form in v1.2, which does
// not move the date its contract froze.
func WithLater() {}
`), "example.com/pkg", kindStable)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := []entry{
		{ImportPath: "example.com/pkg", Symbol: "WithLater", Version: "v1.1"},
		{ImportPath: "example.com/pkg", Symbol: "WithThing", Version: "v1.0"},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	for i, e := range entries {
		if e != want[i] {
			t.Errorf("entries[%d] = %v, want %v", i, e, want[i])
		}
	}
}

// The version is the whole content of the marker, so a marker that does not
// carry one is malformed rather than ignored.
func TestScan_RejectsAMalformedStableMarker(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		marker string
	}{
		{name: "no version", marker: "Stable since."},
		{name: "no v prefix", marker: "Stable since 1.0."},
		{name: "major only", marker: "Stable since v1."},
		{name: "patch component", marker: "Stable since v1.0.3."},
		{name: "version on the next line", marker: "Stable since\n// v1.0."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := scan(writePackage(t, `package pkg

// WithThing configures a thing.
//
// `+tc.marker+`
func WithThing() {}
`), "example.com/pkg", kindStable)
			if err == nil {
				t.Fatal("expected an error for a malformed marker")
			}
			if !strings.Contains(err.Error(), "WithThing") ||
				!strings.Contains(err.Error(), "api.go:") {
				t.Errorf("err = %v, want it to name the symbol and its file:line", err)
			}
		})
	}
}

// writeStableReport lays down a checked-in baseline to enforce against.
func writeStableReport(t *testing.T, entries []entry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stability.txt")
	if err := os.WriteFile(path, []byte(render(kindStable, entries)), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return path
}

// Rewriting a recorded version makes the godoc claim a contract for a
// release that shipped without it. There is no escape hatch for this one.
func TestCheckHistory_RejectsARewrittenVersion(t *testing.T) {
	t.Parallel()

	path := writeStableReport(t, []entry{
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	})
	current := []entry{{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.1"}}

	for _, allowBackfill := range []bool{false, true} {
		err := checkHistory(path, current, allowBackfill)
		if err == nil {
			t.Fatalf("allowBackfill=%v: expected the rewritten version to be rejected", allowBackfill)
		}
		for _, want := range []string{"Thing", "recorded v1.0", "godoc now says v1.1"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("allowBackfill=%v: err = %v, want it to contain %q", allowBackfill, err, want)
			}
		}
	}
}

// The baseline enumerates what a release marked, so a symbol absent from it
// cannot have shipped marked in that release.
func TestCheckHistory_RejectsANewSymbolClaimingAnEnumeratedVersion(t *testing.T) {
	t.Parallel()

	path := writeStableReport(t, []entry{
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	})
	current := []entry{
		{ImportPath: "example.com/pkg", Symbol: "Fresh", Version: "v1.0"},
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	}

	err := checkHistory(path, current, false)
	if err == nil {
		t.Fatal("expected the back-dated claim to be rejected")
	}
	for _, want := range []string{"Fresh", "claims v1.0", "already enumerates"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "Thing") {
		t.Errorf("err = %v, want it to leave the unchanged row alone", err)
	}
}

// The ordinary case: the release being prepared is not yet in the report, so
// every symbol it marks is new under a version nothing else claims.
func TestCheckHistory_AllowsANewSymbolUnderAnUnseenVersion(t *testing.T) {
	t.Parallel()

	path := writeStableReport(t, []entry{
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	})
	current := []entry{
		{ImportPath: "example.com/pkg", Symbol: "Fresh", Version: "v1.2"},
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	}
	if err := checkHistory(path, current, false); err != nil {
		t.Errorf("checkHistory: %v", err)
	}
}

// Marking a symbol that genuinely shipped unmarked is legitimate — the
// convention is sparse — so the back-dated claim has an opt-in. Rewriting a
// recorded version does not, which is the asymmetry the flag documents.
func TestCheckHistory_BackfillAdmitsANewRowOnly(t *testing.T) {
	t.Parallel()

	path := writeStableReport(t, []entry{
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	})
	backdated := []entry{
		{ImportPath: "example.com/pkg", Symbol: "Fresh", Version: "v1.0"},
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	}
	if err := checkHistory(path, backdated, true); err != nil {
		t.Errorf("backfill of a new row: %v", err)
	}

	rewritten := []entry{{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.1"}}
	if err := checkHistory(path, rewritten, true); err == nil {
		t.Error("expected backfill to leave the rewritten version rejected")
	}
}

// The first write of a report has nothing to contradict.
func TestCheckHistory_AcceptsAMissingBaseline(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stability.txt")
	current := []entry{{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"}}
	if err := checkHistory(path, current, false); err != nil {
		t.Errorf("checkHistory on a missing baseline: %v", err)
	}
}

// The invariants gate -write as well as -check. Enforcing them only on the
// check would let a regeneration launder a bad marker into the baseline,
// after which every later check agrees with it.
func TestRun_EnforcesTheInvariantsOnWrite(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		baseline []entry
		src      string
		want     string
	}{
		{
			name: "rewritten version",
			baseline: []entry{
				{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
			},
			src: `package pkg

// Thing does a thing.
//
// Stable since v1.1.
type Thing struct{}
`,
			want: "recorded v1.0",
		},
		{
			name: "new symbol claiming an enumerated version",
			baseline: []entry{
				{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
			},
			src: `package pkg

// Thing does a thing.
//
// Stable since v1.0.
type Thing struct{}

// Fresh does a fresh thing.
//
// Stable since v1.0.
type Fresh struct{}
`,
			want: "already enumerates",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := writeStableReport(t, tc.baseline)
			before, err := os.ReadFile(path) //nolint:gosec // path comes from writeStableReport(t.TempDir).
			if err != nil {
				t.Fatalf("read baseline: %v", err)
			}
			err = run(config{
				root:   writePackage(t, tc.src),
				module: "example.com/pkg",
				kind:   kindStable,
				write:  path,
				out:    io.Discard,
			})
			if err == nil {
				t.Fatal("expected the write to be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
			after, err := os.ReadFile(path) //nolint:gosec // path comes from writeStableReport(t.TempDir).
			if err != nil {
				t.Fatalf("read baseline: %v", err)
			}
			if string(after) != string(before) {
				t.Error("the refused write still replaced the report")
			}
		})
	}
}

func TestRun_WritesAConformingStableReport(t *testing.T) {
	t.Parallel()

	path := writeStableReport(t, []entry{
		{ImportPath: "example.com/pkg", Symbol: "Thing", Version: "v1.0"},
	})
	err := run(config{
		root: writePackage(t, `package pkg

// Thing does a thing.
//
// Stable since v1.0.
type Thing struct{}

// Fresh does a fresh thing.
//
// Stable since v1.2.
type Fresh struct{}
`),
		module: "example.com/pkg",
		kind:   kindStable,
		write:  path,
		out:    io.Discard,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // path comes from writeStableReport(t.TempDir).
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	for _, want := range []string{"example.com/pkg\tFresh\tv1.2", "example.com/pkg\tThing\tv1.0"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("report = %q, want it to contain %q", got, want)
		}
	}
}

// -allow-backfill is a statement about the stable report's history; asking
// for it on the other kind is a mistake worth naming rather than ignoring.
func TestRun_RejectsBackfillOnTheExperimentalKind(t *testing.T) {
	t.Parallel()

	err := run(config{
		root:          writePackage(t, "package pkg\n"),
		module:        "example.com/pkg",
		kind:          kindExperimental,
		allowBackfill: true,
		out:           io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "-allow-backfill") {
		t.Errorf("err = %v, want it to reject -allow-backfill", err)
	}
}
