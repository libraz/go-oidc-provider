package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree materialises files under a temp root. Keys are
// slash-separated repository-relative paths.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

// loadFrom writes a map to a temp tree and loads it, failing the test on
// a parse error the case did not expect.
func loadFrom(t *testing.T, root, body string) *Map {
	t.Helper()
	path := filepath.Join(root, "gates.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write map: %v", err)
	}
	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m
}

// findingsFor collects the messages of findings from one check.
func findingsFor(findings []Finding, check string) []string {
	var out []string
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f.Message)
		}
	}
	return out
}

// TestCheckExercisedFlagsAStaticOnlySurface is the case this gate
// exists for. A surface every gate merely compiles is one nothing runs,
// and a defect in it survives a green tree — which is how a live
// multi-account defect coexisted with a passing conformance suite.
func TestCheckExercisedFlagsAStaticOnlySurface(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	m := loadFrom(t, root, `
surfaces:
  - id: lonely
    title: Lonely surface
    paths: [x]
gates:
  - id: lint
    in_verify: true
    level: static
    answers: Whether the linter is happy.
    blind_to: [behaviour]
    drives: [lonely]
`)
	got := findingsFor(checkExercised(m), "unexercised")
	if len(got) != 1 {
		t.Fatalf("checkExercised returned %d findings %v, want exactly 1", len(got), got)
	}
	if !strings.Contains(got[0], "only reached by static-level gates") {
		t.Errorf("finding does not name the static-only condition: %q", got[0])
	}
}

// TestCheckExercisedAcceptsARecordedReason keeps the gate usable: an
// unexercised surface may be a deliberate decision, but it has to be
// written down where a reviewer sees it.
func TestCheckExercisedAcceptsARecordedReason(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	m := loadFrom(t, root, `
surfaces:
  - id: lonely
    title: Lonely surface
    paths: [x]
    static_only_reason: Nothing can boot it in CI.
gates:
  - id: lint
    in_verify: true
    level: static
    answers: Whether the linter is happy.
    blind_to: [behaviour]
    drives: [lonely]
`)
	if got := checkExercised(m); len(got) != 0 {
		t.Errorf("a recorded reason should silence the check, got %v", got)
	}
}

// TestCheckExercisedRejectsAStaleExemption closes the other direction.
// An exemption that outlives the hole it described is a false claim
// about the tree, and the next reader treats it as still true.
func TestCheckExercisedRejectsAStaleExemption(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	m := loadFrom(t, root, `
surfaces:
  - id: covered
    title: Covered surface
    paths: [x]
    static_only_reason: Nothing can boot it in CI.
gates:
  - id: harness
    in_verify: false
    level: integration
    answers: Whether it boots.
    blind_to: [rendering]
    drives: [covered]
`)
	got := findingsFor(checkExercised(m), "unexercised")
	if len(got) != 1 {
		t.Fatalf("checkExercised returned %d findings %v, want exactly 1", len(got), got)
	}
	if !strings.Contains(got[0], "drop the exemption") {
		t.Errorf("finding does not ask for the exemption to go: %q", got[0])
	}
}

// TestCheckExercisedFlagsAnUndrivenSurface covers the surface no gate
// mentions at all — the shape the reference application was in for
// twelve audits.
func TestCheckExercisedFlagsAnUndrivenSurface(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	m := loadFrom(t, root, `
surfaces:
  - id: orphan
    title: Orphan surface
    paths: [x]
  - id: seen
    title: Seen surface
    paths: [y]
gates:
  - id: harness
    in_verify: false
    level: integration
    answers: Whether it boots.
    blind_to: [rendering]
    drives: [seen]
`)
	got := findingsFor(checkExercised(m), "unexercised")
	if len(got) != 1 {
		t.Fatalf("checkExercised returned %d findings %v, want exactly 1", len(got), got)
	}
	if !strings.Contains(got[0], "no gate at all") {
		t.Errorf("finding does not name the undriven condition: %q", got[0])
	}
}

// TestCheckSurfacePathsFlagsAMovedPath keeps the map from decaying into
// prose about a tree that has moved on.
func TestCheckSurfacePathsFlagsAMovedPath(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{"internal/here/a.go": "package here\n"})
	m := loadFrom(t, root, `
surfaces:
  - id: here
    title: Here
    paths: [internal/here, internal/gone]
gates:
  - id: harness
    in_verify: false
    level: integration
    answers: Whether it boots.
    blind_to: [rendering]
    drives: [here]
`)
	got := findingsFor(checkSurfacePaths(root, m), "surface-paths")
	if len(got) != 1 {
		t.Fatalf("checkSurfacePaths returned %d findings %v, want exactly 1", len(got), got)
	}
	if !strings.Contains(got[0], "internal/gone") {
		t.Errorf("finding does not name the missing path: %q", got[0])
	}
}

// TestCheckMakefileFlagsAnUndeclaredGate is the drift check that keeps
// the map honest as gates are added: a new verification command that
// nobody described is exactly the state this whole file is a reaction
// to.
func TestCheckMakefileFlagsAnUndeclaredGate(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"x": "",
		"Makefile": "" +
			"declared:\n\t@scripts/declared.sh\n\n" +
			"surprise:\n\t@scripts/surprise.sh\n",
	})
	m := loadFrom(t, root, `
surfaces:
  - id: s
    title: S
    paths: [x]
gates:
  - id: declared
    target: declared
    in_verify: true
    level: integration
    answers: Whether the declared thing works.
    blind_to: [everything else]
    drives: [s]
`)
	got := findingsFor(checkMakefileTargets(root, m), "makefile")
	if len(got) != 1 {
		t.Fatalf("checkMakefileTargets returned %d findings %v, want exactly 1", len(got), got)
	}
	if !strings.Contains(got[0], `"surprise"`) {
		t.Errorf("finding does not name the undeclared target: %q", got[0])
	}
}

// TestCheckMakefileFlagsAStaleTarget covers the reverse: a gate whose
// target was renamed away still reads as covered until something looks.
func TestCheckMakefileFlagsAStaleTarget(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"x":        "",
		"Makefile": "kept:\n\t@scripts/kept.sh\n",
	})
	m := loadFrom(t, root, `
surfaces:
  - id: s
    title: S
    paths: [x]
gates:
  - id: kept
    target: kept
    in_verify: true
    level: integration
    answers: Whether the kept thing works.
    blind_to: [everything else]
    drives: [s]
  - id: renamed
    target: renamed-away
    in_verify: true
    level: integration
    answers: Whether the renamed thing works.
    blind_to: [everything else]
    drives: [s]
`)
	got := findingsFor(checkMakefileTargets(root, m), "makefile")
	if len(got) != 1 {
		t.Fatalf("checkMakefileTargets returned %d findings %v, want exactly 1", len(got), got)
	}
	if !strings.Contains(got[0], "renamed-away") {
		t.Errorf("finding does not name the stale target: %q", got[0])
	}
}

// TestCheckMakefileAcceptsATargetThatRunsNoScript keeps `vet`, which is
// a real gate invoking a bare command, from reading as stale.
func TestCheckMakefileAcceptsATargetThatRunsNoScript(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"x":        "",
		"Makefile": "vet:\n\tgo vet ./...\n",
	})
	m := loadFrom(t, root, `
surfaces:
  - id: s
    title: S
    paths: [x]
gates:
  - id: vet
    target: vet
    in_verify: true
    level: unit
    answers: Whether vet is happy.
    blind_to: [logic]
    drives: [s]
`)
	if got := checkMakefileTargets(root, m); len(got) != 0 {
		t.Errorf("a script-free target should not read as stale, got %v", got)
	}
}

// TestLoadRejectsADriveOnAnUndeclaredSurface stops a typo from silently
// shrinking what the map claims to cover.
func TestLoadRejectsADriveOnAnUndeclaredSurface(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "gates.yaml")
	body := `
surfaces:
  - id: real
    title: Real
    paths: [x]
gates:
  - id: g
    in_verify: true
    level: unit
    answers: Whether it works.
    blind_to: [nothing]
    drives: [typo]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write map: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted a drives entry naming no declared surface")
	}
	if !strings.Contains(err.Error(), "typo") {
		t.Errorf("error does not name the offending id: %v", err)
	}
}

// TestLoadRejectsAnUnknownField makes a misspelled key a failure rather
// than a silently ignored claim.
func TestLoadRejectsAnUnknownField(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "gates.yaml")
	body := `
surfaces:
  - id: real
    title: Real
    paths: [x]
    blind_spot: oops
gates:
  - id: g
    in_verify: true
    level: unit
    answers: Whether it works.
    blind_to: [nothing]
    drives: [real]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write map: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted an unknown field")
	}
}

// TestParseMakefileIgnoresVariablesAndPatternRules pins the parser
// against the constructs the real Makefile uses, so a false target name
// never turns into a spurious finding.
func TestParseMakefileIgnoresVariablesAndPatternRules(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"Makefile": "" +
			"SHELL := /usr/bin/env bash\n" +
			".PHONY: real other\n" +
			"EXAMPLE_SMOKE := 01-minimal 03-fapi2\n\n" +
			"real:\n\t@scripts/real.sh\n\n" +
			"define smoke_rule\n" +
			"example-$(word 1,$(subst -, ,$(1))):\n" +
			"\tcd examples/$(1) && go run .\n" +
			"endef\n\n" +
			"other:\n\tgo clean -testcache\n",
	})
	all, scripted, err := parseMakefile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("parseMakefile: %v", err)
	}
	for _, want := range []string{"real", "other"} {
		if !all[want] {
			t.Errorf("parseMakefile missed target %q; got %v", want, all)
		}
	}
	for _, unwanted := range []string{"SHELL", "EXAMPLE_SMOKE", ".PHONY"} {
		if all[unwanted] {
			t.Errorf("parseMakefile treated %q as a target", unwanted)
		}
	}
	if !scripted["real"] {
		t.Error("parseMakefile did not record that 'real' runs a script")
	}
	if scripted["other"] {
		t.Error("parseMakefile recorded a script for a target that runs none")
	}
}
