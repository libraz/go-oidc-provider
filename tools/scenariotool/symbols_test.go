package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// symbolFixtureSource is the Go tree the citation tests resolve
// against. It is deliberately tiny and self-contained: the point is to
// pin the resolver's rules, not to re-index the real repository.
const symbolFixtureSource = `package widget

// Knob is an exported type with an exported field and a method.
type Knob struct {
	Size int
	tag  string
}

// Adjust is a method on Knob.
func (k *Knob) Adjust(n int) {}

// Store is an interface, so its methods are citable as Store.Method.
type Store interface {
	Lookup(id string) (*Knob, error)
}

// WithKnob is an exported constructor-style function.
func WithKnob(k Knob) {}

// tighten is unexported: citable only in path-qualified form.
func tighten() {}

const (
	// ModeFast is declared inside a grouped const block.
	ModeFast = 1
	ModeSlow = 2
)
`

// writeSymbolFixture materialises a repository-shaped tree containing
// one package under pkg/widget plus a go.mod, and returns its root.
func writeSymbolFixture(tb testing.TB) string {
	tb.Helper()
	root := tb.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test\n\ngo 1.25\n"), 0o600); err != nil {
		tb.Fatalf("write go.mod: %v", err)
	}
	dir := filepath.Join(root, "pkg", "widget")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		tb.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "widget.go"), []byte(symbolFixtureSource), 0o600); err != nil {
		tb.Fatalf("write widget.go: %v", err)
	}
	// An external test package in the same directory must not mask the
	// real package name, and its declarations must not become citable.
	external := "package widget_test\n\nfunc HelperOnlyInTests() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "widget_test.go"), []byte(external), 0o600); err != nil {
		tb.Fatalf("write widget_test.go: %v", err)
	}
	return root
}

// TestSymbolIndex_ResolvesDeclarationShapes pins what the index counts
// as declared. The grouped const and the interface method are the two
// shapes a naive line-scanner misses, and a miss there would make the
// gate reject a citation that is perfectly correct.
func TestSymbolIndex_ResolvesDeclarationShapes(t *testing.T) {
	t.Parallel()

	ix, err := buildSymbolIndex(writeSymbolFixture(t))
	if err != nil {
		t.Fatalf("buildSymbolIndex: %v", err)
	}
	cases := []struct {
		name           string
		pkg, sym, memb string
		want           bool
	}{
		{"exported func by name", "widget", "WithKnob", "", true},
		{"exported type by name", "widget", "Knob", "", true},
		{"struct field", "widget", "Knob", "Size", true},
		{"method on pointer receiver", "widget", "Knob", "Adjust", true},
		{"interface method", "widget", "Store", "Lookup", true},
		{"grouped const", "widget", "ModeFast", "", true},
		{"unexported func, path-qualified", "pkg/widget", "tighten", "", true},
		{"path-qualified type", "pkg/widget", "Knob", "", true},
		{"absent symbol", "widget", "WithNoSuchKnob", "", false},
		{"absent field", "widget", "Knob", "Colour", false},
		{"test-only symbol is not citable", "widget", "HelperOnlyInTests", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ix.resolve(tc.pkg, tc.sym, tc.memb); got != tc.want {
				t.Errorf("resolve(%q,%q,%q) = %v, want %v", tc.pkg, tc.sym, tc.memb, got, tc.want)
			}
		})
	}
}

// TestValidate_RejectsUnresolvableSymbolCitation is the gate itself: a
// row whose prose cites a symbol this tree does not declare must fail
// validation. Without it the catalog can keep asserting that an option
// exists long after it was renamed, which is exactly how an
// out-of-scope claim stops being auditable.
func TestValidate_RejectsUnresolvableSymbolCitation(t *testing.T) {
	t.Parallel()

	root := writeSymbolFixture(t)
	catalog := writeCatalog(t, map[string]string{"alpha.yaml": `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
rows:
  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: does the thing
    status: out-of-scope
    out_of_scope_reason: "the tree exposes no widget.WithNoSuchKnob option"
`})

	problems := validationProblems(t, catalog, ValidationOptions{SourceRoot: root})
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly 1", problems)
	}
	if !strings.Contains(problems[0], "widget.WithNoSuchKnob") {
		t.Errorf("problem %q does not name the unresolvable citation", problems[0])
	}
	if !strings.Contains(problems[0], "AL-001") {
		t.Errorf("problem %q does not name the offending row", problems[0])
	}
}

// TestValidate_RejectsLineNumberCitation keeps the cleanup from being
// a one-off. A "file.go:123" reference cannot be resolved — only
// re-checked by hand, which is what stopped happening — so the gate
// refuses the shape outright rather than trying to follow it.
func TestValidate_RejectsLineNumberCitation(t *testing.T) {
	t.Parallel()

	root := writeSymbolFixture(t)
	catalog := writeCatalog(t, map[string]string{"alpha.yaml": `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
rows:
  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: the guard lives at pkg/widget/widget.go:42 and rejects it
    status: active
`})

	problems := validationProblems(t, catalog, ValidationOptions{SourceRoot: root})
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly 1", problems)
	}
	if !strings.Contains(problems[0], "widget.go:42") {
		t.Errorf("problem %q does not name the line citation", problems[0])
	}
	if !strings.Contains(problems[0], "package.Symbol") {
		t.Errorf("problem %q does not say what to write instead", problems[0])
	}
}

// TestValidate_AcceptsResolvableAndNonCitationProse pins the other
// half: real citations pass, and the shapes that merely look like
// citations are left alone. Audit event names (`grant.error`) and file
// references are quoted throughout the catalog, and a gate that
// tripped on them would be turned off within a day.
func TestValidate_AcceptsResolvableAndNonCitationProse(t *testing.T) {
	t.Parallel()

	root := writeSymbolFixture(t)
	catalog := writeCatalog(t, map[string]string{"alpha.yaml": `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
rows:
  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: |
      widget.WithKnob configures it; widget.Knob.Size is the field and
      pkg/widget.tighten is the unexported helper. The emitted audit
      event is grant.error and the handler lives in pkg/widget/widget.go.
      Unrelated packages are not this gate's business: time.Second,
      http.StatusOK, some.host.invalid.
    status: active
`})

	if problems := validationProblems(t, catalog, ValidationOptions{SourceRoot: root}); len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
}

// TestValidate_SkipsCitationCheckOnlyWhenExplicitlyOptedOut pins both
// halves of the opt-out.
//
// A caller with no tree to resolve against — `flip`, re-reading what it
// just wrote — must be able to run the structural rules without failing
// on an empty index. That is why the opt-out exists, and it is not a
// reason to let a missing root mean the same thing: the two are the
// same input and only one of them is deliberate. A caller that lost its
// root would otherwise disable the check and report a catalog it
// resolved not one citation in, which is the failure this check was
// written to catch, one layer up.
func TestValidate_SkipsCitationCheckOnlyWhenExplicitlyOptedOut(t *testing.T) {
	t.Parallel()

	dir := writeCatalog(t, map[string]string{"alpha.yaml": `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
rows:
  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: cites widget.WithNoSuchKnob which does not exist
    status: active
`})

	if problems := validationProblems(t, dir, ValidationOptions{SkipSymbolCitations: true}); len(problems) != 0 {
		t.Fatalf("problems = %v, want none when the check is opted out", problems)
	}

	cat, err := loadCatalog(dir)
	if err != nil {
		t.Fatalf("loadCatalog: %v", err)
	}
	err = cat.Validate(ValidationOptions{})
	if err == nil {
		t.Fatal("validation passed with neither a source root nor the opt-out: " +
			"a caller that lost its root would report the catalog clean without resolving a citation")
	}
	if !strings.Contains(err.Error(), "SkipSymbolCitations") {
		t.Errorf("err = %v, want it to name the deliberate way to disable the check", err)
	}
}

// TestValidate_FailsWhenTheSourceScanFindsNoDeclarations covers the
// other end of the same ambiguity: a root that exists but holds no Go
// source resolves every citation to "not a claim about this
// repository", so the catalog comes back clean having been checked
// against nothing.
func TestValidate_FailsWhenTheSourceScanFindsNoDeclarations(t *testing.T) {
	t.Parallel()

	dir := writeCatalog(t, map[string]string{"alpha.yaml": `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
rows:
  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: cites widget.WithNoSuchKnob which does not exist
    status: active
`})
	cat, err := loadCatalog(dir)
	if err != nil {
		t.Fatalf("loadCatalog: %v", err)
	}

	err = cat.Validate(ValidationOptions{SourceRoot: t.TempDir()})
	if err == nil {
		t.Fatal("validation passed against a tree with no declarations: " +
			"the row cites a symbol nothing declares and the gate reported it clean")
	}
	if !strings.Contains(err.Error(), "no Go declarations") {
		t.Errorf("err = %v, want the empty scan reported as a breakage", err)
	}
}

// TestRunValidate_RequiresACatalogDirThatReducesToARepoRoot drives the
// production entry point, because that is where the root is derived
// rather than supplied: the derivation used to fall back to the working
// directory, which from the wrapper is the tool's own module. The
// citation check then ran against an index describing the tool, dropped
// every citation naming the repository under test, and passed.
func TestRunValidate_RequiresACatalogDirThatReducesToARepoRoot(t *testing.T) {
	t.Parallel()

	root := writeSymbolFixture(t)
	rows := `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
rows:
  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: widget.WithKnob configures it
    status: active
`
	// The control: a catalog sitting where the tool expects it validates
	// against the tree above it, so a failure below is the derivation and
	// not the fixture.
	placed := filepath.Join(root, "test", "scenarios", "catalog")
	if err := os.MkdirAll(placed, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(placed, "alpha.yaml"), []byte(rows), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := runValidate(placed, false); err != nil {
		t.Fatalf("runValidate on a correctly placed catalog: %v", err)
	}

	// And it resolves against that tree rather than merely reaching it:
	// the same row citing a symbol the fixture does not declare has to
	// fail. Without this the case above would pass just as well with the
	// check disabled.
	rotted := strings.Replace(rows, "widget.WithKnob", "widget.WithNoSuchKnob", 1)
	if err := os.WriteFile(filepath.Join(placed, "alpha.yaml"), []byte(rotted), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := runValidate(placed, false)
	if err == nil {
		t.Fatal("runValidate passed a row citing a symbol the tree does not declare")
	}
	if !strings.Contains(err.Error(), "widget.WithNoSuchKnob") {
		t.Errorf("err = %v, want the unresolvable citation named", err)
	}

	// The same catalog somewhere the derivation cannot reduce.
	stray := writeCatalog(t, map[string]string{"alpha.yaml": rows})
	err = runValidate(stray, false)
	if err == nil {
		t.Fatal("runValidate passed with no resolvable repository root: " +
			"the citation check would be off and nothing would say so")
	}
	if !strings.Contains(err.Error(), "citation check has no tree") {
		t.Errorf("err = %v, want the unresolvable root named as the reason", err)
	}
}
