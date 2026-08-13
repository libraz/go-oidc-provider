package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validFeatureFile is the smallest catalog file that satisfies every
// invariant Catalog.Validate enforces. Each case below mutates exactly
// one aspect of it, so the expected problem list isolates one rule.
const validFeatureFile = `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
rows:
  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: does the thing
    status: active
`

// writeCatalog materialises files (name -> body) into a fresh temp
// directory and returns its path.
func writeCatalog(tb testing.TB, files map[string]string) string {
	tb.Helper()
	dir := tb.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			tb.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// validationProblems loads the catalog in dir, validates it, and splits
// the aggregated error back into the individual problem strings. The
// header is asserted here so the reported issue count stays pinned
// alongside the messages themselves.
func validationProblems(tb testing.TB, dir string, opts ValidationOptions) []string {
	tb.Helper()
	cat, err := loadCatalog(dir)
	if err != nil {
		tb.Fatalf("loadCatalog: %v", err)
	}
	err = cat.Validate(opts)
	if err == nil {
		return nil
	}
	head, body, ok := strings.Cut(err.Error(), ":\n  ")
	if !ok {
		tb.Fatalf("unexpected error shape: %v", err)
	}
	problems := strings.Split(body, "\n  ")
	if want := fmt.Sprintf("catalog validation failed (%d issue(s))", len(problems)); head != want {
		tb.Errorf("error header = %q, want %q", head, want)
	}
	return problems
}

// assertProblems compares the produced problem list against the exact
// expected list. Order is significant: Validate sorts its output, so a
// mismatch here also catches a lost or duplicated message.
func assertProblems(tb testing.TB, got, want []string) {
	tb.Helper()
	if len(got) != len(want) {
		tb.Fatalf("got %d problem(s):\n  %s\nwant %d:\n  %s",
			len(got), strings.Join(got, "\n  "), len(want), strings.Join(want, "\n  "))
	}
	for i := range want {
		if got[i] != want[i] {
			tb.Errorf("problem[%d] =\n  %s\nwant\n  %s", i, got[i], want[i])
		}
	}
}

// replaceOnce is a readability shim over strings.Replace that fails the
// test when the fixture text it targets is not present, so a fixture
// edit cannot silently turn a case into a no-op.
func replaceOnce(tb testing.TB, s, old, replacement string) string {
	tb.Helper()
	if !strings.Contains(s, old) {
		tb.Fatalf("fixture does not contain %q", old)
	}
	return strings.Replace(s, old, replacement, 1)
}

// TestCatalogValidate pins one rule per case. Catalog.Validate is the
// gate the whole scenario catalog rests on: a rule that stops being
// checked removes detection power without anything turning red, so
// every invariant is asserted by its exact message here.
func TestCatalogValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		files func(tb testing.TB) map[string]string
		opts  ValidationOptions
		want  func(dir string) []string
	}{
		{
			name: "valid catalog produces no problems",
			files: func(testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": validFeatureFile}
			},
			want: func(string) []string { return nil },
		},
		{
			name: "missing feature",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "feature: alpha\n", "")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ": missing required field 'feature'"}
			},
		},
		{
			name: "feature violates the slug pattern",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "feature: alpha", "feature: Alpha")}
			},
			want: func(dir string) []string {
				return []string{fmt.Sprintf(`%s: feature "Alpha" must match %s`, filepath.Join(dir, "alpha.yaml"), featurePattern)}
			},
		},
		{
			name: "feature does not match the filename",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "feature: alpha", "feature: beta")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + `: feature "beta" must equal filename "alpha"`}
			},
		},
		{
			name: "missing prefix",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "prefix: AL\n", "")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ": missing required field 'prefix'"}
			},
		},
		{
			name: "prefix violates the pattern and no longer matches its rows",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "prefix: AL", "prefix: al")}
			},
			want: func(dir string) []string {
				path := filepath.Join(dir, "alpha.yaml")
				return []string{
					path + ` rows[0] (AL-001): id "AL-001" must start with file prefix "al-"`,
					fmt.Sprintf(`%s: prefix "al" must match %s`, path, prefixPattern),
				}
			},
		},
		{
			name: "prefix reused by a second file",
			files: func(testing.TB) map[string]string {
				return map[string]string{
					"alpha.yaml": validFeatureFile,
					"beta.yaml": `feature: beta
prefix: AL
title: Beta
specs:
  - Spec B
rows:
  - id: AL-002
    severity: P0
    spec: RFC 1 section 2
    behaviour: does the other thing
    status: active
`,
				}
			},
			want: func(dir string) []string {
				return []string{fmt.Sprintf(`%s: prefix "AL" already used by %s`,
					filepath.Join(dir, "beta.yaml"), filepath.Join(dir, "alpha.yaml"))}
			},
		},
		{
			name: "missing title",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "title: Alpha\n", "")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ": missing required field 'title'"}
			},
		},
		{
			name: "no specs",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "specs:\n  - Spec A\n", "")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ": 'specs' MUST have at least one entry"}
			},
		},
		{
			name: "no rows",
			files: func(testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": `feature: alpha
prefix: AL
title: Alpha
specs:
  - Spec A
`}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ": 'rows' MUST have at least one entry"}
			},
		},
		{
			name: "row without an id",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb,
					validFeatureFile, "  - id: AL-001\n    severity: P0\n", "  - severity: P0\n")}
			},
			want: func(dir string) []string {
				// The severity key becomes the list-item anchor, so the
				// row keeps its shape while losing only the id.
				return []string{filepath.Join(dir, "alpha.yaml") + " rows[0] (): missing 'id'"}
			},
		},
		{
			name: "row id violates the pattern",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "id: AL-001", "id: al-001")}
			},
			want: func(dir string) []string {
				return []string{fmt.Sprintf(`%s rows[0] (al-001): id "al-001" must match %s`,
					filepath.Join(dir, "alpha.yaml"), rowIDPattern)}
			},
		},
		{
			name: "row id does not carry the file prefix",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "id: AL-001", "id: ZZ-001")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ` rows[0] (ZZ-001): id "ZZ-001" must start with file prefix "AL-"`}
			},
		},
		{
			name: "duplicate row id",
			files: func(tb testing.TB) map[string]string {
				dup := `  - id: AL-001
    severity: P1
    spec: RFC 1 section 2
    behaviour: does the thing twice
    status: active
`
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "rows:\n", "rows:\n"+dup)}
			},
			want: func(dir string) []string {
				path := filepath.Join(dir, "alpha.yaml")
				return []string{fmt.Sprintf(`%s rows[1] (AL-001): id "AL-001" already declared in %s`, path, path)}
			},
		},
		{
			name: "severity outside the enum",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "severity: P0", "severity: P9")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ` rows[0] (AL-001): severity "P9" must be one of P0|P1|P2`}
			},
		},
		{
			name: "blank spec",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "spec: RFC 1 section 1", `spec: "   "`)}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + " rows[0] (AL-001): 'spec' MUST be non-empty"}
			},
		},
		{
			name: "blank behaviour",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "behaviour: does the thing", `behaviour: "   "`)}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + " rows[0] (AL-001): 'behaviour' MUST be non-empty"}
			},
		},
		{
			name: "status outside the enum",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "status: active", "status: bogus")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ` rows[0] (AL-001): status "bogus" must be active|pending|out-of-scope`}
			},
		},
		{
			name: "omitted status defaults to pending and is accepted",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "    status: active\n", "")}
			},
			want: func(string) []string { return nil },
		},
		{
			name: "out-of-scope without a reason",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile, "status: active", "status: out-of-scope")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + " rows[0] (AL-001): status=out-of-scope requires 'out_of_scope_reason'"}
			},
		},
		{
			name: "reason on a row that is not out-of-scope",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: active\n    out_of_scope_reason: embedder concern\n")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + " rows[0] (AL-001): 'out_of_scope_reason' is only valid when status=out-of-scope"}
			},
		},
		{
			name: "out-of-scope with a reason is accepted",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: out-of-scope\n    out_of_scope_reason: embedder concern\n")}
			},
			want: func(string) []string { return nil },
		},
		{
			name: "covered_by violates the shape",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: active\n    covered_by: bogus\n")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ` rows[0] (AL-001): covered_by "bogus" must be <package path>.<TestFunc>, e.g. internal/authorizeendpoint.TestAuthorize_MaxAge`}
			},
		},
		{
			name: "covered_by on a row that is not active",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: pending\n    covered_by: internal/thing.TestResolves\n")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + " rows[0] (AL-001): covered_by is only valid when status=active (row is pending)"}
			},
		},
		{
			name: "covered_by on an active row is accepted",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: active\n    covered_by: internal/thing.TestResolves\n")}
			},
			want: func(string) []string { return nil },
		},
		{
			name: "cross_ref violates the shape",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: active\n    cross_refs: [nope]\n")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ` rows[0] (AL-001): cross_refs[0]="nope" must match <feature>#<ID>`}
			},
		},
		{
			name: "cross_ref points at an unknown ID",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: active\n    cross_refs: [beta#BE-001]\n")}
			},
			want: func(dir string) []string {
				return []string{filepath.Join(dir, "alpha.yaml") + ` rows (AL-001): cross_ref "beta#BE-001" points at unknown ID`}
			},
		},
		{
			name: "dangling cross_ref is tolerated under LenientCrossRefs",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{"alpha.yaml": replaceOnce(tb, validFeatureFile,
					"    status: active\n", "    status: active\n    cross_refs: [beta#BE-001]\n")}
			},
			opts: ValidationOptions{LenientCrossRefs: true},
			want: func(string) []string { return nil },
		},
		{
			name: "cross_ref that resolves is accepted",
			files: func(tb testing.TB) map[string]string {
				return map[string]string{
					"alpha.yaml": replaceOnce(tb, validFeatureFile,
						"    status: active\n", "    status: active\n    cross_refs: [beta#BE-001]\n"),
					"beta.yaml": `feature: beta
prefix: BE
title: Beta
specs:
  - Spec B
rows:
  - id: BE-001
    severity: P0
    spec: RFC 1 section 2
    behaviour: does the other thing
    status: active
`,
				}
			},
			want: func(string) []string { return nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := writeCatalog(t, tc.files(t))
			// Every case here exercises a structural rule against a
			// catalog with no Go tree beside it. The citation check has
			// its own tests and its own fixture tree, and Validate now
			// refuses to run without either a root or this opt-out.
			opts := tc.opts
			opts.SkipSymbolCitations = true
			assertProblems(t, validationProblems(t, dir, opts), tc.want(dir))
		})
	}
}

// TestCatalogValidate_ReportsEveryProblemAtOnce pins the aggregation
// contract: an operator running the gate has to see the whole list, not
// the first failure, or fixing a catalog becomes one round trip per
// mistake.
func TestCatalogValidate_ReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()
	dir := writeCatalog(t, map[string]string{"alpha.yaml": `feature: Alpha
prefix: al
rows:
  - id: bad-id
    severity: P9
    spec: ""
    behaviour: ""
    status: nope
    cross_refs: [broken]
`})
	path := filepath.Join(dir, "alpha.yaml")
	assertProblems(t, validationProblems(t, dir, ValidationOptions{SkipSymbolCitations: true}), []string{
		path + ` rows[0] (bad-id): 'behaviour' MUST be non-empty`,
		path + ` rows[0] (bad-id): 'spec' MUST be non-empty`,
		path + ` rows[0] (bad-id): cross_refs[0]="broken" must match <feature>#<ID>`,
		fmt.Sprintf(`%s rows[0] (bad-id): id "bad-id" must match %s`, path, rowIDPattern),
		path + ` rows[0] (bad-id): severity "P9" must be one of P0|P1|P2`,
		path + ` rows[0] (bad-id): status "nope" must be active|pending|out-of-scope`,
		path + `: 'specs' MUST have at least one entry`,
		fmt.Sprintf(`%s: feature "Alpha" must match %s`, path, featurePattern),
		path + `: missing required field 'title'`,
		fmt.Sprintf(`%s: prefix "al" must match %s`, path, prefixPattern),
	})
}

// TestCatalogValidate_RowIDIndexSpansFiles pins that ID uniqueness is a
// catalog-wide invariant rather than a per-file one: two feature files
// may not both declare the same row ID, because every cross-reference
// and every test binding resolves an ID against the whole catalog.
func TestCatalogValidate_RowIDIndexSpansFiles(t *testing.T) {
	t.Parallel()
	shared := `  - id: AL-001
    severity: P0
    spec: RFC 1 section 1
    behaviour: does the thing
    status: active
`
	dir := writeCatalog(t, map[string]string{
		"alpha.yaml": validFeatureFile,
		"beta.yaml": `feature: beta
prefix: AL
title: Beta
specs:
  - Spec B
rows:
` + shared,
	})
	alpha := filepath.Join(dir, "alpha.yaml")
	beta := filepath.Join(dir, "beta.yaml")
	assertProblems(t, validationProblems(t, dir, ValidationOptions{SkipSymbolCitations: true}), []string{
		fmt.Sprintf(`%s rows[0] (AL-001): id "AL-001" already declared in %s`, beta, alpha),
		fmt.Sprintf(`%s: prefix "AL" already used by %s`, beta, alpha),
	})
}
