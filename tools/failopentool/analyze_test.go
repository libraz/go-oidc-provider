package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// analyze parses one source body and runs the check over it.
func analyze(t *testing.T, src string) []Finding {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Analyze("internal/x/x.go", fset, f)
}

// callees reduces findings to the storage calls they name.
func callees(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Callee)
	}
	return out
}

// wantCallees asserts the findings name exactly the expected calls.
func wantCallees(t *testing.T, findings []Finding, want ...string) {
	t.Helper()
	got := callees(findings)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("findings = %v; want %v", got, want)
	}
}

// TestAnalyze_ReportsAStoreFaultAnsweredAsAbsence is the shape the gate
// exists for: a lookup that could not reach the backend is reported to
// the caller as a record that is not there.
func TestAnalyze_ReportsAStoreFaultAnsweredAsAbsence(t *testing.T) {
	t.Parallel()
	got := analyze(t, `package x

func resolve(deps D, id string) (*Session, bool) {
	s, err := deps.Sessions.Find(ctx, id)
	if err != nil {
		return nil, false
	}
	return s, true
}
`)
	wantCallees(t, got, "Sessions.Find")
}

// TestAnalyze_AcceptsAPropagatedError leaves alone the branch that hands
// the failure to the caller, which is the correct handling and by far
// the common one.
func TestAnalyze_AcceptsAPropagatedError(t *testing.T) {
	t.Parallel()
	wantCallees(t, analyze(t, `package x

func resolve(deps D, id string) (*Session, error) {
	s, err := deps.Sessions.Find(ctx, id)
	if err != nil {
		return nil, err
	}
	return s, nil
}
`))
}

// TestAnalyze_AcceptsAClassifiedError is the pattern the fixed sites
// now use: the branch separates "no such record" from "the backend did
// not answer" before deciding.
func TestAnalyze_AcceptsAClassifiedError(t *testing.T) {
	t.Parallel()
	wantCallees(t, analyze(t, `package x

func resolve(deps D, id string) (*Session, bool) {
	s, err := deps.Sessions.Find(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, false
		}
		panic(err)
	}
	return s, true
}
`))
}

// TestAnalyze_AcceptsALoggedError covers the other correct shape: the
// wire answer stays uniform, and the failure is still observable.
func TestAnalyze_AcceptsALoggedError(t *testing.T) {
	t.Parallel()
	wantCallees(t, analyze(t, `package x

func resolve(deps D, id string) (*Session, bool) {
	s, err := deps.Sessions.Find(ctx, id)
	if err != nil {
		deps.audit().Emit(ctx, Event{Err: err})
		return nil, false
	}
	return s, true
}
`))
}

// TestAnalyze_ReadsTheIfInitialiser covers the other way the call and
// the test are written together.
func TestAnalyze_ReadsTheIfInitialiser(t *testing.T) {
	t.Parallel()
	got := analyze(t, `package x

func has(deps D, id string) bool {
	if _, err := deps.Grants.Get(ctx, id); err != nil {
		return false
	}
	return true
}
`)
	wantCallees(t, got, "Grants.Get")
}

// TestAnalyze_IgnoresANonStoreCall keeps the gate off the enormous
// population of ordinary error handling. A parse failure answered with
// a zero value is a different question from a storage failure answered
// as absence.
func TestAnalyze_IgnoresANonStoreCall(t *testing.T) {
	t.Parallel()
	wantCallees(t, analyze(t, `package x

func parse(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}
`))
}

// TestAnalyze_IgnoresABranchThatDoesNotAnswer keeps the gate to
// fabricated negatives. A branch that panics or continues has not told
// the caller the record is absent.
func TestAnalyze_IgnoresABranchThatDoesNotAnswer(t *testing.T) {
	t.Parallel()
	wantCallees(t, analyze(t, `package x

func warm(deps D, ids []string) {
	for _, id := range ids {
		s, err := deps.Sessions.Find(ctx, id)
		if err != nil {
			continue
		}
		use(s)
	}
}
`))
}

// TestAnalyze_ReportsABareReturn covers the void shape: the caller is
// told nothing happened, which reads as "there was nothing to do".
func TestAnalyze_ReportsABareReturn(t *testing.T) {
	t.Parallel()
	got := analyze(t, `package x

func cascade(deps D, id string) {
	grants, err := deps.Grants.List(ctx, id)
	if err != nil {
		return
	}
	revoke(grants)
}
`)
	wantCallees(t, got, "Grants.List")
}

// TestAnalyze_ReportsAnEmptyCompositeReturn covers the shape the
// introspection endpoint used: an empty record standing in for "no such
// token".
func TestAnalyze_ReportsAnEmptyCompositeReturn(t *testing.T) {
	t.Parallel()
	got := analyze(t, `package x

func introspect(deps D, tok string) (response, bool) {
	rec, err := deps.AccessTokens.Find(ctx, tok)
	if err != nil {
		return response{}, false
	}
	return build(rec), true
}
`)
	wantCallees(t, got, "AccessTokens.Find")
}

// TestAnalyze_MatchesTheErrorTheBranchTests stops a false positive
// where a store call is followed by an unrelated error check.
func TestAnalyze_MatchesTheErrorTheBranchTests(t *testing.T) {
	t.Parallel()
	wantCallees(t, analyze(t, `package x

func resolve(deps D, id string) (*Session, bool) {
	s, storeErr := deps.Sessions.Find(ctx, id)
	if otherErr != nil {
		return nil, false
	}
	return s, storeErr == nil
}
`))
}

// TestLoadAllowlist_RejectsARowWithoutAReason keeps an exception from
// being added without an argument for it.
func TestLoadAllowlist_RejectsARowWithoutAReason(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/failopen.txt"
	if err := writeFile(path, "internal/x/x.go:12\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadAllowlist(path); err == nil {
		t.Fatal("loadAllowlist accepted a row with no reason")
	}
}

// TestLoadAllowlist_AcceptsAJustifiedRow keeps the escape hatch usable.
func TestLoadAllowlist_AcceptsAJustifiedRow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/failopen.txt"
	if err := writeFile(path, "# comment\n\ninternal/x/x.go:12\tThe caller cannot act on the difference.\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if !got["internal/x/x.go:12"] {
		t.Errorf("allowlist = %v, want the justified row", got)
	}
}
