package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanGoFile_ResolvesEnclosingFunc(t *testing.T) {
	src := `package x

// Helper carries a CVE-2099-12345 reference at file scope.
const x = 1

// TestAlpha pins behaviour. Tracks: CVE-2099-99999 and
// also GHSA-aaaa-bbbb-cccc.
func TestAlpha(t *testing.T) {
	// In-body reference: CVE-2099-11111.
	_ = x
}

func FuzzBeta(f *testing.F) {
	// Seed for CVE-2099-22222.
	_ = 0
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "x_test.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	hits, err := scanGoFile(path)
	if err != nil {
		t.Fatalf("scanGoFile: %v", err)
	}

	want := map[string]string{
		"CVE-2099-12345":      "",          // file scope, before any func
		"CVE-2099-99999":      "TestAlpha", // leading doc comment
		"GHSA-aaaa-bbbb-cccc": "TestAlpha",
		"CVE-2099-11111":      "TestAlpha", // in-body comment
		"CVE-2099-22222":      "FuzzBeta",
	}
	got := map[string]string{}
	for _, h := range hits {
		got[h.ID] = h.Func
	}
	if len(got) != len(want) {
		t.Fatalf("hit count = %d (%v); want %d (%v)", len(got), got, len(want), want)
	}
	for id, fn := range want {
		if got[id] != fn {
			t.Errorf("ID %s enclosing func = %q, want %q", id, got[id], fn)
		}
	}
}

func TestScanGoFile_DedupsWithinSameLine(t *testing.T) {
	src := `package x

// TestSame redundantly cites CVE-2099-00001 CVE-2099-00001 CVE-2099-00001.
func TestSame(t *testing.T) {}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "x_test.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	hits, err := scanGoFile(path)
	if err != nil {
		t.Fatalf("scanGoFile: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1 (dedupe per comment line)", len(hits))
	}
	if hits[0].ID != "CVE-2099-00001" {
		t.Errorf("ID = %q, want CVE-2099-00001", hits[0].ID)
	}
}

func TestLoadAdvisoryInventory_RejectsBadShape(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{
			name: "schema_version mismatch",
			body: `schema_version: 7
advisories: [{id: CVE-2099-00001, severity: P0, source: https://example, threat: T-99, status: tracking}]
`,
			wantSub: "schema_version=7",
		},
		{
			name: "bad ID pattern",
			body: `schema_version: 1
advisories: [{id: NOT-AN-ID, severity: P0, source: https://example, threat: T-99, status: tracking}]
`,
			wantSub: "does not match CVE-/GHSA-",
		},
		{
			name: "out-of-scope without reason",
			body: `schema_version: 1
advisories: [{id: CVE-2099-00002, severity: P0, source: https://example, threat: T-99, status: out-of-scope}]
`,
			wantSub: "out_of_scope_reason",
		},
		{
			name: "duplicate ID",
			body: `schema_version: 1
advisories:
  - {id: CVE-2099-00003, severity: P0, source: https://example, threat: T-99, status: tracking}
  - {id: CVE-2099-00003, severity: P0, source: https://example, threat: T-99, status: tracking}
`,
			wantSub: "duplicate id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, advisoryFileName), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := loadAdvisoryInventory(dir)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err=%q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestRunAdvisories_DetectsDriftAndOrphans(t *testing.T) {
	tmp := t.TempDir()
	catalogDir := filepath.Join(tmp, "catalog")
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(catalogDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Inventory:
	//   CVE-2099-00001 -> covered (must appear in source — it does)
	//   CVE-2099-00002 -> covered (must appear — it doesn't, drift)
	//   CVE-2099-00003 -> tracking (must NOT appear — it does, drift)
	//   CVE-2099-00004 -> tracking (must NOT appear — it doesn't, ok)
	// Source emits CVE-2099-00001, CVE-2099-00003, and an orphan
	// CVE-2099-99999.
	inv := `schema_version: 1
advisories:
  - {id: CVE-2099-00001, severity: P0, source: https://example, threat: T-01, status: covered}
  - {id: CVE-2099-00002, severity: P0, source: https://example, threat: T-01, status: covered}
  - {id: CVE-2099-00003, severity: P0, source: https://example, threat: T-01, status: tracking}
  - {id: CVE-2099-00004, severity: P0, source: https://example, threat: T-01, status: tracking}
`
	if err := os.WriteFile(filepath.Join(catalogDir, advisoryFileName), []byte(inv), 0o600); err != nil {
		t.Fatalf("write inv: %v", err)
	}
	src := `package x

// TestA Tracks: CVE-2099-00001 CVE-2099-00003 CVE-2099-99999.
func TestA(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(srcDir, "a_test.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// Capture stdout to a pipe so the assertion focuses on the
	// returned error rather than the chatty dashboard.
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout; _ = r.Close() }()

	err := runAdvisories(catalogDir, tmp, []string{"src"}, true /*check*/, false)
	_ = w.Close()
	if err == nil {
		t.Fatal("expected drift gate to fail, got nil")
	}
	var ev *exitError
	if !errorsAs(err, &ev) {
		t.Fatalf("expected *exitError, got %T (%v)", err, err)
	}
	if ev.code != 1 {
		t.Errorf("exit code = %d, want 1", ev.code)
	}
	// Three issues expected: covered-but-missing, tracking-but-present, orphan.
	if !strings.Contains(ev.message, "3 issue(s)") {
		t.Errorf("message=%q, expected 3 issues", ev.message)
	}
}

// errorsAs is a tiny shim because errors.As reads more clearly inline
// than importing the package just for one helper.
func errorsAs(err error, target **exitError) bool {
	for e := err; e != nil; {
		if v, ok := e.(*exitError); ok {
			*target = v
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
