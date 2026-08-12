package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanGoFile_ResolvesEnclosingFunc(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestScanGoFile_SeparatesCoverageFromMention(t *testing.T) {
	t.Parallel()
	src := `package x

import "testing"

// Ship notes that CVE-2099-10001 exists. Prose, not a claim.
func Ship() {}

// Guard is production code that names CVE-2099-10002 in a
// Tracks: block. The comment cannot fail.
func Guard() {}

// TestAlpha pins the fix. Tracks: CVE-2099-10003.
func TestAlpha(t *testing.T) {}

// Contract is a shared assertion helper, not a Test* function.
// Tracks: CVE-2099-10004.
func Contract(t *testing.T) {}

// FuzzBeta pins the parse contract.
//
// Tracks (parse-DoS class): the harness covers
//   - CVE-2099-10005 — qualified marker header.
func FuzzBeta(f *testing.F) {}
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
	want := map[string]bool{
		"CVE-2099-10001": false, // no marker, no test
		"CVE-2099-10002": false, // marker, but nothing can fail
		"CVE-2099-10003": true,
		"CVE-2099-10004": true, // helper taking *testing.T counts
		"CVE-2099-10005": true, // qualified marker header, indented list
	}
	got := map[string]bool{}
	for _, h := range hits {
		got[h.ID] = h.Covers()
	}
	if len(got) != len(want) {
		t.Fatalf("hits = %v, want %d IDs", got, len(want))
	}
	for id, covers := range want {
		if got[id] != covers {
			t.Errorf("%s Covers() = %v, want %v", id, got[id], covers)
		}
	}
}

func TestRunAdvisories_MentionIsNotCoverage(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	catalogDir := filepath.Join(tmp, "catalog")
	srcDir := filepath.Join(tmp, "src")
	for _, d := range []string{catalogDir, srcDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	inv := `schema_version: 1
advisories:
  - {id: CVE-2099-20001, severity: P0, source: https://example, threat: T-01, status: covered}
`
	if err := os.WriteFile(filepath.Join(catalogDir, advisoryFileName), []byte(inv), 0o600); err != nil {
		t.Fatalf("write inv: %v", err)
	}
	// The ID appears twice, and neither occurrence is an assertion.
	src := `package x

// Notes mention CVE-2099-20001 in passing.
const notes = 1

// Guard documents the CVE-2099-20001 mitigation. Tracks: CVE-2099-20001.
func Guard() {}
`
	if err := os.WriteFile(filepath.Join(srcDir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// The dashboard is captured so the assertion focuses on the
	// returned error rather than the chatty report.
	err := runAdvisories(&bytes.Buffer{}, catalogDir, tmp, []string{"src"}, true /*check*/, false)
	if err == nil {
		t.Fatal("expected the gate to fail: two mentions, no assertion")
	}
	var ev *exitError
	if !errors.As(err, &ev) {
		t.Fatalf("expected *exitError, got %T (%v)", err, err)
	}
	if !strings.Contains(ev.message, "1 issue(s)") {
		t.Errorf("message=%q, want 1 issue", ev.message)
	}
}

func TestLoadAdvisoryInventory_RejectsBadShape(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
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
	t.Parallel()
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

	// Capture the dashboard so the assertion focuses on the returned
	// error rather than the chatty report.
	err := runAdvisories(&bytes.Buffer{}, catalogDir, tmp, []string{"src"}, true /*check*/, false)
	if err == nil {
		t.Fatal("expected drift gate to fail, got nil")
	}
	var ev *exitError
	if !errors.As(err, &ev) {
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
