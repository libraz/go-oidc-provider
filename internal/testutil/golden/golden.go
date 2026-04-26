// Package golden is a minimal golden-file matcher for tests. It compares
// the actual bytes a function produced against a checked-in fixture so any
// schema drift in user-visible JSON (discovery, JWKS, error envelopes)
// surfaces as a test failure rather than a silent contract change.
//
// Workflow:
//
//   - Run tests normally to verify against the recorded fixture.
//   - Pass -update on the test binary to regenerate fixtures after an
//     intentional change. Reviewers compare the diff in the PR.
//
// The package is intentionally tiny: tests bring their own data; the
// helper just decides "match or fail" and "rewrite or not".
package golden

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateFlag is a single global flag shared by every package that imports
// the helper. The flag is registered lazily via init so the test binary
// recognises -update on the command line; tests never instantiate it.
//
//nolint:gochecknoglobals // shared flag registered at init.
var updateFlag = flag.Bool(
	"update",
	false,
	"rewrite golden fixtures with the values produced by the current test run",
)

// JSON marshals got with stable indentation, then compares the result
// against the bytes stored at path. When -update is supplied the fixture is
// rewritten to match got and the test still passes.
//
// The path is resolved relative to the test binary's working directory
// (typically the package directory), so callers pass "testdata/foo.golden.json"
// and the file lives next to the test source.
func JSON(t *testing.T, got any, path string) {
	t.Helper()
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("golden.JSON: marshal: %v", err)
	}
	encoded = append(encoded, '\n')
	matchOrUpdate(t, encoded, path)
}

// Bytes compares the literal contents of got against path. Use [JSON] for
// structures whose canonical form is JSON; reach for Bytes when the fixture
// is already a byte slice (e.g. binary, hex-encoded, or a tooling-rendered
// string).
func Bytes(t *testing.T, got []byte, path string) {
	t.Helper()
	matchOrUpdate(t, got, path)
}

func matchOrUpdate(t *testing.T, got []byte, path string) {
	t.Helper()
	if *updateFlag {
		writeFixture(t, path, got)
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // path is test-controlled.
	if err != nil {
		t.Fatalf("golden.JSON: read %s: %v (run `go test -update` to create)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf(
			"golden mismatch for %s:\n--- want\n%s\n--- got\n%s\n(run `go test -update` if intentional)",
			path, want, got,
		)
	}
}

func writeFixture(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("golden.JSON: mkdir: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("golden.JSON: write %s: %v", path, err)
	}
}
