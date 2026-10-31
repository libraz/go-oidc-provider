package gatekit

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func parseTwoFields(text string) (string, string, error) {
	key, reason, ok := strings.Cut(text, "\t")
	if !ok || strings.TrimSpace(reason) == "" {
		return "", "", errors.New("want key TAB reason")
	}
	return key, reason, nil
}

func loadFrom(t *testing.T, body string) (*Allowlist[string], error) {
	t.Helper()
	return LoadAllowlist(writeTree2(t, body), parseTwoFields)
}

func writeTree2(t *testing.T, body string) string {
	t.Helper()
	root := writeTree(t, map[string]string{"list.txt": body})
	return filepath.Join(root, "list.txt")
}

func TestLoadAllowlist_MissingFileIsEmpty(t *testing.T) {
	t.Parallel()
	al, err := LoadAllowlist(filepath.Join(t.TempDir(), "absent.txt"), parseTwoFields)
	if err != nil || len(al.Rows) != 0 {
		t.Fatalf("got %v rows, err %v; want an empty allowlist", len(al.Rows), err)
	}
}

func TestLoadAllowlist_SkipsCommentsAndReportsUnused(t *testing.T) {
	t.Parallel()
	al, err := loadFrom(t, "# header\n\n  # indented\na\twhy a\nb\twhy b\n")
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if !al.Allows("a") || al.Allows("missing") {
		t.Fatal("Allows answered wrongly")
	}
	if got := al.Unused(); len(got) != 1 || got[0] != "b" {
		t.Fatalf("Unused() = %v, want [b]", got)
	}
}

func TestLoadAllowlist_RejectsMalformedAndDuplicateRows(t *testing.T) {
	t.Parallel()
	if _, err := loadFrom(t, "a\n"); err == nil || !strings.Contains(err.Error(), ":1: want key TAB reason") {
		t.Errorf("malformed row: err = %v", err)
	}
	if _, err := loadFrom(t, "a\tone\nb\ttwo\na\tthree\n"); err == nil || !strings.Contains(err.Error(), "a is already listed on line 1") {
		t.Errorf("duplicate row: err = %v", err)
	}
}
