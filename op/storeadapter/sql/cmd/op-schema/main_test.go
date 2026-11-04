package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	databasesql "database/sql"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile( //nolint:gosec // reads files this test just wrote.
			filepath.Join(dir, e.Name()),
		)
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

func TestExportFormats(t *testing.T) {
	t.Parallel()
	for _, dialect := range []string{"mysql", "postgres", "sqlite"} {
		for _, format := range []string{"golang-migrate", "goose", "flyway"} {
			t.Run(dialect+"/"+format, func(t *testing.T) {
				t.Parallel()
				out := filepath.Join(t.TempDir(), "nested", "oidc")
				var stdout, stderr bytes.Buffer
				code := run([]string{"export", "--dialect", dialect, "--prefix", "acme_", "--format", format, "--out", out}, &stdout, &stderr)
				if code != 0 {
					t.Fatalf("exit %d: %s", code, stderr.String())
				}
				got := readDir(t, out)
				if len(got) != 6 {
					t.Fatalf("%d files, want 6: %v", len(got), got)
				}
				for name, content := range got {
					if strings.Contains(content, "oidc_") {
						t.Errorf("%s still carries the default prefix", name)
					}
				}
				var first string
				switch format {
				case "golang-migrate":
					first = "000001_v1.0.0.up.sql"
				case "goose":
					first = "000001_v1.0.0.sql"
					if c := got[first]; !strings.HasPrefix(c, "-- +goose Up\n") || !strings.HasSuffix(c, "-- +goose Down\n") {
						t.Errorf("goose sections missing:\n%s", c)
					}
				case "flyway":
					first = "V1__v1_0_0.sql"
					if _, ok := got["V6__v1_5_0.sql"]; !ok {
						t.Errorf("flyway names = %v", got)
					}
				}
				if _, ok := got[first]; !ok {
					t.Errorf("missing %s in %v", first, got)
				}
			})
		}
	}
}

// The files carry exactly what Store.Migrations returns (goose adds its
// markers around it).
func TestExportMatchesMigrations(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	var stderr bytes.Buffer
	if code := run([]string{"export", "--dialect", "sqlite", "--format", "golang-migrate", "--out", out}, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	store, err := oidcsql.New(databasesql.OpenDB(offlineConnector{}), oidcsql.SQLite())
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range readDir(t, out) {
		want, err := fs.ReadFile(store.Migrations(), name)
		if err != nil {
			t.Fatal(err)
		}
		if content != string(want) {
			t.Errorf("%s differs from Store.Migrations", name)
		}
	}
}

func TestExportRejectsBadArguments(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, args := range [][]string{
		{},
		{"export", "--format", "goose", "--out", dir},
		{"export", "--dialect", "oracle", "--out", dir},
		{"export", "--dialect", "sqlite", "--format", "atlas", "--out", dir},
		{"export", "--dialect", "sqlite"},
		{"export", "--dialect", "sqlite", "--prefix", "1bad", "--out", dir},
	} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code == 0 {
			t.Errorf("run(%v) succeeded", args)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("rejected runs wrote %d files", len(entries))
	}
}

func TestExportAppliesNaming(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	var stderr bytes.Buffer
	code := run([]string{
		"export", "--dialect", "postgres", "--out", out,
		"--naming", "clients=acme_clients", "--naming", "sessions=acme_sessions",
	}, &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	store, err := oidcsql.New(databasesql.OpenDB(offlineConnector{}), oidcsql.Postgres(),
		oidcsql.WithNaming(map[string]string{"clients": "acme_clients", "sessions": "acme_sessions"}))
	if err != nil {
		t.Fatal(err)
	}
	got := readDir(t, out)
	for name, content := range got {
		want, err := fs.ReadFile(store.Migrations(), name)
		if err != nil {
			t.Fatal(err)
		}
		if content != string(want) {
			t.Errorf("%s differs from Store.Migrations", name)
		}
	}
	first := got["000001_v1.0.0.up.sql"]
	if !strings.Contains(first, "acme_clients") || !strings.Contains(first, "acme_sessions") {
		t.Errorf("renamed tables missing:\n%s", first)
	}
	if strings.Contains(first, "oidc_clients") {
		t.Errorf("default clients name survived")
	}
}

func TestExportRejectsBadNaming(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, naming := range [][]string{
		{"clients"},
		{"=x"},
		{"clients="},
		{"nope=x"},
		{"clients=1bad"},
		{"clients=a", "clients=b"},
		{"clients=same", "sessions=same"},
	} {
		args := make([]string, 0, 5+2*len(naming))
		args = append(args, "export", "--dialect", "sqlite", "--out", dir)
		for _, n := range naming {
			args = append(args, "--naming", n)
		}
		var stderr bytes.Buffer
		if code := run(args, &bytes.Buffer{}, &stderr); code == 0 {
			t.Errorf("run(%v) succeeded", naming)
		} else if !strings.Contains(stderr.String(), "naming") {
			t.Errorf("run(%v) message does not name the flag: %q", naming, stderr.String())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("rejected runs wrote %d files", len(entries))
	}
}
