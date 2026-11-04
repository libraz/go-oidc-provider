// Command op-schema writes the SQL adapter's migration files in the layout
// of a migration tool, without a database connection.
//
// Usage:
//
//	op-schema export --dialect mysql|postgres|sqlite --format golang-migrate|goose|flyway \
//	    --out <dir> [--prefix <p>] [--naming key=name]...
//
// The files carry the content of oidcsql.Store.Migrations for the dialect,
// prefix and naming overrides; only the file names and a tool header differ.
package main

import (
	"context"
	databasesql "database/sql"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

const (
	formatGolangMigrate = "golang-migrate"
	formatGoose         = "goose"
	formatFlyway        = "flyway"

	defaultPrefix = "oidc_"
	dirPerm       = 0o755
	filePerm      = 0o644
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one command line and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "export" {
		_, _ = fmt.Fprintln(stderr, "usage: op-schema export --dialect mysql|postgres|sqlite --format golang-migrate|goose|flyway --out <dir> [--prefix <p>] [--naming key=name]...")
		return 2
	}
	fl := flag.NewFlagSet("export", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dialect := fl.String("dialect", "", "mysql, postgres or sqlite")
	prefix := fl.String("prefix", defaultPrefix, "table name prefix (oidcsql.WithTablePrefix)")
	format := fl.String("format", formatGolangMigrate, "golang-migrate, goose or flyway")
	out := fl.String("out", "", "directory to write the files to; created if missing")
	var naming namingFlag
	fl.Var(&naming, "naming", "table name override key=name (oidcsql.WithNaming); repeatable")
	if err := fl.Parse(args[1:]); err != nil {
		return 2
	}
	names, err := export(*dialect, *prefix, *format, *out, naming.m)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "op-schema: %v\n", err)
		return 1
	}
	for _, n := range names {
		_, _ = fmt.Fprintln(stdout, n)
	}
	return 0
}

// namingFlag collects repeated --naming key=name pairs.
type namingFlag struct{ m map[string]string }

func (f *namingFlag) String() string { return fmt.Sprint(f.m) }

func (f *namingFlag) Set(v string) error {
	key, name, ok := strings.Cut(v, "=")
	if !ok || key == "" || name == "" {
		return fmt.Errorf("want key=name, got %q", v)
	}
	if _, dup := f.m[key]; dup {
		return fmt.Errorf("key %q given more than once", key)
	}
	if f.m == nil {
		f.m = map[string]string{}
	}
	f.m[key] = name
	return nil
}

// export writes the migration files and returns their paths in order.
func export(dialectName, prefix, format, out string, naming map[string]string) ([]string, error) {
	if out == "" {
		return nil, errors.New("--out is required")
	}
	d, err := dialectFor(dialectName)
	if err != nil {
		return nil, err
	}
	if format != formatGolangMigrate && format != formatGoose && format != formatFlyway {
		return nil, fmt.Errorf("--format must be golang-migrate, goose or flyway, got %q", format)
	}
	// The store only renders names here; the connector is never opened.
	store, err := oidcsql.New(databasesql.OpenDB(offlineConnector{}), d, oidcsql.WithTablePrefix(prefix), oidcsql.WithNaming(naming))
	if err != nil {
		if len(naming) > 0 {
			return nil, fmt.Errorf("--prefix or --naming: %w", err)
		}
		return nil, err
	}
	return writeMigrations(store.Migrations(), format, out)
}

// writeMigrations converts every file in files to format and writes it
// under out, returning the paths written.
func writeMigrations(files fs.FS, format, out string) ([]string, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(out, dirPerm); err != nil {
		return nil, err
	}
	written := make([]string, 0, len(entries))
	for _, e := range entries {
		raw, err := fs.ReadFile(files, e.Name())
		if err != nil {
			return nil, err
		}
		name, content, err := convert(format, e.Name(), string(raw))
		if err != nil {
			return nil, err
		}
		path := filepath.Join(out, name)
		if err := os.WriteFile(path, []byte(content), filePerm); err != nil {
			return nil, err
		}
		written = append(written, path)
	}
	return written, nil
}

// dialectFor resolves the --dialect value.
func dialectFor(name string) (oidcsql.Dialect, error) {
	switch name {
	case "mysql":
		return oidcsql.MySQL(), nil
	case "postgres":
		return oidcsql.Postgres(), nil
	case "sqlite":
		return oidcsql.SQLite(), nil
	}
	return oidcsql.Dialect{}, fmt.Errorf("--dialect must be mysql, postgres or sqlite, got %q", name)
}

var migrationName = regexp.MustCompile(`^(\d+)_(.+)\.up\.sql$`)

// convert maps one golang-migrate file to the tool's file name and content.
func convert(format, file, content string) (string, string, error) {
	m := migrationName.FindStringSubmatch(file)
	if m == nil {
		return "", "", fmt.Errorf("unexpected migration file name %q", file)
	}
	version, label := m[1], m[2]
	switch format {
	case formatGoose:
		return version + "_" + label + ".sql", "-- +goose Up\n" + content + "\n-- +goose Down\n", nil
	case formatFlyway:
		n, err := strconv.Atoi(version)
		if err != nil {
			return "", "", fmt.Errorf("migration version %q: %w", version, err)
		}
		return "V" + strconv.Itoa(n) + "__" + strings.ReplaceAll(label, ".", "_") + ".sql", content, nil
	default:
		return file, content, nil
	}
}

// offlineConnector satisfies driver.Connector for a *sql.DB that renders
// DDL only; any attempt to use it fails.
type offlineConnector struct{}

var errOffline = errors.New("op-schema does not connect to a database")

func (offlineConnector) Connect(context.Context) (driver.Conn, error) { return nil, errOffline }
func (offlineConnector) Driver() driver.Driver                        { return offlineDriver{} }

type offlineDriver struct{}

func (offlineDriver) Open(string) (driver.Conn, error) { return nil, errOffline }
