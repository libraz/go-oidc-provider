//nolint:testpackage // tests reference the unexported dialect schema and the embedded schema FS.
package oidcsql

import (
	"bufio"
	"bytes"
	"embed"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// testdataFS carries the frozen v1.0.0 index baseline. It is embedded rather
// than read from disk so the test observes the same bytes wherever it runs.
//
//go:embed testdata/schema_v1.0.0_indexes.txt
var testdataFS embed.FS

// Store.Migrate is CREATE TABLE IF NOT EXISTS, so it does nothing to a table
// that already exists. On SQLite and PostgreSQL an index is its own
// standalone CREATE INDEX IF NOT EXISTS statement, which a later Migrate run
// does apply — those two dialects self-heal. MySQL has no such statement, so
// v1.sql declares every index inline in the CREATE TABLE body, and a database
// created by an earlier release never acquires an index added afterwards.
//
// The only thing standing between that and a silently unindexed production
// table is the migration files under schema/migrations: nothing fails when an
// index is added to v1.sql and no file creates it. This file is that missing
// check. It is deliberately name-based — an index no migration names cannot
// reach an existing database, whatever the surrounding SQL does.

// alterAddIndexRE matches the MySQL migration form.
var alterAddIndexRE = regexp.MustCompile(`(?i)ADD (?:UNIQUE )?INDEX (\w+) *\(`)

// declaredIndexNames returns every index name the DDL names, across the
// spellings the dialects use: the production parser for CREATE INDEX and
// inline INDEX/KEY clauses, plus MySQL's ALTER TABLE ... ADD INDEX. Names are
// unique across the schema, so a set of names is enough to compare a shipped
// schema against its migrations.
func declaredIndexNames(ddl []byte) map[string]bool {
	out := map[string]bool{}
	for _, idx := range parseDDLIndexNames(string(ddl)) {
		out[idx.name] = true
	}
	for _, m := range alterAddIndexRE.FindAllStringSubmatch(string(ddl), -1) {
		out[m[1]] = true
	}
	return out
}

// laterMigrations joins every migration after the v1.0.0 baseline for one
// dialect, which is what an operator upgrading from v1.0.0 applies.
func laterMigrations(t *testing.T, dialect string) []byte {
	t.Helper()

	out := make([][]byte, 0, len(schemaReleases))
	for _, r := range schemaReleases {
		out = append(out, readMigration(t, dialect, r.migration))
	}
	return bytes.Join(out, []byte("\n"))
}

// baselineIndexNames reads the frozen v1.0.0 index set for one dialect.
func baselineIndexNames(t *testing.T, dialect string) map[string]bool {
	t.Helper()

	raw, err := testdataFS.ReadFile("testdata/schema_v1.0.0_indexes.txt")
	if err != nil {
		t.Fatalf("read v1.0.0 index baseline: %v", err)
	}
	out := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed baseline line %q, want '<dialect> <index name>'", line)
		}
		if fields[0] == dialect {
			out[fields[1]] = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan baseline: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("baseline names no indexes for dialect %q; the file or the dialect key changed", dialect)
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestSchema_IndexesAddedSinceV1AreDocumented requires every index the
// current schema declares that a v1.0.0 database does not already have to be
// created by one of that dialect's later migrations, because an operator
// upgrading such a database has nothing else to apply — and on MySQL, no
// automatic path at all.
func TestSchema_IndexesAddedSinceV1AreDocumented(t *testing.T) {
	t.Parallel()

	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			baseline := baselineIndexNames(t, name)
			current := declaredIndexNames(dialect.schema)
			// Parsed rather than substring-matched: idx_oidc_grants_client
			// is a prefix of idx_oidc_grants_client_subject, so a
			// contains-check would report the shorter one as documented on
			// the strength of the longer one's statement.
			documented := declaredIndexNames(laterMigrations(t, name))

			var undocumented []string
			for _, index := range sortedKeys(current) {
				if baseline[index] || documented[index] {
					continue
				}
				undocumented = append(undocumented, index)
			}
			if len(undocumented) > 0 {
				t.Errorf("%s adds %d index(es) since v1.0.0 that no %s migration creates: %v\n"+
					"an existing database never acquires them (on MySQL there is no self-healing path at all)",
					name, len(undocumented), name, undocumented)
			}
		})
	}
}

// TestSchema_MigrationsDocumentsNoUnknownIndex catches the drift in the other
// direction: a statement left in a migration after the index was renamed or
// dropped from v1.sql creates something the adapter will never use.
func TestSchema_MigrationsDocumentsNoUnknownIndex(t *testing.T) {
	t.Parallel()

	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			current := declaredIndexNames(dialect.schema)
			documented := declaredIndexNames(laterMigrations(t, name))
			for _, index := range sortedKeys(documented) {
				if !current[index] {
					t.Errorf("a %s migration creates %s, which the shipped schema does not declare",
						name, index)
				}
			}
		})
	}
}

// TestSchema_NoBaselineIndexWasSilentlyDropped guards the third direction. An
// index that v1.0.0 shipped and the current schema no longer declares is
// either a deliberate removal — which an upgrading operator needs told, since
// nothing drops it for them — or an accidental deletion.
func TestSchema_NoBaselineIndexWasSilentlyDropped(t *testing.T) {
	t.Parallel()

	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			current := declaredIndexNames(dialect.schema)
			for _, index := range sortedKeys(baselineIndexNames(t, name)) {
				if !current[index] {
					t.Errorf("%s shipped %s at v1.0.0 and no longer declares it; a removal needs a DROP INDEX in a migration",
						name, index)
				}
			}
		})
	}
}

// declaredIndexNames underpins all three checks, so it is pinned against DDL
// whose answer is known, including the negative: a parser that returned
// nothing would leave every check above passing on an undocumented schema.
func TestDeclaredIndexNames_ReadsEverySpelling(t *testing.T) {
	t.Parallel()

	got := declaredIndexNames([]byte(`
CREATE TABLE IF NOT EXISTS t_inline (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    INDEX idx_inline_expires (expires_at),
    UNIQUE KEY uk_inline_id (id)
);
CREATE INDEX IF NOT EXISTS idx_standalone_expires ON t_standalone(expires_at);
CREATE UNIQUE INDEX idx_standalone_unique ON t_standalone (id);
ALTER TABLE t_inline ADD INDEX idx_altered_expires (expires_at);
`))

	for _, want := range []string{
		"idx_inline_expires",
		"uk_inline_id",
		"idx_standalone_expires",
		"idx_standalone_unique",
		"idx_altered_expires",
	} {
		if !got[want] {
			t.Errorf("%s not reported as a declared index", want)
		}
	}
	for _, absent := range []string{"t_inline", "t_standalone", "expires_at", "id"} {
		if got[absent] {
			t.Errorf("%q reported as an index name; it is a table or column", absent)
		}
	}
}

// A migration may wrap ON onto the next line; the production parser must see
// the statement as it does for the single-line form.
func TestParseDDLIndexNames_ReadsWrappedStatements(t *testing.T) {
	t.Parallel()

	got := parseDDLIndexNames("CREATE INDEX IF NOT EXISTS idx_wrapped\n    ON t_wrapped (a);\n" +
		"CREATE TABLE t_inline (\n    a INT,\n    INDEX idx_spaced   (a)\n);\n")
	want := map[string]string{"idx_wrapped": "t_wrapped", "idx_spaced": "t_inline"}
	for _, idx := range got {
		if want[idx.name] != idx.table {
			t.Errorf("index %s reported on %s", idx.name, idx.table)
		}
		delete(want, idx.name)
	}
	if len(want) > 0 {
		t.Errorf("indexes not reported: %v", want)
	}
}
