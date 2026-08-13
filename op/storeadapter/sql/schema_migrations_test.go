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
//go:embed testdata/schema_v1.0.0_indexes.txt testdata/mysql_v1.0.0.sql
var testdataFS embed.FS

// Store.Migrate is CREATE TABLE IF NOT EXISTS, so it does nothing to a table
// that already exists. On SQLite and PostgreSQL an index is its own
// standalone CREATE INDEX IF NOT EXISTS statement, which a later Migrate run
// does apply — those two dialects self-heal. MySQL has no such statement, so
// v1.sql declares every index inline in the CREATE TABLE body, and a database
// created by an earlier release never acquires an index added afterwards.
//
// The only thing standing between that and a silently unindexed production
// table is MIGRATIONS.md, which is prose: nothing fails when an index is added
// to v1.sql and the document is not updated. This file is that missing check.
// It is deliberately name-based — an index the document does not name cannot
// be applied by an operator reading it, whatever the surrounding text says.

var (
	// standaloneIndexRE matches the SQLite / PostgreSQL spelling. The
	// whitespace before ON is \s+ rather than a literal space because
	// v1.sql writes the statement on one line while MIGRATIONS.md wraps
	// the target table onto the next — the same statement either way.
	standaloneIndexRE = regexp.MustCompile(`(?i)CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?(\w+)\s+ON\s`)
	// inlineIndexNameRE matches an index declared inside a CREATE TABLE
	// body, which is how MySQL's v1.sql spells all of them.
	inlineIndexNameRE = regexp.MustCompile(`(?im)^\s*(?:UNIQUE )?(?:INDEX|KEY) (\w+) *\(`)
	// alterAddIndexRE matches the MySQL migration form.
	alterAddIndexRE = regexp.MustCompile(`(?i)ADD (?:UNIQUE )?INDEX (\w+) *\(`)
)

// declaredIndexNames returns every index name the DDL names, across the two
// spellings the dialects use. Names are unique across the schema, so a set of
// names is enough to compare a shipped schema against a document.
func declaredIndexNames(ddl []byte) map[string]bool {
	out := map[string]bool{}
	for _, re := range []*regexp.Regexp{standaloneIndexRE, inlineIndexNameRE, alterAddIndexRE} {
		for _, m := range re.FindAllStringSubmatch(string(ddl), -1) {
			out[m[1]] = true
		}
	}
	return out
}

// migrationsDoc returns MIGRATIONS.md from the same embedded FS the schemas
// come from, so the test reads exactly what ships rather than a file that
// happens to sit next to it on disk.
func migrationsDoc(t *testing.T) []byte {
	t.Helper()

	raw, err := schemaFS.ReadFile("schema/MIGRATIONS.md")
	if err != nil {
		t.Fatalf("read embedded MIGRATIONS.md: %v", err)
	}
	return raw
}

// migrationsSection returns the fenced SQL block that follows the given
// dialect heading in MIGRATIONS.md. Splitting by dialect matters because the
// statements are not interchangeable: a reader following the MySQL section
// must find MySQL's own ALTER TABLE ... ADD INDEX there, and finding the name
// under the SQLite heading would not help them.
func migrationsSection(t *testing.T, doc []byte, heading string) []byte {
	t.Helper()

	start := bytes.Index(doc, []byte("\n"+heading+":\n"))
	if start < 0 {
		t.Fatalf("MIGRATIONS.md has no %q section; the document shape changed and this test stopped checking anything", heading)
	}
	// The section runs to whichever comes first of the next dialect heading
	// and the next markdown header. The search starts one byte in so the
	// section's own heading cannot terminate it.
	rest := doc[start+1:]
	end := len(rest)
	for _, marker := range []string{"\nSQLite:\n", "\nMySQL/MariaDB:\n", "\nPostgreSQL:\n", "\n## "} {
		if i := bytes.Index(rest[1:], []byte(marker)); i >= 0 && i+1 < end {
			end = i + 1
		}
	}
	return rest[:end]
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

// dialectHeadings maps each dialect to its heading in MIGRATIONS.md.
func dialectHeadings() map[string]string {
	return map[string]string{
		"sqlite":   "SQLite",
		"mysql":    "MySQL/MariaDB",
		"postgres": "PostgreSQL",
	}
}

// TestSchema_IndexesAddedSinceV1AreDocumented is the check that makes the
// prose binding. Every index the current schema declares that a v1.0.0
// database does not already have has to be named in that dialect's
// MIGRATIONS.md section, because an operator upgrading such a database has
// nothing else to apply — and on MySQL, no automatic path at all.
func TestSchema_IndexesAddedSinceV1AreDocumented(t *testing.T) {
	t.Parallel()

	doc := migrationsDoc(t)
	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			baseline := baselineIndexNames(t, name)
			current := declaredIndexNames(dialect.schema)
			// Parsed rather than substring-matched: idx_oidc_grants_client
			// is a prefix of idx_oidc_grants_client_subject, so a
			// contains-check would report the shorter one as documented on
			// the strength of the longer one's statement.
			documented := declaredIndexNames(migrationsSection(t, doc, dialectHeadings()[name]))

			var undocumented []string
			for _, index := range sortedKeys(current) {
				if baseline[index] || documented[index] {
					continue
				}
				undocumented = append(undocumented, index)
			}
			if len(undocumented) > 0 {
				t.Errorf("%s adds %d index(es) since v1.0.0 that the %s section of MIGRATIONS.md does not name: %v\n"+
					"an existing database never acquires them (on MySQL there is no self-healing path at all)",
					name, len(undocumented), dialectHeadings()[name], undocumented)
			}
		})
	}
}

// TestSchema_MigrationsDocumentsNoUnknownIndex catches the drift in the other
// direction: a statement left in the document after the index was renamed or
// dropped from v1.sql sends an operator to create something the adapter will
// never use.
func TestSchema_MigrationsDocumentsNoUnknownIndex(t *testing.T) {
	t.Parallel()

	doc := migrationsDoc(t)
	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			current := declaredIndexNames(dialect.schema)
			documented := declaredIndexNames(migrationsSection(t, doc, dialectHeadings()[name]))
			for _, index := range sortedKeys(documented) {
				if !current[index] {
					t.Errorf("MIGRATIONS.md tells a %s operator to create %s, which the shipped schema does not declare",
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
					t.Errorf("%s shipped %s at v1.0.0 and no longer declares it; a removal needs a DROP INDEX in MIGRATIONS.md",
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
