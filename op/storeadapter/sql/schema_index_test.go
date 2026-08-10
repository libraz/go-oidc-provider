//nolint:testpackage // tests reference the unexported query registry and dialect schema.
package oidcsql

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// A DELETE that filters on a column with no index scans the table, and
// on MySQL it takes a lock per row it examines rather than per row it
// removes. The statements below are exactly the ones a deployment runs
// on a schedule against its largest tables, so the scan grows with the
// data the sweep exists to bound.
//
// The swept tables are derived from the query registry rather than
// listed here: a hand-kept list is the thing that goes stale the moment
// a new sweep is added, which is the failure this test exists to catch.

var (
	expirySweepRE   = regexp.MustCompile(`DELETE FROM (\w+) WHERE[^;]*\bexpires_at\b`)
	clientCascadeRE = regexp.MustCompile(`DELETE FROM (\w+) WHERE client_id = `)
	createIndexRE   = regexp.MustCompile(`(?i)CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?\w+ ON (\w+)\s*\(\s*(\w+)`)
	createTableRE   = regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?(\w+)\s*\(`)
	inlineIndexRE   = regexp.MustCompile(`(?i)^\s*(?:UNIQUE )?(?:INDEX|KEY) \w+ \(\s*(\w+)`)
)

func allDialects() map[string]Dialect {
	return map[string]Dialect{"sqlite": SQLite(), "mysql": MySQL(), "postgres": Postgres()}
}

// indexedColumns maps each table to the set of columns that lead an
// index on it, covering both DDL shapes the dialects use: standalone
// CREATE INDEX (SQLite, PostgreSQL) and inline INDEX clauses inside
// CREATE TABLE (MySQL, which has no CREATE INDEX IF NOT EXISTS and so
// declares them with the table). A primary key counts too — its column
// is the first one named in the table body.
func indexedColumns(t *testing.T, schema []byte) map[string]map[string]bool {
	t.Helper()

	out := map[string]map[string]bool{}
	add := func(table, column string) {
		if out[table] == nil {
			out[table] = map[string]bool{}
		}
		out[table][column] = true
	}

	for _, m := range createIndexRE.FindAllStringSubmatch(string(schema), -1) {
		add(m[1], m[2])
	}

	// Walk each CREATE TABLE body for inline index clauses and the
	// primary key.
	text := string(schema)
	for _, loc := range createTableRE.FindAllStringSubmatchIndex(text, -1) {
		table := text[loc[2]:loc[3]]
		body := text[loc[1]:]
		if end := strings.Index(body, "\n);"); end >= 0 {
			body = body[:end]
		}
		for _, line := range strings.Split(body, "\n") {
			if m := inlineIndexRE.FindStringSubmatch(line); m != nil {
				add(table, m[1])
				continue
			}
			if strings.Contains(strings.ToUpper(line), "PRIMARY KEY") {
				if fields := strings.Fields(strings.TrimSpace(line)); len(fields) > 0 {
					add(table, strings.Trim(fields[0], "(,"))
				}
			}
		}
	}
	return out
}

// sweptTables returns the tables the registry deletes from with a
// predicate on the named column.
func sweptTables(t *testing.T, re *regexp.Regexp) map[string]bool {
	t.Helper()

	q, err := buildQueries(SQLite(), defaultNames())
	if err != nil {
		t.Fatalf("buildQueries: %v", err)
	}
	tables := map[string]bool{}
	v := reflect.ValueOf(q)
	for i := range v.NumField() {
		field := v.Field(i)
		if field.Kind() != reflect.String {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(field.String(), -1) {
			tables[m[1]] = true
		}
	}
	if len(tables) == 0 {
		t.Fatal("no matching DELETE statements found; the registry shape changed and this test stopped checking anything")
	}
	return tables
}

// indexedColumns is the whole basis of the checks below, so it is
// pinned against DDL whose answer is known — including the negative. A
// parser that silently reported every column as indexed would leave
// those checks passing on a schema with no indexes at all.
func TestIndexedColumns_ReadsBothDDLShapes(t *testing.T) {
	t.Parallel()

	got := indexedColumns(t, []byte(`
CREATE TABLE IF NOT EXISTS t_inline (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    unswept BIGINT NOT NULL,
    INDEX idx_t_inline_expires (expires_at)
);

CREATE TABLE IF NOT EXISTS t_standalone (
    id TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    unswept BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_t_standalone_expires ON t_standalone(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_t_standalone_unique ON t_standalone (id);

CREATE TABLE IF NOT EXISTS t_bare (
    id TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
`))

	for _, want := range []struct{ table, column string }{
		{"t_inline", "id"},
		{"t_inline", "expires_at"},
		{"t_standalone", "id"},
		{"t_standalone", "expires_at"},
		{"t_bare", "id"},
	} {
		if !got[want.table][want.column] {
			t.Errorf("%s(%s) not reported as indexed", want.table, want.column)
		}
	}
	for _, absent := range []struct{ table, column string }{
		{"t_inline", "unswept"},
		{"t_standalone", "unswept"},
		{"t_bare", "expires_at"},
	} {
		if got[absent.table][absent.column] {
			t.Errorf("%s(%s) reported as indexed; nothing in the DDL indexes it", absent.table, absent.column)
		}
	}
}

func TestSchema_EveryExpirySweepIsIndexed(t *testing.T) {
	t.Parallel()

	tables := sweptTables(t, expirySweepRE)
	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			indexed := indexedColumns(t, dialect.schema)
			for table := range tables {
				if !indexed[table]["expires_at"] {
					t.Errorf("%s sweeps %s on expires_at but the schema declares no index leading with that column", name, table)
				}
			}
		})
	}
}

// The client-scoped cascade runs when a client is deleted through
// dynamic registration, and it deletes from tables keyed on something
// else entirely. oidc_grants is the one that needs saying out loud: it
// carries a composite index leading with subject, which cannot serve a
// client_id predicate, so the cascade scanned until a dedicated index
// was added.
func TestSchema_EveryClientCascadeIsIndexed(t *testing.T) {
	t.Parallel()

	tables := sweptTables(t, clientCascadeRE)
	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			indexed := indexedColumns(t, dialect.schema)
			for table := range tables {
				if !indexed[table]["client_id"] {
					t.Errorf("%s cascades over %s on client_id but the schema declares no index leading with that column", name, table)
				}
			}
		})
	}
}

// The three dialects are three hand-maintained files, so an index added
// to one is an index missing from two. Only the (table, column) pairs
// are compared: MySQL spells them inline and the others standalone, and
// the shape is not what has to match.
func TestSchema_DialectsIndexTheSameColumns(t *testing.T) {
	t.Parallel()

	reference := indexedColumns(t, SQLite().schema)
	for name, dialect := range allDialects() {
		if name == "sqlite" {
			continue
		}
		got := indexedColumns(t, dialect.schema)
		for table, columns := range reference {
			for column := range columns {
				if !got[table][column] {
					t.Errorf("%s is missing the index sqlite declares on %s(%s)", name, table, column)
				}
			}
		}
		for table, columns := range got {
			for column := range columns {
				if !reference[table][column] {
					t.Errorf("%s declares an index on %s(%s) that sqlite does not", name, table, column)
				}
			}
		}
	}
}
