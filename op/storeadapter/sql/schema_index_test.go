//nolint:testpackage // tests reference the unexported query registry and dialect schema.
package oidcsql

import (
	"reflect"
	"regexp"
	"testing"
)

// A DELETE or an UPDATE that filters on a column with no index scans the
// table, and on MySQL it takes a lock per row it examines rather than per
// row it writes. The statements below are exactly the ones a deployment
// runs on a schedule, or on a client deletion, against its largest
// tables, so the scan grows with the data the sweep exists to bound.
//
// The swept tables are derived from the query registry rather than
// listed here: a hand-kept list is the thing that goes stale the moment
// a new sweep is added, which is the failure this test exists to catch.

var (
	expirySweepRE = regexp.MustCompile(`DELETE FROM (\w+) WHERE[^;]*\bexpires_at\b`)
	// The cascade revokes from some tables and deletes from others, and
	// the distinction is invisible to the engine: both plan the same way
	// and both take the same locks. Matching only DELETE left the three
	// revoking UPDATEs unchecked.
	clientCascadeRE = regexp.MustCompile(`(?:DELETE FROM|UPDATE) (\w+)(?: SET [^;]*?)? WHERE client_id = `)
)

func allDialects() map[string]Dialect {
	return map[string]Dialect{"sqlite": SQLite(), "mysql": MySQL(), "postgres": Postgres()}
}

// sweptTables returns the tables the registry runs re's statement shape
// against with a predicate on the named column.
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
		t.Fatal("no matching statements found; the registry shape changed and this test stopped checking anything")
	}
	return tables
}

// parseDDLIndexColumns is the whole basis of the checks below, so it is
// pinned against DDL whose answer is known — including the negative. A
// parser that silently reported every column as indexed would leave
// those checks passing on a schema with no indexes at all.
func TestIndexedColumns_ReadsBothDDLShapes(t *testing.T) {
	t.Parallel()

	got := parseDDLIndexColumns([]byte(`
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

CREATE TABLE IF NOT EXISTS t_unique (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL UNIQUE, -- inline unique
    other TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS t_composite (
    -- PRIMARY KEY in a comment names no column
    owner TEXT NOT NULL,
    slot INTEGER NOT NULL,
    PRIMARY KEY (owner, slot)
);
`))

	for _, want := range []struct{ table, column string }{
		{"t_composite", "owner"},
		{"t_inline", "id"},
		{"t_inline", "expires_at"},
		{"t_standalone", "id"},
		{"t_standalone", "expires_at"},
		{"t_bare", "id"},
		{"t_unique", "token"},
	} {
		if !got[want.table][want.column] {
			t.Errorf("%s(%s) not reported as indexed", want.table, want.column)
		}
	}
	for _, absent := range []struct{ table, column string }{
		{"t_inline", "unswept"},
		{"t_standalone", "unswept"},
		{"t_bare", "expires_at"},
		{"t_unique", "other"},
		{"t_composite", "slot"},
		{"t_composite", "--"},
		{"t_composite", "PRIMARY"},
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

			indexed := parseDDLIndexColumns(dialect.schema)
			for table := range tables {
				if !indexed[table]["expires_at"] {
					t.Errorf("%s sweeps %s on expires_at but the schema declares no index leading with that column", name, table)
				}
			}
		})
	}
}

// The client-scoped cascade runs when a client is deleted through
// dynamic registration, over tables keyed on something else entirely. It
// deletes from some of them and revokes in place on the others;
// oidc_grants is the one that needs saying out loud, because it carries a
// composite index leading with subject, which cannot serve a client_id
// predicate, so the cascade scanned until a dedicated index was added.
//
// The revoking half is named explicitly below. Deriving the table set
// from the registry is what keeps a newly added statement in scope, but
// it also means a regex that stops matching a shape silently narrows the
// check to nothing rather than failing.
func TestSchema_EveryClientCascadeIsIndexed(t *testing.T) {
	t.Parallel()

	tables := sweptTables(t, clientCascadeRE)
	for _, revoked := range []string{"oidc_refresh_tokens", "oidc_access_tokens", "oidc_opaque_access_tokens"} {
		if !tables[revoked] {
			t.Fatalf("the cascade's UPDATE against %s is no longer matched; this test stopped covering it", revoked)
		}
	}
	for name, dialect := range allDialects() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			indexed := parseDDLIndexColumns(dialect.schema)
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

	reference := parseDDLIndexColumns(SQLite().schema)
	for name, dialect := range allDialects() {
		if name == "sqlite" {
			continue
		}
		got := parseDDLIndexColumns(dialect.schema)
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
