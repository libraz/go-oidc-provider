//nolint:testpackage // tests reference the unexported table catalog, release history and dialect schema.
package oidcsql

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// updateTablesDoc regenerates schema/TABLES.md. Run
// "go test -run TestTablesDoc -update ." in op/storeadapter/sql after
// changing tableCatalog, schemaReleases or the DDL.
var updateTablesDoc = flag.Bool("update", false, "regenerate schema/TABLES.md")

// tableColumnsInDDL returns each table's column names in declaration order.
func tableColumnsInDDL(t *testing.T, schema []byte) map[string][]string {
	t.Helper()

	out := map[string][]string{}
	text := string(schema)
	for _, loc := range createTableRE.FindAllStringSubmatchIndex(text, -1) {
		table := text[loc[2]:loc[3]]
		body := text[loc[1]:]
		if end := strings.Index(body, "\n);"); end >= 0 {
			body = body[:end]
		}
		for _, line := range strings.Split(body, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(fields[0], "--") {
				continue
			}
			switch strings.ToUpper(fields[0]) {
			case "PRIMARY", "UNIQUE", "INDEX", "KEY", "CONSTRAINT", "CHECK", "FOREIGN":
				continue
			}
			out[table] = append(out[table], fields[0])
		}
	}
	if len(out) == 0 {
		t.Fatal("no tables parsed from the DDL; the schema shape changed and this test stopped checking anything")
	}
	return out
}

func TestTableCatalog_CoversEveryNamingKey(t *testing.T) {
	t.Parallel()

	if len(tableCatalog) != len(knownNamingKeys) {
		t.Fatalf("tableCatalog has %d entries, knownNamingKeys %d", len(tableCatalog), len(knownNamingKeys))
	}
	storeType := reflect.TypeFor[*Store]()
	for i, info := range tableCatalog {
		if info.key != knownNamingKeys[i] {
			t.Errorf("tableCatalog[%d] is %q, knownNamingKeys[%d] is %q; keep one order", i, info.key, i, knownNamingKeys[i])
		}
		if _, ok := storeType.MethodByName(info.accessor); !ok {
			t.Errorf("%s names accessor %s, which *Store does not have", info.key, info.accessor)
		}
		if info.holds == "" || info.used == "" {
			t.Errorf("%s has an empty description", info.key)
		}
	}
}

func TestTableColumns_SameAcrossDialects(t *testing.T) {
	t.Parallel()

	want := tableColumnsInDDL(t, Postgres().schema)
	for name, dialect := range allDialects() {
		got := tableColumnsInDDL(t, dialect.schema)
		for table, cols := range want {
			a, b := slices.Sorted(slices.Values(cols)), slices.Sorted(slices.Values(got[table]))
			if !slices.Equal(a, b) {
				t.Errorf("%s %s columns %v differ from postgres %v", name, table, b, a)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s declares %d tables, postgres %d", name, len(got), len(want))
		}
	}
}

func TestSchemaReleases_ColumnsExistInEveryDialect(t *testing.T) {
	t.Parallel()

	names := defaultNames()
	seen := map[string]string{}
	for i, r := range schemaReleases {
		if i > 0 && !versionLess(schemaReleases[i-1].version, r.version) {
			t.Errorf("schemaReleases out of order: %s after %s", r.version, schemaReleases[i-1].version)
		}
		for _, tc := range r.columns {
			table := names.byKey(tc.key)
			if table == "" {
				t.Errorf("%s names unknown key %q", r.version, tc.key)
				continue
			}
			for _, c := range tc.columns {
				id := tc.key + "." + c
				if prior, ok := seen[id]; ok {
					t.Errorf("%s is listed under both %s and %s", id, prior, r.version)
				}
				seen[id] = r.version
				for name, dialect := range allDialects() {
					if !slices.Contains(tableColumnsInDDL(t, dialect.schema)[table], c) {
						t.Errorf("%s lists %s, which the %s DDL does not declare", r.version, id, name)
					}
				}
			}
		}
	}
}

// versionLess compares "vMAJOR.MINOR.PATCH" numerically.
func versionLess(a, b string) bool {
	var pa, pb [3]int
	_, errA := fmt.Sscanf(a, "v%d.%d.%d", &pa[0], &pa[1], &pa[2])
	_, errB := fmt.Sscanf(b, "v%d.%d.%d", &pb[0], &pb[1], &pb[2])
	if errA != nil || errB != nil {
		return false
	}
	return slices.Compare(pa[:], pb[:]) < 0
}

// releaseSection returns the "## <version>" section of MIGRATIONS.md.
func releaseSection(t *testing.T, doc []byte, version string) []byte {
	t.Helper()

	start := bytes.Index(doc, []byte("\n## "+version+"\n"))
	if start < 0 {
		t.Fatalf("MIGRATIONS.md has no %q section", "## "+version)
	}
	rest := doc[start+1:]
	if end := bytes.Index(rest[1:], []byte("\n## ")); end >= 0 {
		rest = rest[:end+1]
	}
	return rest
}

// TestSchemaReleases_MigrationsSectionAddsEveryColumn binds the release
// history to the document: an operator reading a release's section must
// find an ADD COLUMN for each column that release added, under every
// dialect, or ValidateSchema would send them to a section that cannot fix
// the error it reports.
func TestSchemaReleases_MigrationsSectionAddsEveryColumn(t *testing.T) {
	t.Parallel()

	doc := migrationsDoc(t)
	names := defaultNames()
	for _, r := range schemaReleases {
		section := releaseSection(t, doc, r.version)
		for _, heading := range dialectHeadings() {
			added := addedColumns(bytes.Join(migrationsSections(t, section, heading), nil))
			for _, tc := range r.columns {
				for _, c := range tc.columns {
					if !added[names.byKey(tc.key)+"."+c] {
						t.Errorf("the %s section of MIGRATIONS.md has no %s ADD COLUMN for %s.%s",
							r.version, heading, tc.key, c)
					}
				}
			}
		}
	}
}

var (
	alterTableRE = regexp.MustCompile(`(?i)ALTER TABLE (\w+)`)
	addColumnRE  = regexp.MustCompile(`(?i)ADD COLUMN (\w+)`)
)

// addedColumns returns "table.column" for every ADD COLUMN in the SQL,
// attributed to the ALTER TABLE statement it belongs to.
func addedColumns(sql []byte) map[string]bool {
	out := map[string]bool{}
	for _, stmt := range strings.Split(string(sql), ";") {
		m := alterTableRE.FindStringSubmatch(stmt)
		if m == nil {
			continue
		}
		for _, c := range addColumnRE.FindAllStringSubmatch(stmt, -1) {
			out[m[1]+"."+c[1]] = true
		}
	}
	return out
}

func TestAddedColumns_AttributesToTheAlteredTable(t *testing.T) {
	t.Parallel()

	got := addedColumns([]byte(`
ALTER TABLE a ADD COLUMN x INTEGER NOT NULL DEFAULT 0;
ALTER TABLE b
    ADD COLUMN x JSON NULL,
    ADD COLUMN y TEXT NOT NULL;
CREATE INDEX IF NOT EXISTS idx_c ON c(z);
`))
	want := map[string]bool{"a.x": true, "b.x": true, "b.y": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("addedColumns = %v, want %v", got, want)
	}
}

// renderTablesDoc builds schema/TABLES.md from tableCatalog, the
// PostgreSQL DDL column order, and schemaReleases.
func renderTablesDoc(t *testing.T) []byte {
	t.Helper()

	names := defaultNames()
	columns := tableColumnsInDDL(t, Postgres().schema)
	var b strings.Builder
	b.WriteString("# SQL adapter tables\n\n")
	b.WriteString("<!-- Generated from tables.go by TestTablesDoc; regenerate with `go test -run TestTablesDoc -update .` in op/storeadapter/sql. -->\n\n")
	b.WriteString("Every table below must exist: `Store.ValidateSchema` checks all of them at\n")
	b.WriteString("startup. A table whose \"Used when\" condition your configuration does not meet\n")
	b.WriteString("stays empty, so create it and leave it. `WithNaming` renames a table through\n")
	b.WriteString("its key; the columns are fixed. Your own users table needs no new column: the\n")
	b.WriteString("OP only needs a stable subject from it, through a `store.UserStore`.\n\n")
	b.WriteString("Column types differ by dialect; `schema/<dialect>/v1.sql` is authoritative.\n")
	b.WriteString("A column marked with a release was added to an existing table in that release;\n")
	b.WriteString("an existing database applies the matching section of `MIGRATIONS.md`.\n\n")
	b.WriteString("| Table | `WithNaming` key | Holds | Used when |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, info := range tableCatalog {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", names.byKey(info.key), info.key, info.holds, info.used)
	}
	b.WriteString("\n## Columns\n")
	for _, info := range tableCatalog {
		table := names.byKey(info.key)
		fmt.Fprintf(&b, "\n### `%s`\n\nSubstore: `Store.%s()`\n\n", table, info.accessor)
		cols := columns[table]
		if len(cols) == 0 {
			t.Fatalf("%s has no columns in the PostgreSQL DDL", table)
		}
		for _, c := range cols {
			if v := columnAddedIn(info.key, c); v != "" {
				fmt.Fprintf(&b, "- `%s` (%s)\n", c, v)
				continue
			}
			fmt.Fprintf(&b, "- `%s`\n", c)
		}
	}
	return []byte(b.String())
}

func TestTablesDoc(t *testing.T) {
	t.Parallel()

	const path = "schema/TABLES.md"
	got := renderTablesDoc(t)
	if *updateTablesDoc {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run with -update to generate)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run `go test -run TestTablesDoc -update .` in op/storeadapter/sql", path)
	}
}

func TestMigrationHint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key     string
		missing []string
		want    string
	}{
		{"clients", []string{"previous_secret_hash"}, "; apply the v1.5.0 section of schema/MIGRATIONS.md"},
		{"refresh_tokens", []string{"chain_id", "claims"}, "; apply the v1.4.0 section of schema/MIGRATIONS.md"},
		{"refresh_tokens", []string{"subject_public"}, ""},
		{"refresh_tokens", []string{"subject_public", "chain_id"}, "; apply the v1.4.0 section of schema/MIGRATIONS.md"},
	}
	for _, tc := range cases {
		if got := migrationHint(tc.key, tc.missing); got != tc.want {
			t.Errorf("migrationHint(%s, %v) = %q, want %q", tc.key, tc.missing, got, tc.want)
		}
	}
}
