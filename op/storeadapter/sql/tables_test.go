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

	out := parseDDLColumns(schema)
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
		if _, ok := checkedWhen[info.checked]; !ok {
			t.Errorf("%s has unknown checked tag %q", info.key, info.checked)
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

// releaseSection returns one release's migration file for a dialect.
func releaseSection(t *testing.T, dialect string, r schemaRelease) []byte {
	t.Helper()

	return readMigration(t, dialect, r.migration)
}

// TestSchemaReleases_MigrationsSectionAddsEveryColumn binds the release
// history to the migration files: a release's file must carry an ADD COLUMN
// for each column that release added and a CREATE TABLE for each table it
// created, under every dialect, or ValidateSchema would send an operator to
// a migration that cannot fix the error it reports.
func TestSchemaReleases_MigrationsSectionAddsEveryColumn(t *testing.T) {
	t.Parallel()

	names := defaultNames()
	for _, r := range schemaReleases {
		for dialect := range allDialects() {
			sql := releaseSection(t, dialect, r)
			added := addedColumns(sql)
			for _, tc := range r.columns {
				for _, c := range tc.columns {
					if !added[names.byKey(tc.key)+"."+c] {
						t.Errorf("%s migration %s has no ADD COLUMN for %s.%s", dialect, r.migration, tc.key, c)
					}
				}
			}
			created := map[string]bool{}
			for _, m := range createTableRE.FindAllSubmatch(sql, -1) {
				created[string(m[1])] = true
			}
			for _, key := range r.tables {
				if !created[names.byKey(key)] {
					t.Errorf("%s migration %s has no CREATE TABLE for %s", dialect, r.migration, key)
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
	b.WriteString("`op.New` checks, at construction, the tables the configuration uses (the\n")
	b.WriteString("\"Checked when\" column) and names any that are missing. Run against an empty\n")
	b.WriteString("database, its error lists every table your configuration needs in one pass.\n")
	b.WriteString("A table whose condition your configuration does not meet does not stop\n")
	b.WriteString("startup, but create every table from `schema/<dialect>/v1.sql` anyway and\n")
	b.WriteString("leave the unused ones empty: the release files under `migrations/<dialect>`\n")
	b.WriteString("alter optional tables too, and `Store.ValidateSchema`, the deploy gate,\n")
	b.WriteString("checks every table. A table checked always must exist even while it stays\n")
	b.WriteString("empty; its row says what reaches it.\n")
	b.WriteString("`WithTablePrefix` replaces the `oidc_` prefix of every name and `WithNaming`\n")
	b.WriteString("renames one table through its key; the columns are fixed. Your own\n")
	b.WriteString("users table needs no new column when it already has an opaque identifier that\n")
	b.WriteString("is assigned once and never reused: the OP only needs that subject from it,\n")
	b.WriteString("through a `store.UserStore`. A table keyed only by an auto-increment id or an\n")
	b.WriteString("email address adds one such column.\n\n")
	defaults := make([]string, 0, len(defaultConfigTables))
	var always []string
	for _, key := range defaultConfigTables {
		name := names.byKey(key)
		if name == "" {
			t.Fatalf("defaultConfigTables names unknown key %q", key)
		}
		defaults = append(defaults, "`"+name+"`")
		if tableRequired(key) {
			always = append(always, "`"+name+"`")
		}
	}
	fmt.Fprintf(&b, "The default configuration (the `authorization_code` and `refresh_token`\n"+
		"grants, password login against your own user store, every other option at its\n"+
		"default) needs these %d tables: %s.\n\n", len(defaults), strings.Join(defaults, ", "))
	fmt.Fprintf(&b, "Of these, the following %d are checked in every configuration, even while the\n"+
		"feature that writes them is unused, so they must exist empty: %s. The access-token\n"+
		"tables are among them because revocation and introspection look every presented\n"+
		"token up, although rows appear only under the configuration their row names.\n\n", len(always), strings.Join(always, ", "))
	b.WriteString("Column types differ by dialect; `schema/<dialect>/v1.sql` is authoritative.\n")
	b.WriteString("A column marked with a release was added to an existing table in that release;\n")
	b.WriteString("an existing database applies the matching file under `migrations/<dialect>`.\n")
	b.WriteString("op.New and `Store.ValidateSchema` check that every column listed here exists.\n\n")
	b.WriteString("| Table | `WithNaming` key | Holds | Checked when | Rows appear when |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, info := range tableCatalog {
		checked, ok := checkedWhen[info.checked]
		if !ok {
			t.Fatalf("%s has unknown checked tag %q", info.key, info.checked)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s. | %s |\n", names.byKey(info.key), info.key, info.holds, checked, info.used)
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
		{"clients", []string{"previous_secret_hash"}, "; apply migration 000006_v1.5.0 (schema/migrations/sqlite/000006_v1.5.0.up.sql)"},
		{"refresh_tokens", []string{"chain_id", "claims"}, "; apply migration 000005_v1.4.0 (schema/migrations/sqlite/000005_v1.4.0.up.sql)"},
		{"refresh_tokens", []string{"subject_public"}, ""},
		{"refresh_tokens", []string{"subject_public", "chain_id"}, "; apply migration 000005_v1.4.0 (schema/migrations/sqlite/000005_v1.4.0.up.sql)"},
		{"totp_secrets", []string{"row_version"}, "; apply migration 000002_v1.1.0 (schema/migrations/sqlite/000002_v1.1.0.up.sql)"},
	}
	for _, tc := range cases {
		if got := migrationHint("sqlite", tc.key, tc.missing); got != tc.want {
			t.Errorf("migrationHint(%s, %v) = %q, want %q", tc.key, tc.missing, got, tc.want)
		}
	}
	got := migrationsHint("mysql", []string{"000005_v1.4.0", "000006_v1.5.0"})
	if want := "; apply migrations 000005_v1.4.0, 000006_v1.5.0 (schema/migrations/mysql/)"; got != want {
		t.Errorf("migrationsHint = %q, want %q", got, want)
	}
}

func TestCollationMigration(t *testing.T) {
	t.Parallel()

	for key, want := range map[string]string{
		"clients":     "000004_v1.3.0",
		"users":       "000004_v1.3.0",
		"ssf_streams": "000006_v1.5.0",
	} {
		if got := collationMigration(key); got != want {
			t.Errorf("collationMigration(%s) = %q, want %q", key, got, want)
		}
	}
}

// TestBinaryCollationColumns_MatchMySQLDDL binds binaryCollationColumns to
// the columns the MySQL DDL declares COLLATE utf8mb4_bin, so ValidateSchema
// checks exactly the columns the schema pins.
func TestBinaryCollationColumns_MatchMySQLDDL(t *testing.T) {
	t.Parallel()

	names := defaultNames()
	want := map[string][]string{}
	text := string(MySQL().schema)
	for _, loc := range createTableRE.FindAllStringSubmatchIndex(text, -1) {
		table := text[loc[2]:loc[3]]
		body := text[loc[1]:]
		if end := strings.Index(body, "\n);"); end >= 0 {
			body = body[:end]
		}
		key := ""
		for i, name := range names.all() {
			if name == table {
				key = knownNamingKeys[i]
			}
		}
		if key == "" {
			t.Fatalf("MySQL DDL declares %s, which no WithNaming key names", table)
		}
		for _, line := range strings.Split(body, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(fields[0], "--") || !strings.Contains(line, "COLLATE utf8mb4_bin") {
				continue
			}
			want[key] = append(want[key], fields[0])
		}
	}
	if len(want) == 0 {
		t.Fatal("no COLLATE utf8mb4_bin columns parsed from the MySQL DDL; the schema shape changed and this test stopped checking anything")
	}
	if !reflect.DeepEqual(binaryCollationColumns, want) {
		t.Fatalf("binaryCollationColumns = %v, want the MySQL DDL's %v", binaryCollationColumns, want)
	}
}

func TestDDLColumns_ParsesEveryDialectForEveryKey(t *testing.T) {
	t.Parallel()

	for name, d := range allDialects() {
		cols := ddlColumns(d)
		for _, key := range knownNamingKeys {
			if len(cols[key]) == 0 {
				t.Errorf("%s: no columns parsed for %s", name, key)
			}
		}
		if !slices.Contains(cols["refresh_tokens"], "retry_response") || !slices.Contains(cols["authn_lockouts"], "failed_count") {
			t.Errorf("%s: expected columns missing from parsed DDL: %v", name, cols)
		}
		for key, list := range cols {
			for _, c := range list {
				if strings.ContainsAny(c, "(),`") {
					t.Errorf("%s: %s has malformed column %q", name, key, c)
				}
			}
		}
	}
}
