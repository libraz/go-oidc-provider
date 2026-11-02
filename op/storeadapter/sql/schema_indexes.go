package oidcsql

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
)

var (
	createIndexRE = regexp.MustCompile(`(?i)CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?\w+\s+ON\s+(\w+)\s*\(\s*(\w+)`)
	inlineIndexRE = regexp.MustCompile(`(?i)^\s*(?:UNIQUE )?(?:INDEX|KEY) \w+\s*\(\s*(\w+)`)
	tablePKRE     = regexp.MustCompile(`(?i)^\s*PRIMARY KEY\s*\(\s*(\w+)`)
	columnUniqRE  = regexp.MustCompile(`(?i)^\s*(\w+)\s+[^-]*\bUNIQUE\b`)
)

// parseDDLIndexColumns maps each table to the set of columns that lead an
// index on it, covering both DDL shapes the dialects use: standalone
// CREATE INDEX (SQLite, PostgreSQL) and inline INDEX clauses inside
// CREATE TABLE (MySQL, which has no CREATE INDEX IF NOT EXISTS and so
// declares them with the table). The first column of a primary key counts
// too, whether declared on the column or as a table constraint.
func parseDDLIndexColumns(schema []byte) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(table, column string) {
		if out[table] == nil {
			out[table] = map[string]bool{}
		}
		out[table][column] = true
	}

	text := string(schema)
	for _, m := range createIndexRE.FindAllStringSubmatch(text, -1) {
		add(m[1], m[2])
	}
	for _, loc := range createTableRE.FindAllStringSubmatchIndex(text, -1) {
		table := text[loc[2]:loc[3]]
		body := text[loc[1]:]
		if end := strings.Index(body, "\n);"); end >= 0 {
			body = body[:end]
		}
		for _, line := range strings.Split(body, "\n") {
			if column := ddlLineIndexLead(line); column != "" {
				add(table, column)
			}
		}
	}
	return out
}

// ddlLineIndexLead returns the column a CREATE TABLE body line leads an
// index with (an inline INDEX/KEY, a PRIMARY KEY constraint, or a column
// declared PRIMARY KEY or UNIQUE), or "" for any other line.
func ddlLineIndexLead(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "--") {
		return ""
	}
	if m := inlineIndexRE.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := tablePKRE.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if strings.Contains(strings.ToUpper(line), "PRIMARY KEY") {
		return strings.Fields(trimmed)[0]
	}
	if m := columnUniqRE.FindStringSubmatch(line); m != nil && !strings.EqualFold(m[1], "UNIQUE") {
		return m[1]
	}
	return ""
}

// ddlIndexLeads returns, by WithNaming key, the sorted columns that lead an
// index in the reference DDL of the dialect. Table names in the DDL are the
// defaults; columns do not change under [WithNaming].
func ddlIndexLeads(d Dialect) map[string][]string {
	ddlIndexLeadsMu.Lock()
	defer ddlIndexLeadsMu.Unlock()
	if leads, ok := ddlIndexLeadsCache[d.name]; ok {
		return leads
	}
	byTable := parseDDLIndexColumns(d.schema)
	names := defaultNames()
	leads := make(map[string][]string, len(knownNamingKeys))
	for _, key := range knownNamingKeys {
		leads[key] = slices.Sorted(maps.Keys(byTable[names.byKey(key)]))
	}
	ddlIndexLeadsCache[d.name] = leads
	return leads
}

var (
	ddlIndexLeadsMu    sync.Mutex                         //nolint:gochecknoglobals // guards ddlIndexLeadsCache.
	ddlIndexLeadsCache = map[string]map[string][]string{} //nolint:gochecknoglobals // memo of parsed embedded DDL.
)

// checkIndexes reports, as one problem, the columns of table that lead no
// index although the reference DDL indexes them. Index names and extra
// columns are not compared, so an embedder's own index passes.
func (s *Store) checkIndexes(ctx context.Context, key, table string) ([]error, error) {
	want := ddlIndexLeads(s.dialect)[key]
	if len(want) == 0 {
		return nil, nil
	}
	have, err := s.indexLeadColumns(ctx, table)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, col := range want {
		if !have[col] {
			missing = append(missing, col)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	hint := ""
	if s.dialect.name == "mysql" {
		hint = "; Store.Migrate cannot add indexes to an existing table, see schema/MIGRATIONS.md"
	}
	return []error{fmt.Errorf("oidcsql: %s has no index on %s; create it from %s%s",
		table, strings.Join(missing, ", "), s.ddlReference(), hint)}, nil
}

// indexLeadColumns returns the columns that lead an index on the physical
// table, the primary key included.
func (s *Store) indexLeadColumns(ctx context.Context, table string) (map[string]bool, error) {
	name := s.catalogTableName(table)
	args := []any{name}
	if s.dialect.name == "sqlite" {
		args = append(args, name)
	}
	rows, err := s.db.QueryContext(ctx, s.indexLeadQuery(), args...)
	if err != nil {
		return nil, fmt.Errorf("oidcsql: inspect indexes for %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var col databasesql.NullString
		if err := rows.Scan(&col); err != nil {
			return nil, fmt.Errorf("oidcsql: scan indexes for %s: %w", table, err)
		}
		if col.Valid {
			out[col.String] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oidcsql: iterate indexes for %s: %w", table, err)
	}
	return out, nil
}

// indexLeadQuery reads the leading column of every index on one table.
// SQLite lists a rowid alias primary key in no index, so its query also reads
// the first primary-key column from the table info, and takes the table name
// twice.
func (s *Store) indexLeadQuery() string {
	switch s.dialect.name {
	case "sqlite":
		return "SELECT ii.name FROM pragma_index_list(?) AS il JOIN pragma_index_info(il.name) AS ii WHERE ii.seqno = 0 " +
			"UNION SELECT name FROM pragma_table_info(?) WHERE pk = 1"
	case "mysql":
		return "SELECT column_name FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND seq_in_index = 1"
	case "postgres":
		return "SELECT a.attname FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace " +
			"JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0] WHERE n.nspname = " + postgresResolvedSchema + " AND c.relname = $1::text"
	default:
		return ""
	}
}

// releaseGap tracks which release a database that fails the schema check was
// last at, from the releases that added what it lacks.
type releaseGap struct {
	earliest int // index into schemaReleases of the earliest release with something missing
	found    bool
	baseline bool // something the first release shipped is missing
}

// add records one missing table or column by the release that added it, ""
// for one present since the first release.
func (g *releaseGap) add(version string) {
	if version == "" {
		g.baseline = true
		return
	}
	if i := releaseIndex(version); !g.found || i < g.earliest {
		g.earliest, g.found = i, true
	}
}

// hint says which migration number to record with "migrate force" so that
// golang-migrate applies only the releases the database lacks. It returns nil
// when a table or column of the first release is missing, since no release
// is then known to be applied.
func (g releaseGap) hint() error {
	if g.baseline || !g.found {
		return nil
	}
	version, stem := "v1.0.0", baselineMigration
	if g.earliest > 0 {
		prev := schemaReleases[g.earliest-1]
		version, stem = prev.version, prev.migration
	}
	return fmt.Errorf("oidcsql: the schema matches release %s (migration %s); a database golang-migrate does not track yet "+
		"records that with \"migrate force %d\" before \"migrate up\"", version, stem[:strings.IndexByte(stem, '_')], g.earliest+1)
}
