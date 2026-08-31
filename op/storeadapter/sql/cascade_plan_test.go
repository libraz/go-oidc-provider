//nolint:testpackage // tests reference the unexported query registry.
package oidcsql

import (
	"context"
	databasesql "database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// clientCascadeStatements returns every registry statement the
// client-scoped cascade runs, keyed by the registry field that holds it.
// Deriving them from the registry is what keeps a statement added later
// in scope; [clientCascadeRE] is the same matcher the schema guard uses,
// so the two checks cannot drift into covering different sets.
func clientCascadeStatements(t *testing.T) map[string]string {
	t.Helper()

	q, err := buildQueries(SQLite(), defaultNames())
	if err != nil {
		t.Fatalf("buildQueries: %v", err)
	}
	out := map[string]string{}
	v := reflect.ValueOf(q)
	for i := range v.NumField() {
		field := v.Field(i)
		if field.Kind() != reflect.String {
			continue
		}
		if clientCascadeRE.MatchString(field.String()) {
			out[v.Type().Field(i).Name] = field.String()
		}
	}
	if len(out) == 0 {
		t.Fatal("no client-scoped cascade statements found; the registry shape changed and this test stopped checking anything")
	}
	return out
}

// TestSQLite_ClientCascadeStatementsPlanOnAnIndex asks the engine what it
// would do rather than reading the DDL and concluding it must be fine.
// The schema guard next door proves an index leading with client_id
// exists; only the planner can say the statement actually uses it, which
// is what decides whether deleting one client examines its own tokens or
// every token in the table.
//
// SQLite is the engine asked because it needs no container, and its
// planner is the strictest of the three about saying so: it reports SCAN
// for a table scan and SEARCH ... USING INDEX for anything else, with no
// row statistics needed to choose between them.
func TestSQLite_ClientCascadeStatementsPlanOnAnIndex(t *testing.T) {
	t.Parallel()

	dsn := "file:" + filepath.Join(t.TempDir(), "oidc.db")
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db, SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	for name, stmt := range clientCascadeStatements(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			plan := queryPlan(t, db, stmt)
			for _, step := range plan {
				if strings.HasPrefix(step, "SCAN ") {
					t.Errorf("the cascade scans the table:\n  %s\n  plan: %v", stmt, plan)
				}
			}
			if !strings.Contains(strings.Join(plan, "\n"), "USING INDEX") &&
				!strings.Contains(strings.Join(plan, "\n"), "USING COVERING INDEX") {
				t.Errorf("the cascade plans without an index:\n  %s\n  plan: %v", stmt, plan)
			}
		})
	}
}

// queryPlan returns the planner's account of stmt, one entry per step.
// The statement is explained rather than run, so the bind values only
// have to fill the placeholders.
func queryPlan(t *testing.T, db *databasesql.DB, stmt string) []string {
	t.Helper()

	args := make([]any, strings.Count(stmt, "?"))
	for i := range args {
		args[i] = ""
	}
	rows, err := db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+stmt, args...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN %q: %v", stmt, err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var (
			id, parent, notUsed int64
			detail              string
		)
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		out = append(out, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan rows: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("EXPLAIN QUERY PLAN returned nothing for %q", stmt)
	}
	return out
}
