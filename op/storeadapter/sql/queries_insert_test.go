//nolint:testpackage // tests reference unexported buildQueries and defaultNames.
package oidcsql

import (
	"reflect"
	"strings"
	"testing"
)

// listAfter returns the comma-separated items of the first parenthesised
// group that follows marker in query.
func listAfter(t *testing.T, query, marker string) []string {
	t.Helper()
	_, rest, ok := strings.Cut(query, marker+" (")
	if !ok {
		t.Fatalf("no %q list in %s", marker, query)
	}
	list, _, ok := strings.Cut(rest, ")")
	if !ok {
		t.Fatalf("unterminated %q list in %s", marker, query)
	}
	return strings.Split(list, ",")
}

// TestBuildQueries_InsertsBindOnePlaceholderPerColumn pins that every
// INSERT template names as many value placeholders as it lists columns,
// under every dialect's placeholder syntax.
func TestBuildQueries_InsertsBindOnePlaceholderPerColumn(t *testing.T) {
	t.Parallel()
	for _, d := range []Dialect{SQLite(), MySQL(), Postgres()} {
		t.Run(d.Name(), func(t *testing.T) {
			t.Parallel()
			q, err := buildQueries(d, defaultNames())
			if err != nil {
				t.Fatalf("buildQueries(%s): %v", d.Name(), err)
			}
			v := reflect.ValueOf(q)
			inserts := 0
			for i := range v.NumField() {
				if v.Field(i).Kind() != reflect.String {
					continue
				}
				query := v.Field(i).String()
				if !strings.HasPrefix(query, "INSERT INTO ") {
					continue
				}
				inserts++
				name := v.Type().Field(i).Name
				cols := listAfter(t, query, strings.SplitN(query, " ", 4)[2])
				values := listAfter(t, query, "VALUES")
				if len(cols) != len(values) {
					t.Errorf("%s: %d columns, %d placeholders: %s", name, len(cols), len(values), query)
				}
			}
			if inserts == 0 {
				t.Fatal("no INSERT template found")
			}
		})
	}
}
