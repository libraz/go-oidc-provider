//nolint:testpackage // tests reference unexported splitStatements helper.
package oidcsql

import (
	"reflect"
	"testing"
)

// TestSplitStatements_StripsLineCommentsBeforeSplitting pins down the
// regression that surfaced when the MySQL contract harness booted: the
// MySQL schema contains a `-- ... ; ...` line comment, and the naive
// `strings.Split(src, ";")` splitter cut the comment in half and tried
// to execute the leftovers as standalone SQL.
func TestSplitStatements_StripsLineCommentsBeforeSplitting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "comment with semicolon",
			src: `-- VARCHAR(255) is used; fits in UTF8MB4
CREATE TABLE t (id INT);`,
			want: []string{"CREATE TABLE t (id INT)"},
		},
		{
			name: "two statements, both preceded by comments",
			src: `-- first;
CREATE TABLE a (id INT);
-- second; with semicolons
CREATE TABLE b (id INT);`,
			want: []string{"CREATE TABLE a (id INT)", "CREATE TABLE b (id INT)"},
		},
		{
			name: "string literal containing semicolon-like text",
			src:  `INSERT INTO t (note) VALUES ('a; b');`,
			want: []string{`INSERT INTO t (note) VALUES ('a; b')`},
		},
		{
			name: "empty string literal default",
			src:  `CREATE TABLE t (s VARCHAR(64) NOT NULL DEFAULT '');`,
			want: []string{`CREATE TABLE t (s VARCHAR(64) NOT NULL DEFAULT '')`},
		},
		{
			name: "trailing whitespace and blank statements",
			src:  `CREATE TABLE t (id INT); ; ;`,
			want: []string{"CREATE TABLE t (id INT)"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := splitStatements(c.src)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitStatements(%q)\n  got:  %#v\n  want: %#v", c.src, got, c.want)
			}
		})
	}
}

// TestSplitStatements_EachShippedSchemaProducesNoCommentLeftovers
// asserts that none of the bundled DDL splits produce a fragment that
// starts with `--` (which would indicate a comment slipped past the
// stripper) or contains an unmatched string-literal quote (which would
// indicate the splitter cut a literal in half).
func TestSplitStatements_EachShippedSchemaProducesNoCommentLeftovers(t *testing.T) {
	t.Parallel()
	for _, d := range []Dialect{SQLite(), MySQL(), Postgres()} {
		t.Run(d.Name(), func(t *testing.T) {
			t.Parallel()
			stmts := splitStatements(string(d.schema))
			if len(stmts) == 0 {
				t.Fatalf("splitStatements(%s) produced zero statements", d.Name())
			}
			for i, s := range stmts {
				if len(s) >= 2 && s[:2] == "--" {
					t.Errorf("%s stmt[%d] starts with comment marker: %q", d.Name(), i, s)
				}
				quotes := 0
				for _, b := range []byte(s) {
					if b == '\'' {
						quotes++
					}
				}
				if quotes%2 != 0 {
					t.Errorf("%s stmt[%d] has unbalanced single quotes: %q", d.Name(), i, s)
				}
			}
		})
	}
}
