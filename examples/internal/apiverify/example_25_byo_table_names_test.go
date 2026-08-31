//go:build apiverify

package apiverify

import (
	"strings"
	"testing"
	"time"
)

// 25 renames every OP-internal table, and both halves of that need
// driving. The DDL half is only visible in the table listing the example
// reads back out of sqlite_master: a logical kind missing from the naming
// map is not an error, so the adapter quietly creates it under the
// bundled oidc_ default and the schema ships half-renamed. The query half
// surfaces at login rather than at construction, so the probe reaches the
// password prompt too.
func TestExample25BYOTableNames(t *testing.T) {
	const baseURL = "http://127.0.0.1:8080"

	p := buildAndStart(t, "../../25-byo-table-names")
	defer p.kill()

	driveAuthorizeInteraction(t, p, baseURL,
		authorizeParams("demo-spa", "https://rp.example.com/cb", "openid profile email"),
		[]string{`name="password"`})

	for _, table := range createdTables(t, p) {
		if !strings.HasPrefix(table, "auth_") {
			t.Errorf("table %q was created outside the auth_ convention; the naming map does not cover its logical kind", table)
		}
	}
}

// createdTables reads the physical table names the example logs after
// migrating.
func createdTables(t *testing.T, p *proc) []string {
	t.Helper()
	const marker = "created tables: "
	waitForLog(t, p, marker, 10*time.Second)

	for line := range strings.SplitSeq(p.readLog(), "\n") {
		_, list, found := strings.Cut(line, marker)
		if !found {
			continue
		}
		var tables []string
		for _, name := range strings.Split(list, ", ") {
			if name = strings.TrimSpace(name); name != "" {
				tables = append(tables, name)
			}
		}
		if len(tables) == 0 {
			t.Fatalf("the example logged an empty table list:\n%s", line)
		}
		return tables
	}
	t.Fatalf("no %q line in the example log:\n%s", marker, p.readLog())
	return nil
}
