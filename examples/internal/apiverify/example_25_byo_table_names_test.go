//go:build apiverify

package apiverify

import "testing"

// 25 boots an OP backed by SQLite with every OP-internal table renamed
// through oidcsql.WithNaming; the discovery probe confirms the renamed
// store migrated and the listener serves.
func TestExample25BYOTableNames(t *testing.T) {
	runDiscovery(t, "../../25-byo-table-names", "http://127.0.0.1:8080")
}
