//go:build apiverify

package apiverify

import "testing"

// 06 boots an OP backed by SQLite; the discovery probe confirms the store
// wired up and the listener serves.
func TestExample06SQLStore(t *testing.T) {
	runDiscovery(t, "../../06-sql-store", "http://127.0.0.1:8080")
}
