//nolint:testpackage // tests reference the unexported sessionStore.
package oidcsql

import "testing"

func TestSessions_ReportsDurability(t *testing.T) {
	t.Parallel()

	if !(*sessionStore)(nil).Durable() {
		t.Fatal("sql session store must report durable")
	}
}
