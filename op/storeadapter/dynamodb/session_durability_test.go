//nolint:testpackage // tests reference the unexported sessionStore.
package oidcdynamo

import "testing"

func TestSessions_ReportsDurability(t *testing.T) {
	t.Parallel()

	if !(*sessionStore)(nil).Durable() {
		t.Fatal("dynamodb session store must report durable")
	}
}
