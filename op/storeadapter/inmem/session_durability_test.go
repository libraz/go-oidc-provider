//nolint:testpackage // tests reference the unexported sessionStore.
package inmem

import "testing"

func TestSessions_ReportsDurability(t *testing.T) {
	t.Parallel()

	if (*sessionStore)(nil).Durable() {
		t.Fatal("inmem session store must report volatile")
	}
}
