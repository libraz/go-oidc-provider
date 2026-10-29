//nolint:testpackage // tests reference the unexported sessionStore.
package oidcredis

import "testing"

func TestSessions_ReportsDurability(t *testing.T) {
	t.Parallel()

	if (*sessionStore)(nil).Durable() {
		t.Fatal("redis session store must report volatile")
	}
}
