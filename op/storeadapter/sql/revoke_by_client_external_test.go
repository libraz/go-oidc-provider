//go:build testcontainers

package oidcsql_test

import "testing"

// TestRevokeByClient_ExternalDialects runs the DCR token-retirement capability
// against the same MySQL and PostgreSQL engines covered by the contract gate.
func TestRevokeByClient_ExternalDialects(t *testing.T) {
	t.Run("mysql", func(t *testing.T) {
		testRevokeByClient(t, newMySQLFactory(t)(t))
	})
	t.Run("postgres", func(t *testing.T) {
		testRevokeByClient(t, newPostgresFactory(t)(t))
	})
}
