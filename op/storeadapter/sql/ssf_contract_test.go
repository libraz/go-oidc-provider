//go:build testcontainers

package oidcsql_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// TestMySQL_SSF runs the Shared Signals contract against MySQL, whose
// ClaimDue leases through a compare-and-swap UPDATE.
func TestMySQL_SSF(t *testing.T) {
	t.Parallel()
	contract.RunSSF(t, ssfFactory(newMySQLFactory(t)))
}

// TestPostgres_SSF runs the Shared Signals contract against PostgreSQL,
// whose ClaimDue leases through a compare-and-swap UPDATE.
func TestPostgres_SSF(t *testing.T) {
	t.Parallel()
	contract.RunSSF(t, ssfFactory(newPostgresFactory(t)))
}
