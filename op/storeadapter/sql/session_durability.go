package oidcsql

import "github.com/libraz/go-oidc-provider/op/store"

var _ store.SessionDurabilityReporter = (*sessionStore)(nil)

// Durable reports true: sessions live in the SQL database and survive a
// restart. A SQLite ":memory:" database is not durable; use it for
// development only.
func (s *sessionStore) Durable() bool { return true }
