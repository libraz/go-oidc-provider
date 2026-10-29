package inmem

import "github.com/libraz/go-oidc-provider/op/store"

var _ store.SessionDurabilityReporter = (*sessionStore)(nil)

// Durable reports false: sessions live in process memory and are lost on
// restart.
func (s *sessionStore) Durable() bool { return false }
