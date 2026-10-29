package oidcredis

import "github.com/libraz/go-oidc-provider/op/store"

var _ store.SessionDurabilityReporter = (*sessionStore)(nil)

// Durable reports false: the adapter cannot tell whether the Redis
// deployment persists writes (AOF), so sessions are classed as volatile.
// Embedders running persistent Redis declare
// op.WithSessionDurabilityPosture(op.SessionDurabilityDurable).
func (s *sessionStore) Durable() bool { return false }
