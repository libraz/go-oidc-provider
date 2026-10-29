package oidcdynamo

import "github.com/libraz/go-oidc-provider/op/store"

var _ store.SessionDurabilityReporter = (*sessionStore)(nil)

// Durable reports true: sessions live in DynamoDB and survive a restart.
func (s *sessionStore) Durable() bool { return true }
