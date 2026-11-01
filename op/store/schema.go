package store

import "context"

// SchemaValidator is implemented by a store that can check the persistent
// schema it reads and writes: a substore, a store held by a login-flow
// step, the user store, or the authn lockout store. op.New calls it at
// construction for every store the configuration uses, so a missing table
// or column fails construction instead of the first request that touches
// it. A store that does not implement it is not checked.
//
// ValidateSchema MUST only read the backend's catalog; it never creates,
// alters or drops anything. It returns nil when the schema matches.
//
// Stable since v1.5.
type SchemaValidator interface {
	ValidateSchema(ctx context.Context) error
}
