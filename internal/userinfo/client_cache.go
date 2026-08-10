package userinfo

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/store"
)

// requestClientCache memoises the client lookup a single /userinfo
// request performs.
//
// Three consumers ask the registry for the same client_id: the
// deleted-client revocation probe, the pairwise subject projection, and
// the response-shape dispatch that decides between a JSON body and a
// signed JWT. Each was written to resolve the client on its own, so the
// number of backend reads depended on which combination happened to be
// active in a given configuration.
//
// Sharing one answer fixes that at one read regardless, and removes the
// window in which two consumers of the same request could disagree
// about whether the client exists because it was deleted between their
// lookups.
//
// An instance is created per request and used from the one goroutine
// serving it, so the memo carries no lock. It must not be placed in
// [HandlerDeps] at construction time.
type requestClientCache struct {
	inner store.ClientStore

	id     string
	client *store.Client
	err    error
	filled bool
}

// GetClient returns the memoised answer for id, resolving it on first
// use. A second id — which the current callers never ask for — bypasses
// the memo rather than overwriting it, so the shared answer stays tied
// to the token's own client_id.
func (c *requestClientCache) GetClient(ctx context.Context, id string) (*store.Client, error) {
	if c.filled && c.id == id {
		return c.client, c.err
	}
	client, err := c.inner.GetClient(ctx, id)
	if c.filled {
		return client, err
	}
	c.id, c.client, c.err, c.filled = id, client, err, true
	return client, err
}
