package clientauth

import (
	"context"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// A single private_key_jwt verification resolves the same client through
// three seams — the assertion alg-pin check, the JWKS lookup, and (on a
// rotation miss) the cache-bypassing refetch — each of which loads the
// client record. Without memoisation that is 2 GetClient calls on the
// happy path and up to 4 with rotation recovery, all against the same id.
// For a SQL-backed ClientStore that is a real DB round-trip per seam,
// scaling with request rate.
//
// clientMemo caches GetClient results for the lifetime of one request
// context so the backing store is hit at most once per (context, client).
// The memo is context-scoped rather than resolver-scoped so it can never
// leak a stale client across requests: [withClientMemo] installs a fresh
// map at the start of each verification and it is discarded when the
// context goes out of scope.
type clientMemo struct {
	mu   sync.Mutex
	seen map[string]memoEntry
}

type memoEntry struct {
	client *store.Client
	err    error
}

type clientMemoKey struct{}

// withClientMemo returns a context carrying a fresh per-request client
// memo. If ctx already carries one (nested call), it is returned
// unchanged so the innermost caller owns the cache lifetime.
func withClientMemo(ctx context.Context) context.Context {
	if ctx.Value(clientMemoKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, clientMemoKey{}, &clientMemo{seen: make(map[string]memoEntry)})
}

// memoClientStore wraps a [store.ClientStore] so GetClient results are
// served from the context-scoped [clientMemo] when one is present. With
// no memo in context (any call path that did not pass through
// [withClientMemo]) it delegates straight through, so the wrapper is
// transparent outside assertion verification.
type memoClientStore struct {
	inner store.ClientStore
}

// GetClient implements [store.ClientStore], memoising the (client, err)
// pair per client id for the request context. The cached pointer is
// read-only to callers — the assertion seams only read JWKs / JWKsURI /
// TokenEndpointAuthSigningAlg — so sharing it across seams is safe.
func (m memoClientStore) GetClient(ctx context.Context, clientID string) (*store.Client, error) {
	memo, ok := ctx.Value(clientMemoKey{}).(*clientMemo)
	if !ok || memo == nil {
		return m.inner.GetClient(ctx, clientID)
	}
	memo.mu.Lock()
	if e, hit := memo.seen[clientID]; hit {
		memo.mu.Unlock()
		return e.client, e.err
	}
	memo.mu.Unlock()

	client, err := m.inner.GetClient(ctx, clientID)

	memo.mu.Lock()
	memo.seen[clientID] = memoEntry{client: client, err: err}
	memo.mu.Unlock()
	return client, err
}
