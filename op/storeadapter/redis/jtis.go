package oidcredis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// jtiStore implements [store.ConsumedJTIStore] against Redis. Mark uses
// SETNX (atomic create) so the "first writer wins" invariant the
// contract demands is enforced by the storage engine itself, not by
// the adapter — there is no GET / DEL race window.
type jtiStore struct {
	parent *Store
}

func newJTIStore(parent *Store) *jtiStore { return &jtiStore{parent: parent} }

// jtiKey hashes the supplied jti so the key length is bounded. JTI
// values come from JWT claims and may legitimately be long
// (RFC 7519 sets no upper bound); hashing guarantees a fixed 64-char
// hex suffix and does not leak the jti payload to anyone with redis
// SCAN access. The hash is not a secret — its only purpose is bounded
// length and deterministic key derivation.
func (j *jtiStore) jtiKey(jti string) string {
	h := sha256.Sum256([]byte(jti))
	return j.parent.prefix + "jti:" + hex.EncodeToString(h[:])
}

// Mark records jti as consumed. It returns [store.ErrAlreadyConsumed]
// when the same jti has been marked before, even when the previous
// expiresAt has not yet been reached. expiresAt drives the SETEX TTL;
// expiresAt in the past returns nil without writing (per the contract,
// already-expired records may be treated as absent on subsequent reads).
func (j *jtiStore) Mark(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := expiresAt.Sub(j.parent.clock.Now())
	if ttl <= 0 {
		// Past-dated marker: nothing to record, since any subsequent
		// Has call would treat the entry as absent anyway.
		return nil
	}
	ok, err := j.parent.client.SetNX(ctx, j.jtiKey(jti), "1", ttl).Result()
	if err != nil {
		return fmt.Errorf("oidcredis: SETNX jti: %w", err)
	}
	if !ok {
		return store.ErrAlreadyConsumed
	}
	return nil
}

// Has reports whether jti has previously been marked. Redis evicts
// expired keys lazily, so a hit on EXISTS guarantees the entry is
// still within its TTL and the contract's "expired entries MAY be
// treated as absent" clause is satisfied automatically.
func (j *jtiStore) Has(ctx context.Context, jti string) (bool, error) {
	n, err := j.parent.client.Exists(ctx, j.jtiKey(jti)).Result()
	if err != nil {
		return false, fmt.Errorf("oidcredis: EXISTS jti: %w", err)
	}
	return n > 0, nil
}
