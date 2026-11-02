package inmem

import (
	"time"

	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// tokenRowOps reads the fields the JWT access-token registry and the opaque
// access-token store share, so their revocation, index and reclamation logic
// is written once. V is a pointer to the stored record type.
type tokenRowOps[V comparable] struct {
	grantID    func(V) string
	clientID   func(V) string
	expiresAt  func(V) time.Time
	revoked    func(V) bool
	setRevoked func(V)
}

// tokenIndex maps a grant or client to the primary keys of the rows that
// carry it, so administrative revocation visits only its target set.
type tokenIndex struct {
	byGrant  refreshIndex
	byClient refreshIndex
}

func newTokenIndex() tokenIndex {
	return tokenIndex{byGrant: make(refreshIndex), byClient: make(refreshIndex)}
}

func (o tokenRowOps[V]) track(idx tokenIndex, key string, rec V) {
	idx.byGrant.add(o.grantID(rec), key)
	idx.byClient.add(o.clientID(rec), key)
}

func (o tokenRowOps[V]) untrack(idx tokenIndex, key string, rec V) {
	idx.byGrant.remove(o.grantID(rec), key)
	idx.byClient.remove(o.clientID(rec), key)
}

// revokeIndexed flips Revoked on every not-yet-revoked row of m named by ids
// that satisfies match, and returns how many rows it flipped.
func revokeIndexed[V comparable](
	ops tokenRowOps[V], m map[string]V, ids map[string]struct{}, match func(V) bool,
) int {
	n := 0
	for key := range ids {
		rec, ok := m[key]
		if !ok || ops.revoked(rec) || !match(rec) {
			continue
		}
		ops.setRevoked(rec)
		n++
	}
	return n
}

// gcRows drops every row of m whose expiry is strictly before cutoff and
// retires its index entries. A zero expiry never matches.
func gcRows[V comparable](ops tokenRowOps[V], m map[string]V, idx tokenIndex, cutoff time.Time) int {
	n := 0
	for key, rec := range m {
		if !patterns.IsExpiredStrict(ops.expiresAt(rec), cutoff) {
			continue
		}
		ops.untrack(idx, key, rec)
		delete(m, key)
		n++
	}
	return n
}

// revokeStaged is the transactional counterpart of [revokeIndexed]: the
// candidates are the committed rows named by ids plus every row written in
// the transaction, each resolved through the overlay.
func revokeStaged[V comparable](
	ops tokenRowOps[V], st *overlay[V], clone func(V) V, ids map[string]struct{}, match func(V) bool,
) int {
	keys := make(map[string]struct{}, len(ids)+len(st.written))
	for key := range ids {
		keys[key] = struct{}{}
	}
	for key := range st.written {
		keys[key] = struct{}{}
	}
	var none V
	n := 0
	for key := range keys {
		rec := st.lookup(key)
		if rec == none || ops.revoked(rec) || !match(rec) {
			continue
		}
		updated := clone(rec)
		ops.setRevoked(updated)
		st.stage(key, updated)
		n++
	}
	return n
}
