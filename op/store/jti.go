package store

import (
	"context"
	"time"
)

// ConsumedJTIStore records the JWT ID claim ("jti", RFC 7519 §4.1.7) of
// every JWT the library has accepted so that replays of the same JWT are
// rejected. The current call site is DPoP proof replay detection
// (RFC 9449 §11.1), but the contract is generic enough to also serve
// private_key_jwt assertions and any other "single-use JWT" feature that
// arrives later.
//
// ConsumedJTIStore is explicitly NOT part of the atomic-routing cluster. The
// operations are idempotent ("first writer wins; subsequent writers see
// already-consumed") and the store is safe to lose: the worst outcome of a
// total cache flush is a window of attacker-controlled replay equal to the
// JWT's remaining lifetime, which the cnf binding limits in practice.
type ConsumedJTIStore interface {
	// Mark records jti as consumed. It MUST return [ErrAlreadyConsumed]
	// if the same jti is already marked and that marker has not expired.
	// Backends MUST treat expired markers as absent: once the previous
	// expiresAt is at or before the backend's clock, a new Mark for the
	// same jti MUST succeed and replace the stale marker. expiresAt is
	// the wall-clock time at which the record may safely be discarded;
	// backends use it to drive TTL-based eviction. The caller is
	// responsible for computing expiresAt from the JWT's exp claim.
	Mark(ctx context.Context, jti string, expiresAt time.Time) error

	// Has reports whether jti has previously been marked. It MUST return
	// (false, nil) for unknown JTIs and (true, nil) for known ones; an
	// error return is reserved for transport faults. Backends MAY treat
	// expired entries as absent so that stale evictions are observable
	// to the caller.
	Has(ctx context.Context, jti string) (bool, error)
}
