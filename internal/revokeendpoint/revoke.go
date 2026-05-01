package revokeendpoint

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// revokeToken dispatches to the JWT-acknowledgement or refresh-token
// branch based on the token's structural shape and the supplied hint.
// The function never surfaces an error: every failure path collapses
// onto a no-op so the caller can write a uniform 200 response per
// RFC 7009 §2.2.
//
// The hint dictates which branch tries first; both branches still
// run on miss because RFC 7009 §2.1 says the server MUST extend its
// search across all supported token types when the hint does not
// locate a record.
func revokeToken(
	ctx context.Context,
	deps Deps,
	verifier *tokens.AccessTokenVerifier,
	authenticatedClientID, token, hint string,
) {
	// The JWT branch only makes sense when the token actually looks
	// like a JWS; a non-JWT-shaped token would always miss there, so
	// short-circuit to opaque immediately to avoid pointless verifier
	// work (and the spurious "malformed JWT" log entries it would
	// emit).
	jwtShaped := looksLikeJWT(token)
	for _, branch := range branchOrder(hint, jwtShaped) {
		if branch(ctx, deps, verifier, authenticatedClientID, token) {
			return
		}
	}
}

// branchFn is the resolver shape shared by [revokeJWT] / [revokeOpaque].
// Returning a uniform signature lets [branchOrder] emit a slice the
// dispatcher can iterate without a per-hint switch inside
// [revokeToken] itself.
//
// The bool return is "this branch handled the token". A successful
// match (JWT verified + client match, or refresh-chain found and
// revoked) returns true and short-circuits the next branch; any
// other outcome returns false and falls through.
type branchFn func(
	ctx context.Context,
	deps Deps,
	verifier *tokens.AccessTokenVerifier,
	authenticatedClientID, token string,
) bool

// branchOrder returns the branches to try, in the order dictated by
// token_type_hint and the JWT-shape probe. An unrecognised or absent
// hint prefers JWT first when the shape matches, then opaque, per
// the RFC 7009 §2.1 fallthrough rule.
func branchOrder(hint string, jwtShaped bool) []branchFn {
	jwt := func() branchFn {
		if !jwtShaped {
			return nil
		}
		return revokeJWT
	}
	opq := func() branchFn {
		return func(ctx context.Context, deps Deps, _ *tokens.AccessTokenVerifier, c, t string) bool {
			return revokeOpaque(ctx, deps, c, t)
		}
	}
	switch hint {
	case hintRefreshToken:
		return appendNonNil(opq(), jwt())
	case hintAccessToken, "":
		return appendNonNil(jwt(), opq())
	default:
		return appendNonNil(jwt(), opq())
	}
}

// appendNonNil returns a slice containing only the non-nil branches.
// A nil entry means the JWT branch is disabled because the token
// does not look like a JWS; collapsing it out keeps [revokeToken]'s
// loop free of per-iteration nilness checks.
func appendNonNil(branches ...branchFn) []branchFn {
	out := make([]branchFn, 0, len(branches))
	for _, b := range branches {
		if b != nil {
			out = append(out, b)
		}
	}
	return out
}

// revokeJWT verifies token as a JWT-formatted access token and
// acknowledges the revocation when the embedded "client_id" matches
// the authenticated client. The acknowledgement is a no-op: v1.0
// does not maintain an access-token denylist, and the JWT will
// expire on its own at "exp". The bool return reports a successful
// acknowledgement so [revokeToken] can stop searching; false means
// the verifier rejected the token (or same-client-only failed) and
// the caller MUST fall through.
func revokeJWT(ctx context.Context, deps Deps, verifier *tokens.AccessTokenVerifier, authenticatedClientID, token string) bool {
	claims, _, err := verifier.Verify(token)
	if err != nil {
		return false
	}
	if claims.ClientID != authenticatedClientID {
		// Same-client-only: a token belonging to a different
		// client is silently ignored. RFC 7009 §2.2 forbids
		// leaking the failure mode through the status code, and
		// returning false here lets the opaque branch run on the
		// off chance the value also matches a refresh token (it
		// will not in practice, but the fallthrough keeps the
		// dispatcher uniform).
		return false
	}
	// Persist the revocation so a subsequent userinfo / introspection
	// call against the same token returns invalid_token /
	// {"active": false}. The shape depends on the configured ADR 0025
	// strategy; every branch is idempotent (missing row → nil) and
	// keeps the endpoint on the RFC 7009 §2.2 "always 200" path.
	switch deps.RevocationStrategy {
	case store.RevocationStrategyNone:
		// Stateless mode: the OP knowingly opted out of AT
		// revocation. RFC 7009 §2.2 still requires HTTP 200; the
		// caller writes the status. Nothing to persist.
	case store.RevocationStrategyJTIRegistry:
		if deps.AccessTokens != nil {
			_ = deps.AccessTokens.RevokeByJTI(ctx, claims.JTI)
		}
	default:
		// GrantTombstone (default): write a per-JTI denylist row.
		// ADR 0025 §Alternatives explicitly rejects coalescing a
		// single-AT revoke into a grant tombstone — the rest of the
		// grant stays alive. The denylist row's expiry is the AT's
		// own exp plus a 5-minute grace so it outlives any cache.
		if deps.GrantRevocations != nil {
			_ = deps.GrantRevocations.RevokeJTI(ctx, store.RevokedJTI{
				JTI:       claims.JTI,
				GrantID:   claims.GrantID,
				ExpiresAt: time.Unix(claims.ExpiresAt, 0).Add(5 * time.Minute).UTC(),
			})
		} else if deps.AccessTokens != nil {
			// Legacy fallback: GrantRevocations is unwired but the
			// JTI registry is. Use it so the cascade still works for
			// embedders mid-migration.
			_ = deps.AccessTokens.RevokeByJTI(ctx, claims.JTI)
		}
	}
	return true
}

// revokeOpaque looks token up in the opaque-format substores (opaque
// access tokens first, refresh tokens second) and revokes the matched
// record when the authenticated client owns it. The bool return
// reports a handled match; false means neither store had a row that
// matched the (token, client) pair (lookup missed, cross-client, or
// store fault), and the caller MUST fall through. RFC 7009 §2.2
// requires the HTTP response to be 200 in every one of these cases,
// so the caller writes 200 unconditionally and the bool exists purely
// to short-circuit the JWT fallthrough.
//
// The opaque-access-token substore is consulted first because the
// token endpoint's most-recent issuance for an embedder that opted
// into ADR 0024 is an opaque AT; the refresh-token branch is the
// long-standing path. Both nil substores collapse onto the no-op
// fallback.
func revokeOpaque(ctx context.Context, deps Deps, authenticatedClientID, token string) bool {
	if deps.OpaqueAccessTokens != nil {
		if revokeOpaqueAccessToken(ctx, deps, authenticatedClientID, token) {
			return true
		}
	}
	if deps.RefreshTokens == nil {
		return false
	}
	// [op/store.RefreshTokenStore.Find] is ID-keyed (godoc on the
	// store interface). The library's bearer-string format is the
	// row ID itself in the inmem reference adapter; backends that
	// hash bearer strings into the ID column hand the hashed ID
	// across the wire to clients (so the parameter the RP submits
	// at /revoke matches the stored ID). Either shape passes
	// through this lookup unchanged.
	rec, err := deps.RefreshTokens.Find(ctx, token)
	if err != nil || rec == nil {
		// ErrNotFound and any other store error collapse onto a
		// silent miss: RFC 7009 §2.2 forbids leaking which
		// sub-class produced the rejection.
		return false
	}
	if rec.ClientID != authenticatedClientID {
		// Same-client-only: a refresh token issued to another
		// client is silently ignored. The cross-client revoker
		// sees the same 200 a legitimate revoker would.
		return false
	}
	rootID, ok := findChainRoot(ctx, deps, rec.ID)
	if !ok {
		return false
	}
	if err := deps.RefreshTokens.RevokeChain(ctx, rootID); err != nil {
		// Store fault: the wire stays 200 (RFC 7009 §2.2) but the
		// audit channel surfaces the silent failure so SOC tooling
		// can detect a fosite-class GHSA-7mqr-2v3q-v2wm regression
		// where the OP claims success while persistence broke.
		emitRevokeFailed(ctx, deps, authenticatedClientID, "refresh_chain", err)
		return false
	}
	return true
}

// revokeOpaqueAccessToken handles the ADR 0024 opaque-format branch.
// The substore is asked to flip the row to revoked; the call is
// idempotent so a missing row returns nil. The function returns true
// when a live row matched the authenticated client and was flipped,
// false otherwise (miss, cross-client, store fault). Cross-client
// revocation attempts collapse onto false — RFC 7009 §2.2 forbids
// leaking the failure mode through the wire response, but the bool
// is consumed only by the dispatcher to short-circuit the JWT
// fallthrough; the cross-client revoker still sees the same 200 a
// legitimate revoker would.
func revokeOpaqueAccessToken(ctx context.Context, deps Deps, authenticatedClientID, token string) bool {
	rec, err := deps.OpaqueAccessTokens.Find(ctx, token)
	if err != nil || rec == nil {
		// ErrNotFound and any other store error collapse onto a
		// silent miss so the caller can fall through to the
		// refresh-token branch without leaking metadata.
		return false
	}
	if rec.ClientID != authenticatedClientID {
		// Same-client-only (ADR 0024 §S.8): a token issued to
		// another client is silently ignored. The cross-client
		// revoker sees the same 200 a legitimate revoker would.
		return false
	}
	if err := deps.OpaqueAccessTokens.RevokeByID(ctx, token); err != nil {
		// Store fault: see [revokeOpaque] — wire stays 200, audit
		// surfaces the failure for SOC observability.
		emitRevokeFailed(ctx, deps, authenticatedClientID, "opaque_access_token", err)
		return false
	}
	return true
}

// emitRevokeFailed raises [audit.Event] for a non-NotFound storage
// fault encountered while revoking. ErrNotFound (and nil-rec misses)
// are not faults — they collapse onto the "no such token" branch the
// caller already treats as 200. Only real persistence errors flow
// through this helper.
//
// The event keeps the wire response 200 per RFC 7009 §2.2 ("invalid
// tokens do not cause an error response") while still surfacing the
// fosite GHSA-7mqr-2v3q-v2wm class to operators: a token is recorded
// as "revocation requested but not committed" rather than silently
// disappearing.
func emitRevokeFailed(ctx context.Context, deps Deps, clientID, surface string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     "token.revoke_failed",
		Level:    audit.LevelError,
		Message:  "revoke endpoint encountered a storage fault while flipping a record",
		ClientID: clientID,
		Extras: map[string]any{
			"surface": surface,
			"err":     err.Error(),
		},
	})
}

// findChainRoot follows parent pointers from startID up to the
// chain's root, or returns ok=false when the walk fails or loops.
// The walk terminates at the first record whose ParentID is nil;
// [chainWalkLimit] caps the iteration count so a corrupted store
// cannot loop forever.
//
// The walk consumes [op/store.RefreshTokenStore.Find] — whose
// contract is "returns the refresh token identified by id" (see the
// godoc on [op/store.RefreshTokenStore.Find] for the wire-level
// statement). Both startID (the Find result of the bearer string
// supplied by the client) and every [op/store.RefreshToken.ParentID]
// it dereferences are interpreted as ID values, never as bearer
// secrets. The contract assumes the backend's ID space and ParentID
// pointer agree — the library guarantees this on every Save call —
// and a backend that hashes bearer strings into the ID column simply
// produces opaque IDs that this walk treats as such.
//
// The helper is a self-contained copy of
// [internal/grants/refresh.findChainRoot]; we deliberately do not
// import that package because its helper is unexported and the
// revoke endpoint is otherwise independent of the rotation
// machinery.
func findChainRoot(ctx context.Context, deps Deps, startID string) (string, bool) {
	current := startID
	for range chainWalkLimit {
		rec, err := deps.RefreshTokens.Find(ctx, current)
		if err != nil || rec == nil {
			return "", false
		}
		if rec.ParentID == nil {
			return current, true
		}
		current = *rec.ParentID
	}
	return "", false
}
