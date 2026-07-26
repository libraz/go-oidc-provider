package revokeendpoint

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/refreshchain"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

const (
	auditTokenRevoked      = string(auditevent.AuditTokenRevoked)
	auditTokenRevokeFailed = string(auditevent.AuditTokenRevokeFailed)
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
	// call against the same token returns invalid_token / {"active":
	// false}. The shape depends on the configured strategy; every branch
	// is idempotent (missing row → nil) and keeps the endpoint on the
	// RFC 7009 §2.2 "always 200" path.
	if err := endpointsupport.RevokeJWTAccessTokenByJTI(ctx, endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, claims.JTI, claims.GrantID, time.Unix(claims.ExpiresAt, 0).Add(5*time.Minute).UTC()); err != nil {
		emitRevokeFailed(ctx, deps, authenticatedClientID, "jwt_access_token", err)
	} else {
		emitRevoked(ctx, deps, revokedEvent{
			ClientID: authenticatedClientID,
			Subject:  claims.Subject,
			Surface:  "jwt_access_token",
			GrantID:  claims.GrantID,
			JTI:      claims.JTI,
		})
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
// The opaque-access-token substore is consulted first because for an
// embedder that opted into the opaque format, the token endpoint's
// most-recent issuance is an opaque AT; the refresh-token branch is
// the long-standing path. Both nil substores collapse onto the no-op
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
	// RFC 7009 §2.1 SHOULD: revoking a refresh token also invalidates the
	// access tokens issued under the same grant. Mirror the /end_session
	// cascade so a client that revokes to contain a compromise is not left
	// with live access tokens until their own exp.
	cascadeRevokeAccessTokens(ctx, deps, rec.GrantID)
	emitRevoked(ctx, deps, revokedEvent{
		ClientID: authenticatedClientID,
		Subject:  rec.Subject,
		Surface:  "refresh_chain",
		GrantID:  rec.GrantID,
	})
	return true
}

// cascadeRevokeAccessTokens propagates a refresh-token revocation to the
// access tokens issued under the same grant (RFC 7009 §2.1 SHOULD),
// mirroring the /end_session cascade. Both the JWT-strategy path and the
// opaque substore run best-effort: a store fault must not disturb the RFC
// 7009 §2.2 "always 200" wire posture, so errors are swallowed here (the
// refresh-chain revocation itself already succeeded before this runs).
func cascadeRevokeAccessTokens(ctx context.Context, deps Deps, grantID string) {
	if grantID == "" {
		return
	}
	now := revokeNow(deps)
	_ = endpointsupport.RevokeJWTAccessTokensByGrant(ctx, endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, grantID, now, revokeTombstoneRetention(deps.AccessTokenTTL), "revoke")
	if deps.OpaqueAccessTokens != nil {
		_, _ = deps.OpaqueAccessTokens.RevokeByGrant(ctx, grantID)
	}
}

// revokeTombstoneRetention returns the grant-tombstone retention window
// (AT TTL + 5-minute clock-skew grace; one-hour fallback for a zero TTL),
// mirroring the /end_session cascade's tombstoneRetention.
func revokeTombstoneRetention(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return ttl + 5*time.Minute
}

// revokeNow returns the wall-clock reading the cascade stamps on tombstone
// RevokedAt / ExpiresAt: a configured [Deps.Clock] wins, else
// [timex.SystemClock] (the single sanctioned wall-clock seam).
func revokeNow(deps Deps) time.Time {
	if deps.Clock != nil {
		return deps.Clock.Now().UTC()
	}
	return timex.SystemClock.Now().UTC()
}

// revokeOpaqueAccessToken handles the opaque-format branch. The
// substore is asked to flip the row to revoked; the call is
// idempotent so a missing row returns nil. The function returns true
// when a live row matched the authenticated client and was flipped,
// false otherwise (miss, cross-client, store fault). Cross-client
// revocation attempts collapse onto false — RFC 7009 §2.2 forbids
// leaking the failure mode through the wire response, but the bool is
// consumed only by the dispatcher to short-circuit the JWT
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
		// Same-client-only: a token issued to another client is silently
		// ignored. The cross-client revoker sees the same 200 a legitimate
		// revoker would.
		return false
	}
	if err := deps.OpaqueAccessTokens.RevokeByID(ctx, token); err != nil {
		// Store fault: see [revokeOpaque] — wire stays 200, audit
		// surfaces the failure for SOC observability.
		emitRevokeFailed(ctx, deps, authenticatedClientID, "opaque_access_token", err)
		return false
	}
	emitRevoked(ctx, deps, revokedEvent{
		ClientID: authenticatedClientID,
		Subject:  rec.Subject,
		Surface:  "opaque_access_token",
		GrantID:  rec.GrantID,
	})
	return true
}

type revokedEvent struct {
	ClientID string
	Subject  string
	Surface  string
	GrantID  string
	JTI      string
}

func emitRevoked(ctx context.Context, deps Deps, ev revokedEvent) {
	extras := map[string]any{
		"surface": ev.Surface,
	}
	if ev.GrantID != "" {
		extras["grant_id"] = ev.GrantID
	}
	if ev.JTI != "" {
		extras["jti"] = ev.JTI
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditTokenRevoked,
		Level:    audit.LevelInfo,
		Message:  "token revoked",
		ActorID:  ev.Subject,
		ClientID: ev.ClientID,
		Extras:   extras,
	})
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
		Name:     auditTokenRevokeFailed,
		Level:    audit.LevelError,
		Message:  "revoke endpoint encountered a storage fault while flipping a record",
		ClientID: clientID,
		Extras: map[string]any{
			"surface": surface,
			"err":     err.Error(),
		},
	})
}

// findChainRoot follows parent pointers from startID up to the chain's root,
// using the shared refreshchain helper so /revoke and the refresh-token grant
// honour the same ParentID round-trip contract.
func findChainRoot(ctx context.Context, deps Deps, startID string) (string, bool) {
	return refreshchain.FindRoot(ctx, deps.RefreshTokens, startID, chainWalkLimit)
}
