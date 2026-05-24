// Package devicecodekit ships the small embedder helpers that close
// the two foot-guns left around the RFC 8628 device-authorization
// surface in v0.9.1: the user_code brute-force gate that the
// embedder's verification page must run on every form POST, and the
// audit-emitting revoke wrapper that an embedder calls when the user
// denies a pending request or revokes a previously approved device.
//
// # Why a separate sub-package
//
// The two helpers compose the public [store.DeviceCodeStore]
// primitives that the OP itself never calls directly — the
// verification page and the revoke ceremony live in the embedder's
// HTTP layer, not in the OP's HTTP handler. Putting the helpers here
// rather than on the top-level op package keeps the public surface
// scoped: an embedder who builds their own verification page imports
// devicecodekit explicitly, and an embedder who has no device-flow
// code never sees the symbols.
//
// The package mirrors [github.com/libraz/go-oidc-provider/op/totpkit]:
// a small surface, no construction sentinel, every helper consumes a
// [Deps] bundle the embedder builds once at startup.
package devicecodekit

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/op/store"
)

// MaxUserCodeStrikes re-exports the brute-force ceiling the library
// applies per [store.DeviceCode] record. After this many mismatched
// user_code submissions [VerifyUserCode] transitions the record to
// Denied with reason [DenyReasonUserCodeLockout]. Embedders MAY surface
// the value in their UI ("you have N attempts remaining") but MUST NOT
// pass a different ceiling — the library treats this constant as the
// single source of truth across the verification page, the audit
// catalogue ([op.AuditDeviceCodeUserCodeBruteForce]), and the wire
// behaviour of the next /token poll on the locked-out record.
const MaxUserCodeStrikes = devicecode.MaxUserCodeStrikes

// Deny reasons the helpers stamp on [store.DeviceCodeStore.Deny]. The
// strings are stable and embedder-visible: SOC tooling subscribes to
// [op.AuditDeviceCodeRevoked] / [op.AuditDeviceCodeVerificationDenied]
// and reads the "reason" extra to triage. New reasons MAY be added in
// a minor release; existing values are part of the API surface and
// only renamed in a major release with a deprecation notice.
const (
	// DenyReasonUserCodeLockout is the reason the brute-force gate
	// stamps when [VerifyUserCode] crosses [MaxUserCodeStrikes]
	// mismatched submissions. Embedders MUST NOT use this value for
	// other denials — the wire posture (next /token poll returns
	// access_denied) is identical, but log-correlation tooling
	// distinguishes a user-driven deny from a brute-force lockout
	// through the reason string.
	DenyReasonUserCodeLockout = "user_code_lockout"

	// DenyReasonUserDenied is the conventional reason for an
	// explicit user-driven deny on the verification page. The library
	// itself does not stamp this value; it is exported so embedders
	// who want a single source of truth for the canonical deny
	// reasons can reference it.
	DenyReasonUserDenied = "user_denied"

	// DenyReasonUserRevokedDevice is the conventional reason for a
	// revocation that comes after the user has already approved the
	// request — for example, the user later visits a "manage
	// authorised devices" surface and removes the entry. Same
	// posture as DenyReasonUserDenied: exported for clarity, never
	// stamped by the library itself.
	DenyReasonUserRevokedDevice = "user_revoked_device"
)

// Sentinel errors the helpers surface so callers can dispatch on
// [errors.Is]. Each sentinel collapses a class of substore failures
// onto a stable comparison handle so a UI layer can render a single
// "code not recognised" message without inspecting the substore's
// internal shape.
var (
	// ErrUnknownDeviceCode is returned by [VerifyUserCode] and
	// [Revoke] when the substore reports no record matching the
	// supplied device_code. The verification page typically surfaces
	// this as "your session has expired, please scan the device's
	// code again"; the wire shape on the polling channel is
	// expired_token.
	ErrUnknownDeviceCode = errors.New("devicecodekit: device_code not found")

	// ErrAlreadyDecided is returned by [VerifyUserCode] and [Revoke]
	// when the record is no longer in the Pending state — the user
	// already approved or denied, the brute-force gate already fired,
	// or the token endpoint already consumed the row. The verification
	// page typically surfaces this as "this code has already been
	// used"; the embedder MUST NOT increment the strike counter or
	// re-fire the deny.
	ErrAlreadyDecided = errors.New("devicecodekit: device_code is no longer pending")

	// ErrInvalidArgument is returned when a caller passes an empty
	// device_code or user_code, or a nil [Deps]. The error is
	// programmer-facing rather than user-facing; callers that bubble
	// it past the boundary should treat it as a 500 in their HTTP
	// layer.
	ErrInvalidArgument = errors.New("devicecodekit: invalid argument")
)

// Deps bundles the runtime dependencies the helpers need. The
// embedder builds one [Deps] at startup (typically alongside the
// [op.New] call) and passes it to every helper invocation. The
// struct is intentionally small: only the substore is required;
// [Deps.Audit] defaults to the discard sink so the helper can call
// the emitter unconditionally.
type Deps struct {
	// DeviceCodes is the substore the helpers mutate. Required.
	// A nil value causes every helper to return [ErrInvalidArgument]
	// at the boundary so the embedder sees the misconfiguration on
	// the first call rather than a panic deep inside the helper.
	DeviceCodes store.DeviceCodeStore

	// Audit is the structured audit-event sink. The helpers emit
	// [op.AuditDeviceCodeUserCodeBruteForce] on every mismatched
	// user_code submission, [op.AuditDeviceCodeVerificationDenied]
	// when the brute-force gate fires the lockout, and
	// [op.AuditDeviceCodeRevoked] from [Revoke]. A nil emitter
	// collapses to the discard sink so the helpers stay safe to
	// invoke when the embedder has not wired audit observability
	// yet.
	Audit audit.Emitter

	// AccessTokens is the access-token registry the [Revoke] helper
	// cascades into: when a device authorization is revoked, every
	// access token issued from that device_code is revoked alongside
	// the record via [store.AccessTokenRegistry.RevokeByGrant]. The
	// device_code's ID is stamped verbatim as the GrantID on every
	// access token derived from that authorization, so the existing
	// per-grant cascade is sufficient. Optional: a nil registry
	// (JWT-stateless deployments with no shadow store, or embedders
	// that drive the cascade out-of-band) skips the cascade, and
	// [Revoke] still denies the authorization and emits the audit
	// event. When set, [op.AuditDeviceCodeRevoked] carries the
	// "revoked_access_tokens" count.
	AccessTokens store.AccessTokenRegistry
}

// auditEmitter returns the configured audit sink, or a discard
// emitter so call sites can invoke Emit unconditionally.
func (d *Deps) auditEmitter() audit.Emitter {
	if d == nil || d.Audit == nil {
		return audit.Discard()
	}
	return d.Audit
}

// VerifyUserCode runs the brute-force-protected user_code lookup
// embedders MUST call from the verification page handler before
// transitioning a Pending record to Approved.
//
// The lookup proceeds in three steps:
//
//  1. Resolve the record by deviceCodeID. The embedder identifies
//     the record through some out-of-band linkage (a session-bound
//     cookie set when the user landed on the verification page, the
//     `user_code` query string the device's QR code embedded, etc.);
//     this helper does not implement that linkage.
//  2. Constant-time-compare the canonicalised submittedUserCode
//     against the record's stored UserCode. The submittedUserCode is
//     normalised through [devicecode.NormaliseUserCode] before the
//     compare so a user typing "abcd-efgh" hits the same bytes the
//     library minted at /device_authorization.
//  3. On mismatch: increment the per-record strike counter. When the
//     post-increment value reaches [MaxUserCodeStrikes] the record
//     transitions to Denied with reason
//     [DenyReasonUserCodeLockout]; the audit emitter logs both the
//     per-strike event ([op.AuditDeviceCodeUserCodeBruteForce]) and
//     the lockout event ([op.AuditDeviceCodeVerificationDenied]).
//     A submission to a record that is already Denied returns
//     (false, [ErrAlreadyDecided]) without further strikes.
//
// The boolean return is true iff the canonicalised submission
// matches the stored UserCode. A nil error with matched=false
// indicates the strike was recorded; matched=true with nil error
// indicates the embedder may proceed to Approve. A non-nil error
// indicates the substore could not be consulted (transport fault,
// record absent, record already decided); the embedder MUST NOT
// call Approve in that case.
//
// Concurrency: the helper relies on the substore's per-record CAS
// for the strike-counter increment and the lockout transition.
// Two pollers racing the same submission both see their strike
// recorded; the lockout fires when the post-increment value
// crosses the ceiling, irrespective of which goroutine got there
// first. Backends that violate the substore contract by losing
// strikes break this guarantee.
func VerifyUserCode(ctx context.Context, deps *Deps, deviceCodeID, submittedUserCode string) (matched bool, err error) {
	if deps == nil || deps.DeviceCodes == nil {
		return false, ErrInvalidArgument
	}
	if deviceCodeID == "" || submittedUserCode == "" {
		return false, ErrInvalidArgument
	}

	canonical, err := devicecode.NormaliseUserCode(submittedUserCode)
	if err != nil {
		// A malformed submission (wrong length, characters outside
		// the Crockford alphabet) cannot match any stored user_code.
		// The library still records a strike so a brute-force loop
		// that probes the alphabet hits the lockout on the same
		// budget as a loop that probes well-formed values.
		canonical = ""
	}

	rec, lookupErr := deps.DeviceCodes.FindByDeviceCode(ctx, deviceCodeID)
	if lookupErr != nil {
		if errors.Is(lookupErr, store.ErrNotFound) {
			return false, ErrUnknownDeviceCode
		}
		return false, lookupErr
	}
	if rec.Status != store.DeviceCodeStatusPending {
		return false, ErrAlreadyDecided
	}

	if canonical != "" && constantTimeStringEqual(canonical, rec.UserCode) {
		return true, nil
	}

	return false, recordStrike(ctx, deps, deviceCodeID, rec.ClientID)
}

// recordStrike increments the per-record strike counter and, when
// the post-increment value crosses [MaxUserCodeStrikes], transitions
// the record to Denied with reason [DenyReasonUserCodeLockout]. The
// helper emits [op.AuditDeviceCodeUserCodeBruteForce] on every
// strike and [op.AuditDeviceCodeVerificationDenied] on the lockout
// transition.
func recordStrike(ctx context.Context, deps *Deps, deviceCodeID, clientID string) error {
	strikes, err := deps.DeviceCodes.IncrementUserCodeStrike(ctx, deviceCodeID)
	if err != nil {
		// A substore fault on the strike path is treated as fatal:
		// the verification page MUST NOT silently accept the next
		// submission as if the strike had landed. The caller surfaces
		// this as a 500 so an attacker cannot defeat the gate by
		// triggering a substore outage.
		return err
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     devicecode.AuditUserCodeBruteForce,
		Level:    audit.LevelWarn,
		Message:  "user_code mismatch on verification page",
		ClientID: clientID,
		Extras: map[string]any{
			"strikes":     int(strikes),
			"max_strikes": int(MaxUserCodeStrikes),
		},
	})
	if strikes < MaxUserCodeStrikes {
		return nil
	}
	// Lockout: transition to Denied. A racing strike that already
	// transitioned the record returns store.ErrConflict; treat that
	// (and the TTL-evicted row case) as a no-op because the lockout's
	// observable side effect is in place either way and the per-strike
	// audit signal already fired above.
	if denyErr := deps.DeviceCodes.Deny(ctx, deviceCodeID, DenyReasonUserCodeLockout); denyErr != nil {
		if !errors.Is(denyErr, store.ErrConflict) && !errors.Is(denyErr, store.ErrNotFound) {
			return denyErr
		}
		// Sentinel-class race absorbed; audit already emitted, lockout observable.
		return nil
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     devicecode.AuditVerificationDenied,
		Level:    audit.LevelWarn,
		Message:  "device_code denied: user_code brute-force lockout",
		ClientID: clientID,
		Extras: map[string]any{
			"reason":      DenyReasonUserCodeLockout,
			"strikes":     int(strikes),
			"max_strikes": int(MaxUserCodeStrikes),
		},
	})
	return nil
}

// Revoke transitions a Pending device-authorization record to Denied
// with the supplied reason, cascade-revokes every access token issued
// from that device_code, and emits an [op.AuditDeviceCodeRevoked] audit
// event.
//
// The cascade enacts the user-trust posture every device-flow OP should
// hold: "when the user revokes a device authorization, every access
// token issued from that device_code is revoked alongside the row." The
// device_code's ID is stamped verbatim as the GrantID on every access
// token derived from that authorization, so the cascade is a single
// [store.AccessTokenRegistry.RevokeByGrant] call. It runs only when
// [Deps.AccessTokens] is set; a nil registry (JWT-stateless or
// out-of-band deployments) skips the cascade while still denying the
// authorization and emitting the audit event. The audit event carries
// the "revoked_access_tokens" count when the cascade ran.
//
// Errors:
//   - [ErrInvalidArgument] when deps or deps.DeviceCodes is nil, or
//     when deviceCodeID is empty.
//   - [ErrUnknownDeviceCode] when the substore reports no matching
//     record.
//   - [ErrAlreadyDecided] when the record is no longer in Pending
//     (already Approved, Denied, or Consumed).
//   - Any substore transport error surfaces verbatim.
//   - A wrapped error when the access-token cascade fails after the
//     record was denied; the denial and audit event still stand, so a
//     caller seeing this error knows the authorization is revoked but
//     the token cascade did not complete.
//
// The reason argument is stamped onto the record's DenyReason field
// and the audit event's "reason" extra. Embedders SHOULD use one of
// the [DenyReasonUserDenied] / [DenyReasonUserRevokedDevice]
// constants for the canonical cases and a stable embedder-defined
// string otherwise (the SOC dashboard groups by this field).
func Revoke(ctx context.Context, deps *Deps, deviceCodeID, reason string) error {
	if deps == nil || deps.DeviceCodes == nil {
		return ErrInvalidArgument
	}
	if deviceCodeID == "" {
		return ErrInvalidArgument
	}
	// Resolve the record so the audit event can carry client_id;
	// the lookup also surfaces the canonical "not found" / "already
	// decided" sentinels at the boundary so embedders can dispatch
	// without inspecting the substore's internal shape.
	rec, err := deps.DeviceCodes.FindByDeviceCode(ctx, deviceCodeID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrUnknownDeviceCode
		}
		return err
	}
	if rec.Status != store.DeviceCodeStatusPending {
		return ErrAlreadyDecided
	}
	if err := deps.DeviceCodes.Deny(ctx, deviceCodeID, reason); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrUnknownDeviceCode
		case errors.Is(err, store.ErrConflict):
			// A racing approve / deny landed between the lookup and
			// the transition. The user-facing surface treats this as
			// "already decided" — the cascade-revoke audit signal is
			// suppressed because the record's terminal state was
			// not driven by this revoke call.
			return ErrAlreadyDecided
		default:
			return err
		}
	}
	// Cascade-revoke every access token issued from this device_code.
	// The device_code's ID is the GrantID stamped on each issued token,
	// so RevokeByGrant retires them all. The denial already stopped new
	// tokens; this revokes the ones already minted. A nil registry
	// skips the cascade (JWT-stateless or out-of-band deployments).
	revoked, cascadeErr := 0, error(nil)
	if deps.AccessTokens != nil {
		revoked, cascadeErr = deps.AccessTokens.RevokeByGrant(ctx, deviceCodeID)
	}
	extras := map[string]any{
		"device_code_id": deviceCodeID,
		"reason":         reason,
	}
	if deps.AccessTokens != nil {
		extras["revoked_access_tokens"] = revoked
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     devicecode.AuditRevoked,
		Level:    audit.LevelInfo,
		Message:  "device_code revoked",
		ClientID: rec.ClientID,
		Extras:   extras,
	})
	if cascadeErr != nil {
		return fmt.Errorf("devicecodekit: cascade revoke access tokens: %w", cascadeErr)
	}
	return nil
}

// constantTimeStringEqual reports whether a and b are byte-identical
// using a constant-time compare. The helper exists so the verify
// path's compare cannot leak the matching prefix length through
// timing — a partial match of the user_code is no different from a
// full mismatch as far as the wire response is concerned.
func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
