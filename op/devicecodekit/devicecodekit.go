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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/redact"
	"github.com/libraz/go-oidc-provider/internal/timex"
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

// DefaultMaxAttemptKeys bounds the number of opaque ceremony keys retained by
// the built-in in-memory limiter. Deployments with a shared limiter can use a
// larger distributed budget, but the local fallback must not turn an attacker
// supplied attempt_key into an unbounded map.
const DefaultMaxAttemptKeys = 4096

// DefaultAttemptTTL is the maximum lifetime of an opaque manual-entry
// ceremony in the built-in limiter. Entries are evicted lazily on the next
// limiter operation after this deadline; no background goroutine is needed.
// The default follows the provider's default device-code lifetime.
const DefaultAttemptTTL = devicecode.DefaultExpiresIn

// Deny reasons the helpers stamp through [store.DeviceCodeStore.Deny]
// and [store.DeviceCodeStore.Revoke]. The strings are stable and
// embedder-visible: SOC tooling subscribes to
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

	// ErrAlreadyDecided is returned by [VerifyUserCode] when the record
	// is no longer in the Pending state — the user already approved or
	// denied, the brute-force gate already fired, or the token endpoint
	// already consumed the row. The verification page typically surfaces
	// this as "this code has already been used"; the embedder MUST NOT
	// increment the strike counter or re-fire the deny.
	ErrAlreadyDecided = errors.New("devicecodekit: device_code is no longer pending")

	// ErrInvalidArgument is returned when a caller passes an empty
	// device_code or user_code, or a nil [Deps]. The error is
	// programmer-facing rather than user-facing; callers that bubble
	// it past the boundary should treat it as a 500 in their HTTP
	// layer.
	ErrInvalidArgument = errors.New("devicecodekit: invalid argument")

	// ErrAttemptLocked is returned by the opaque-attempt-key manual-entry
	// helper after that key has consumed its complete atomic budget. The
	// rejection happens before normalization or lookup, so a correct code
	// cannot bypass a locked ceremony.
	ErrAttemptLocked = errors.New("devicecodekit: manual-entry attempt locked")

	// ErrMissingRevocationBackend is returned by [Revoke] when the
	// selected JWT revocation strategy has no configured persistence
	// backend. Revoke has already made the device authorization
	// non-issuable (or observed it as Consumed), but the caller MUST
	// wire the missing backend and retry before reporting that the
	// credential cascade completed.
	ErrMissingRevocationBackend = errors.New("devicecodekit: missing JWT revocation backend")
)

// Deps bundles the runtime dependencies the helpers need. The
// embedder builds one [Deps] at startup (typically alongside the
// [op.New] call) and passes it to every helper invocation. The
// DeviceCodes is always required. Revoke additionally requires the
// backend selected by RevocationStrategy: AccessTokens for JTIRegistry,
// GrantRevocations (or the documented AccessTokens migration fallback)
// for GrantTombstone, and no JWT backend for None. An unset audit sink
// defaults to discard so the helpers can call the emitter unconditionally.
type Deps struct {
	// DeviceCodes is the substore the helpers mutate. Required.
	// A nil value causes every helper to return [ErrInvalidArgument]
	// at the boundary so the embedder sees the misconfiguration on
	// the first call rather than a panic deep inside the helper.
	DeviceCodes store.DeviceCodeStore

	// AuditLogger is the audit sink of the helpers. The events land on
	// it as structured slog records carrying audit="true", the same
	// shape and the same routing attribute the OP writes through
	// op.WithAuditLogger, so one handler can serve both streams.
	// The helpers emit
	// [op.AuditDeviceCodeUserCodeBruteForce] on every mismatched
	// user_code submission, [op.AuditDeviceCodeVerificationApproved]
	// and [op.AuditDeviceCodeVerificationDenied] from the verification
	// page, and [op.AuditDeviceCodeRevoked] from [Revoke]. A nil logger
	// drops every record, so the helpers stay safe to invoke when the
	// embedder has not wired audit observability yet.
	//
	// The logger's handler is wrapped with the library redaction hook
	// (the same one op.WithAuditLogger applies) before any record is
	// written, so an attribute named after an OAuth/OIDC credential is
	// masked before it reaches the embedder's handler. Wrapping is
	// idempotent: a handler that already carries the hook is used as-is.
	//
	// The handler is invoked synchronously on the goroutine that ran the
	// helper, so it MUST be non-blocking — hand the record to a buffered
	// worker rather than shipping it inline — and safe for concurrent use.
	AuditLogger *slog.Logger

	// Audit is the structured audit-event sink used in preference to
	// AuditLogger when both are set.
	//
	// Deprecated: the field's interface type takes a package-internal
	// event type as its method argument, so no code outside this module
	// can implement it and the field can only be assigned from within
	// the library. Embedders wire AuditLogger instead; it carries the
	// same device-code events.
	Audit audit.Emitter

	// AccessTokens is the per-JTI JWT access-token registry [Revoke]
	// uses under [store.RevocationStrategyJTIRegistry], and the fallback
	// cascade used when GrantRevocations is absent during migration.
	// Optional when the selected strategy does not require it.
	AccessTokens store.AccessTokenRegistry

	// OpaqueAccessTokens stores opaque access-token records. When set,
	// Revoke retires every row whose GrantID matches the device_code.
	// Optional for JWT-only deployments.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// RefreshTokens stores refresh-token rotation chains. When set,
	// Revoke retires every chain whose GrantID matches the device_code.
	// Optional for deployments that never issue refresh tokens from the
	// device grant.
	RefreshTokens store.RefreshTokenStore

	// GrantRevocations stores JWT grant tombstones. Revoke writes a
	// tombstone here under the default
	// [store.RevocationStrategyGrantTombstone] strategy. Optional only
	// when AccessTokens provides the documented migration fallback.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token cascade shape.
	// The zero value is [store.RevocationStrategyGrantTombstone], matching
	// the provider default.
	RevocationStrategy store.AccessTokenRevocationStrategy

	// AccessTokenTTL is the longest JWT access-token lifetime used by
	// this provider. Revoke retains a grant tombstone for this duration
	// plus five minutes of clock-skew grace. A non-positive value uses
	// the provider default of five minutes.
	AccessTokenTTL time.Duration

	// Clock supplies the wall-clock instant written to grant tombstones.
	// A nil value uses the library system clock.
	Clock Clock

	// AttemptLimiter is the atomic limiter for the first-entry manual user_code
	// flow ([VerifyUserCodeByAttemptKey]). A nil value gets a private in-memory
	// limiter for this dependency bundle with [MaxUserCodeStrikes] attempts and
	// [DefaultAttemptTTL] key retention.
	// The pre-bound record APIs do not consult this limiter and retain their
	// existing per-record strike contract.
	AttemptLimiter AttemptLimiter

	limiterMu sync.Mutex
	limiter   AttemptLimiter
}

// AttemptLimiter atomically charges an opaque manual-entry key. Allow returns
// false without an error when the key is at capacity. Reset is an explicit
// ceremony-owner operation; VerifyUserCodeByAttemptKey does not call it
// because a valid code alone does not authenticate ownership of the opaque
// key. Implementations backed by a distributed store should make Allow a
// single compare-and-increment operation; separate read/increment calls are
// not safe.
type AttemptLimiter interface {
	Allow(ctx context.Context, attemptKey string) (bool, error)
	// Reset is an explicit ceremony-owner operation. The generic verification
	// helper never calls it because an opaque key alone does not prove that the
	// caller owns the ceremony; embedders may reset an authenticated ceremony
	// when they intentionally retire its key.
	Reset(ctx context.Context, attemptKey string) error
}

// attemptCountReader is an optional extension used only to enrich the
// brute-force audit event. Distributed limiters need not implement it; the
// attempt gate remains correct when the count is unavailable to the caller.
type attemptCountReader interface {
	Count(ctx context.Context, attemptKey string) (int, error)
}

// ManualEntryLimiter is a descriptive alias for [AttemptLimiter]. It is kept
// as a second spelling so embedder code can name the dependency by flow rather
// than by its implementation detail.
type ManualEntryLimiter = AttemptLimiter

// InMemoryAttemptLimiter is a small atomic limiter suitable for a single
// process or for tests. Production deployments that run multiple instances
// should provide an AttemptLimiter backed by their shared coordination store.
type InMemoryAttemptLimiter struct {
	mu       sync.Mutex
	max      uint8
	maxKeys  int
	ttl      time.Duration
	clock    Clock
	attempts map[string]attemptEntry
}

type attemptEntry struct {
	strikes   uint8
	expiresAt time.Time
}

// AttemptLimiterOptions configures the bounded in-memory implementation.
// The key capacity remains fixed at [DefaultMaxAttemptKeys] so configuration
// cannot accidentally turn this fallback into an unbounded map. A non-positive
// TTL uses [DefaultAttemptTTL]. Clock is primarily useful for deterministic
// tests; production callers normally leave it nil.
type AttemptLimiterOptions struct {
	TTL   time.Duration
	Clock Clock
}

// NewAttemptLimiter constructs an in-memory limiter. Non-positive limit values
// use the library's fixed manual-entry ceiling.
func NewAttemptLimiter(limit int) *InMemoryAttemptLimiter {
	return NewAttemptLimiterWithOptions(limit, AttemptLimiterOptions{})
}

// NewAttemptLimiterWithOptions constructs an in-memory limiter with bounded
// key retention. It is useful when an embedder wants a shorter ceremony TTL
// or needs to drive expiry from a deterministic clock in tests.
func NewAttemptLimiterWithOptions(limit int, options AttemptLimiterOptions) *InMemoryAttemptLimiter {
	if limit <= 0 {
		limit = int(MaxUserCodeStrikes)
	}
	if limit > 255 {
		limit = 255
	}
	ttl := options.TTL
	if ttl <= 0 {
		ttl = DefaultAttemptTTL
	}
	return &InMemoryAttemptLimiter{
		max:      uint8(limit),
		maxKeys:  DefaultMaxAttemptKeys,
		ttl:      ttl,
		clock:    options.Clock,
		attempts: make(map[string]attemptEntry),
	}
}

// NewInMemoryAttemptLimiter is an explicit spelling of [NewAttemptLimiter].
func NewInMemoryAttemptLimiter(limit int) *InMemoryAttemptLimiter {
	return NewAttemptLimiter(limit)
}

// Allow charges one manual user-code attempt to attemptKey and reports whether
// it remains within the bounded ceremony budget.
func (l *InMemoryAttemptLimiter) Allow(ctx context.Context, attemptKey string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if l == nil || attemptKey == "" {
		return false, ErrInvalidArgument
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictExpiredLocked(now)
	entry, exists := l.attempts[attemptKey]
	if !exists && len(l.attempts) >= l.maxKeys {
		// Fail closed when the local key budget is exhausted. A distributed
		// limiter can choose a different bounded policy; this fallback must
		// never grow in response to caller-controlled key material. Expired
		// ceremonies were evicted above, so a key can become available again
		// without an unbounded active-key eviction policy.
		return false, nil
	}
	if exists && entry.strikes >= l.max {
		return false, nil
	}
	if !exists {
		entry.expiresAt = now.Add(l.ttl)
	}
	entry.strikes++
	l.attempts[attemptKey] = entry
	return true, nil
}

// Reset removes the bounded attempt budget for attemptKey.
func (l *InMemoryAttemptLimiter) Reset(ctx context.Context, attemptKey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil || attemptKey == "" {
		return ErrInvalidArgument
	}
	l.mu.Lock()
	delete(l.attempts, attemptKey)
	l.mu.Unlock()
	return nil
}

// Count reports the number of charged attempts for an opaque key. It is an
// optional observability extension; Allow remains the atomic enforcement
// operation.
func (l *InMemoryAttemptLimiter) Count(ctx context.Context, attemptKey string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if l == nil || attemptKey == "" {
		return 0, ErrInvalidArgument
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictExpiredLocked(now)
	return int(l.attempts[attemptKey].strikes), nil
}

func (l *InMemoryAttemptLimiter) now() time.Time {
	if l.clock != nil {
		return l.clock.Now().UTC()
	}
	return timex.SystemClock.Now().UTC()
}

func (l *InMemoryAttemptLimiter) evictExpiredLocked(now time.Time) {
	for key, entry := range l.attempts {
		if !entry.expiresAt.After(now) {
			delete(l.attempts, key)
		}
	}
}

// Clock is the wall-clock surface [Deps] accepts for deterministic
// grant-tombstone timestamps.
type Clock interface {
	Now() time.Time
}

// auditEmitter returns the configured audit sink, or a discard
// emitter so call sites can invoke Emit unconditionally.
//
// [Deps.AuditLogger] is redact-wrapped here rather than at assignment
// time: Deps is a plain struct the embedder fills in field by field,
// so there is no constructor to run the wrap in, and the hook has to be
// in place before the first record reaches the embedder's handler.
// Wrapping is idempotent and allocation-cheap next to the emission
// itself, which happens once per verification-page submission.
func (d *Deps) auditEmitter() audit.Emitter {
	if d == nil {
		return audit.Discard()
	}
	if d.Audit != nil {
		return d.Audit
	}
	if d.AuditLogger == nil {
		return audit.Discard()
	}
	return audit.Slog(slog.New(redact.WrapHandler(d.AuditLogger.Handler())))
}

//nolint:ireturn // The configured limiter is an extension point; the fallback shares its interface.
func (d *Deps) attemptLimiter() AttemptLimiter {
	d.limiterMu.Lock()
	defer d.limiterMu.Unlock()
	if d.AttemptLimiter != nil {
		return d.AttemptLimiter
	}
	if d.limiter == nil {
		d.limiter = NewAttemptLimiter(int(MaxUserCodeStrikes))
	}
	return d.limiter
}

func (d *Deps) now() time.Time {
	if d != nil && d.Clock != nil {
		return d.Clock.Now().UTC()
	}
	return timex.SystemClock.Now().UTC()
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

// VerifyUserCodeByUserCode is the user_code-keyed variant of
// [VerifyUserCode]. It lets a verification page identify the pending
// record by a normalised user_code (for example one carried in a
// session-bound browser flow or QR-code URL) without ever receiving the
// polling bearer device_code.
func VerifyUserCodeByUserCode(ctx context.Context, deps *Deps, recordUserCode, submittedUserCode string) (matched bool, err error) {
	if deps == nil || deps.DeviceCodes == nil {
		return false, ErrInvalidArgument
	}
	if recordUserCode == "" || submittedUserCode == "" {
		return false, ErrInvalidArgument
	}
	recordCanonical, err := devicecode.NormaliseUserCode(recordUserCode)
	if err != nil {
		return false, ErrInvalidArgument
	}
	submittedCanonical, err := devicecode.NormaliseUserCode(submittedUserCode)
	if err != nil {
		submittedCanonical = ""
	}
	rec, lookupErr := deps.DeviceCodes.FindByUserCode(ctx, recordCanonical)
	if lookupErr != nil {
		if errors.Is(lookupErr, store.ErrNotFound) {
			return false, ErrUnknownDeviceCode
		}
		return false, lookupErr
	}
	if rec.Status != store.DeviceCodeStatusPending {
		return false, ErrAlreadyDecided
	}
	if submittedCanonical != "" && constantTimeStringEqual(submittedCanonical, rec.UserCode) {
		return true, nil
	}
	return false, recordStrikeByUserCode(ctx, deps, recordCanonical, rec.ClientID)
}

// VerifyUserCodeByAttemptKey is the first-entry manual user_code path. The
// caller supplies an opaque, stable attemptKey (for example a browser session
// or account-scoped ceremony id); the submitted code is never used as the
// limiter key. Allow is charged before normalization and before the store
// lookup, so malformed and unknown codes consume the same budget as valid
// guesses. A key at capacity returns [ErrAttemptLocked], even when the next
// code is correct, while a different key has an independent budget.
//
// A successful normalized lookup and constant-time comparison still consume
// the current key's charge. The helper cannot prove that an opaque key is an
// authenticated ceremony owned by the caller, so a valid code must not reset
// its budget and enable an attacker to loop over newly issued records. The
// embedder should mint a fresh key for a new authenticated ceremony; stale
// keys are released by the limiter TTL. Mismatches and all lookup/normalization
// failures likewise retain the charge. This helper deliberately leaves
// [VerifyUserCode] and [VerifyUserCodeByUserCode] unchanged for flows that
// already bind the attempt to a record.
func VerifyUserCodeByAttemptKey(ctx context.Context, deps *Deps, attemptKey, submittedUserCode string) (matched bool, err error) {
	if deps == nil || deps.DeviceCodes == nil || attemptKey == "" {
		return false, ErrInvalidArgument
	}
	allowed, err := deps.attemptLimiter().Allow(ctx, attemptKey)
	if err != nil {
		return false, err
	}
	if !allowed {
		return false, ErrAttemptLocked
	}

	canonical, normalizeErr := devicecode.NormaliseUserCode(submittedUserCode)
	if normalizeErr != nil {
		emitManualAttemptMismatch(ctx, deps, deps.attemptLimiter(), attemptKey, "")
		return false, ErrUnknownDeviceCode
	}
	rec, lookupErr := deps.DeviceCodes.FindByUserCode(ctx, canonical)
	if lookupErr != nil {
		if errors.Is(lookupErr, store.ErrNotFound) {
			emitManualAttemptMismatch(ctx, deps, deps.attemptLimiter(), attemptKey, "")
			return false, ErrUnknownDeviceCode
		}
		return false, lookupErr
	}
	if rec.Status != store.DeviceCodeStatusPending {
		return false, ErrAlreadyDecided
	}
	if !constantTimeStringEqual(canonical, rec.UserCode) {
		// The lookup key normally equals rec.UserCode, but retain a
		// defensive constant-time mismatch branch if a backend violates
		// its key contract. The opaque attempt charge remains consumed.
		emitManualAttemptMismatch(ctx, deps, deps.attemptLimiter(), attemptKey, rec.ClientID)
		return false, nil
	}
	return true, nil
}

func emitManualAttemptMismatch(ctx context.Context, deps *Deps, limiter AttemptLimiter, attemptKey, clientID string) {
	extras := map[string]any{
		"max_strikes": int(MaxUserCodeStrikes),
	}
	if reader, ok := limiter.(attemptCountReader); ok {
		if strikes, err := reader.Count(ctx, attemptKey); err == nil {
			extras["strikes"] = strikes
		}
	}
	// The opaque attempt key is deliberately absent: it is caller-controlled
	// ceremony material and may itself identify a browser session. Unknown and
	// malformed submissions still produce the same bounded mismatch evidence
	// as record-bound verification, but never disclose lookup or key material.
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     devicecode.AuditUserCodeBruteForce,
		Level:    audit.LevelWarn,
		Message:  "user_code mismatch on verification page",
		ClientID: clientID,
		Extras:   extras,
	})
}

// VerifyUserCodeWithAttemptKey is a compatibility spelling for
// [VerifyUserCodeByAttemptKey].
func VerifyUserCodeWithAttemptKey(ctx context.Context, deps *Deps, attemptKey, submittedUserCode string) (bool, error) {
	return VerifyUserCodeByAttemptKey(ctx, deps, attemptKey, submittedUserCode)
}

// ApproveUserCode transitions a Pending device authorization to
// Approved using only the human user_code as the record key. The helper
// is the verification-page companion to [VerifyUserCodeByUserCode]:
// embedders can build the whole browser approval path without exposing
// device_code to that browser.
func ApproveUserCode(ctx context.Context, deps *Deps, userCode, subject string, authTime time.Time) error {
	if deps == nil || deps.DeviceCodes == nil {
		return ErrInvalidArgument
	}
	if userCode == "" || subject == "" {
		return ErrInvalidArgument
	}
	canonical, err := devicecode.NormaliseUserCode(userCode)
	if err != nil {
		return ErrInvalidArgument
	}
	if err := deps.DeviceCodes.ApproveByUserCode(ctx, canonical, subject, authTime); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrUnknownDeviceCode
		case errors.Is(err, store.ErrConflict):
			return ErrAlreadyDecided
		default:
			return err
		}
	}
	// Emitted only after the substore has accepted the transition, so
	// the record says "approved" for every event in the log. The
	// substore's compare-and-swap is what makes this at-most-once: a
	// second approval of the same record returns ErrConflict above and
	// never reaches here.
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:    devicecode.AuditVerificationApproved,
		Level:   audit.LevelInfo,
		Message: "device_code approved at the verification page",
		ActorID: subject,
	})
	return nil
}

// DenyUserCode transitions a Pending device authorization to Denied
// using only the human user_code as the record key.
func DenyUserCode(ctx context.Context, deps *Deps, userCode, reason string) error {
	if deps == nil || deps.DeviceCodes == nil {
		return ErrInvalidArgument
	}
	if userCode == "" {
		return ErrInvalidArgument
	}
	canonical, err := devicecode.NormaliseUserCode(userCode)
	if err != nil {
		return ErrInvalidArgument
	}
	if err := deps.DeviceCodes.DenyByUserCode(ctx, canonical, reason); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrUnknownDeviceCode
		case errors.Is(err, store.ErrConflict):
			return ErrAlreadyDecided
		default:
			return err
		}
	}
	// The brute-force lockout raises the same event from recordStrike.
	// Both are genuine denials of the same record and only one can win
	// the substore's compare-and-swap, so the reason extra is what
	// separates a user declining from the OP locking the record.
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:    devicecode.AuditVerificationDenied,
		Level:   audit.LevelInfo,
		Message: "device_code denied at the verification page",
		Extras:  map[string]any{"reason": reason},
	})
	return nil
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

func recordStrikeByUserCode(ctx context.Context, deps *Deps, userCode, clientID string) error {
	strikes, err := deps.DeviceCodes.IncrementUserCodeStrikeByUserCode(ctx, userCode)
	if err != nil {
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
	if denyErr := deps.DeviceCodes.DenyByUserCode(ctx, userCode, DenyReasonUserCodeLockout); denyErr != nil {
		if !errors.Is(denyErr, store.ErrConflict) && !errors.Is(denyErr, store.ErrNotFound) {
			return denyErr
		}
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

// Revoke permanently disables a device authorization, cascade-revokes
// every credential issued from it, and emits an
// [op.AuditDeviceCodeRevoked] audit event.
//
// [store.DeviceCode.ID] is also the GrantID stamped on JWT access
// tokens, opaque access tokens, and refresh tokens issued by the device
// grant. Revoke uses that shared lineage to retire every configured
// credential surface:
//
//   - Pending and Approved records atomically transition to Denied, so a
//     later /token poll cannot issue credentials.
//   - Denied records remain Denied and retry the cascade.
//   - Consumed records remain Consumed and run the cascade, preserving
//     issuance history while retiring the already-issued credentials.
//
// The cascade dispatches JWT revocation through
// [Deps.RevocationStrategy], then independently retires opaque access
// tokens and refresh-token chains when their substores are configured.
// Every substore is attempted even if an earlier one fails. Repeating
// Revoke is safe and retries a partial cascade against the retained
// device-code record.
//
// Errors:
//   - [ErrInvalidArgument] when deps or deps.DeviceCodes is nil, or
//     when deviceCodeID is empty.
//   - [ErrUnknownDeviceCode] when the substore reports no matching
//     live record.
//   - [ErrMissingRevocationBackend] when the selected JWT strategy has
//     no configured store.
//   - Any substore transport error surfaces verbatim.
//   - A joined wrapped error when one or more credential cascades fail.
//     The device authorization is already non-issuable (or was already
//     Consumed), the audit event records cascade_complete=false, and the
//     caller can safely retry Revoke to finish the cascade.
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
	// Resolve the record so the audit event can carry client_id and the
	// pre-revocation lifecycle state. Revoke below is still the
	// authoritative atomic transition: Consume may race this lookup.
	rec, err := deps.DeviceCodes.FindByDeviceCode(ctx, deviceCodeID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrUnknownDeviceCode
		}
		return err
	}
	if err := deps.DeviceCodes.Revoke(ctx, deviceCodeID, reason); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrUnknownDeviceCode
		}
		return err
	}

	result, cascadeErr := revokeGrantCredentials(ctx, deps, deviceCodeID, reason)
	extras := map[string]any{
		"cascade_complete": result.complete,
		"device_code_hash": fingerprintDeviceCode(deviceCodeID),
		"previous_status":  rec.Status.String(),
		"reason":           reason,
	}
	if result.jwtRegistryAttempted {
		extras["revoked_access_tokens"] = result.jwtRegistryCount
	}
	if result.grantTombstoneAttempted {
		extras["grant_tombstone_written"] = result.grantTombstoneWritten
	}
	if result.opaqueAttempted {
		extras["revoked_opaque_access_tokens"] = result.opaqueCount
	}
	if result.refreshAttempted {
		extras["refresh_token_cascade_complete"] = result.refreshComplete
	}
	level := audit.LevelInfo
	if cascadeErr != nil {
		level = audit.LevelWarn
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     devicecode.AuditRevoked,
		Level:    level,
		Message:  "device_code revoked",
		ClientID: rec.ClientID,
		Extras:   extras,
	})
	if cascadeErr != nil {
		return fmt.Errorf("devicecodekit: cascade revoke grant credentials: %w", cascadeErr)
	}
	return nil
}

type revokeResult struct {
	complete                bool
	jwtRegistryAttempted    bool
	jwtRegistryCount        int
	grantTombstoneAttempted bool
	grantTombstoneWritten   bool
	opaqueAttempted         bool
	opaqueCount             int
	refreshAttempted        bool
	refreshComplete         bool
}

func revokeGrantCredentials(
	ctx context.Context,
	deps *Deps,
	grantID, reason string,
) (revokeResult, error) {
	result := revokeResult{complete: true}
	err := errors.Join(
		revokeJWTGrantCredentials(ctx, deps, grantID, reason, &result),
		revokeOpaqueGrantCredentials(ctx, deps, grantID, &result),
		revokeRefreshGrantCredentials(ctx, deps, grantID, &result),
	)
	result.complete = err == nil
	return result, err
}

func revokeJWTGrantCredentials(
	ctx context.Context,
	deps *Deps,
	grantID, reason string,
	result *revokeResult,
) error {
	switch deps.RevocationStrategy {
	case store.RevocationStrategyNone:
		return nil
	case store.RevocationStrategyJTIRegistry:
		if deps.AccessTokens == nil {
			return fmt.Errorf("%w: JTIRegistry requires AccessTokens", ErrMissingRevocationBackend)
		}
		return revokeJWTRegistryCredentials(ctx, deps.AccessTokens, grantID, result)
	case store.RevocationStrategyGrantTombstone:
		return revokeJWTTombstoneCredentials(ctx, deps, grantID, reason, result)
	default:
		return fmt.Errorf("%w: invalid revocation strategy %s", ErrInvalidArgument, deps.RevocationStrategy)
	}
}

func revokeJWTRegistryCredentials(
	ctx context.Context,
	reg store.AccessTokenRegistry,
	grantID string,
	result *revokeResult,
) error {
	if reg == nil {
		return nil
	}
	result.jwtRegistryAttempted = true
	n, err := reg.RevokeByGrant(ctx, grantID)
	result.jwtRegistryCount = n
	if err != nil {
		return fmt.Errorf("revoke JWT access tokens: %w", err)
	}
	return nil
}

func revokeJWTTombstoneCredentials(
	ctx context.Context,
	deps *Deps,
	grantID, reason string,
	result *revokeResult,
) error {
	if deps.GrantRevocations == nil {
		if deps.AccessTokens == nil {
			return fmt.Errorf(
				"%w: GrantTombstone requires GrantRevocations or the AccessTokens migration fallback",
				ErrMissingRevocationBackend,
			)
		}
		return revokeJWTRegistryCredentials(ctx, deps.AccessTokens, grantID, result)
	}
	result.grantTombstoneAttempted = true
	now := deps.now()
	ttl := deps.AccessTokenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	err := deps.GrantRevocations.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   grantID,
		RevokedAt: now,
		ExpiresAt: now.Add(ttl + 5*time.Minute),
		Reason:    reason,
	})
	result.grantTombstoneWritten = err == nil
	if err != nil {
		return fmt.Errorf("revoke JWT grant: %w", err)
	}
	return nil
}

func revokeOpaqueGrantCredentials(
	ctx context.Context,
	deps *Deps,
	grantID string,
	result *revokeResult,
) error {
	if deps.OpaqueAccessTokens == nil {
		return nil
	}
	result.opaqueAttempted = true
	n, err := deps.OpaqueAccessTokens.RevokeByGrant(ctx, grantID)
	result.opaqueCount = n
	if err != nil {
		return fmt.Errorf("revoke opaque access tokens: %w", err)
	}
	return nil
}

func revokeRefreshGrantCredentials(
	ctx context.Context,
	deps *Deps,
	grantID string,
	result *revokeResult,
) error {
	if deps.RefreshTokens == nil {
		return nil
	}
	result.refreshAttempted = true
	err := deps.RefreshTokens.RevokeByGrant(ctx, grantID)
	result.refreshComplete = err == nil
	if err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	return nil
}

func fingerprintDeviceCode(deviceCodeID string) string {
	sum := sha256.Sum256([]byte(deviceCodeID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
