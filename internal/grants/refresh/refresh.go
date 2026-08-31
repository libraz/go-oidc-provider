// Package refresh implements the refresh_token grant (RFC 6749 §6,
// OpenID Connect Core 1.0 §12, RFC 9700 §2.2.2 rotation + replay).
//
// The package owns three transitions:
//
//   - Issue: at the token endpoint, after a successful authorization_code
//     exchange OR rotation. The Issuer mints a fresh opaque token and
//     persists the [store.RefreshToken] record. The optional ParentID field
//     on [IssueInput] turns Issue into the second half of a rotation.
//
//   - Exchange: at the token endpoint, when the RP presents a refresh
//     token to renew its access token. The Exchanger consumes the token
//     atomically (via the store contract) and validates the client and
//     scope bindings. On success the caller invokes [Issuer.Issue] with
//     the consumed token's ID as ParentID to rotate.
//
//   - Replay defence: when [store.RefreshTokenStore.Consume] reports
//     [store.ErrAlreadyConsumed], the caller sees [ErrTokenReplayed] and
//     the rotation history is retired — walked to its chain root and passed
//     to [store.RefreshTokenStore.RevokeChain], or, when no root resolves,
//     retired grant-wide through [store.RefreshTokenStore.RevokeByGrant].
//     Who runs that cascade is decided by
//     [ExchangerConfig.DeferReplayCascade]: by default the Exchanger runs
//     it inline, and a caller that wraps Exchange in a [store.Tx] sets the
//     flag and calls [Exchanger.RevokeReplayedChain] itself once the
//     transaction has settled.
//
//     The refresh chain is the whole of what this package retires. Access
//     tokens issued under the same grant are retired by the caller, which
//     owns the access-token substores and the revocation strategy that
//     decides how a JWT access token is made to stop verifying; the
//     cascade entry points therefore return the grant they resolved.
//
// Like the authorization-code package, this layer never reads the wall
// clock directly; callers inject a clock so tests advance time
// deterministically.
package refresh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/refreshchain"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Audit event names sourced from the typed registry that backs the public
// op.AuditEvent catalog.
const (
	auditRefreshReplayDetected    = string(auditevent.AuditRefreshReplayDetected)
	auditRefreshChainRevokeFailed = string(auditevent.AuditRefreshChainRevokeFailed)
	auditRefreshGrantRevokeFailed = string(auditevent.AuditRefreshGrantRevokeFailed)
)

// IDLength is the byte length of a randomly-generated refresh token. 32
// bytes (256 bits) matches RFC 6819 §5.1.4.2 and the value used for
// authorization codes.
const IDLength = 32

// GraceTTLDefault is the default RFC 9700 §2.2.2 grace window during
// which a just-rotated refresh token is still accepted ("the previous
// refresh token MAY be invalidated but MUST remain valid until the new
// refresh token is delivered to the client successfully"). 60 seconds
// covers OFCS's 30-second probe between rotation and replay plus a
// margin for HTTP timeouts and slow retries; deployments that prefer
// stricter single-use semantics pass a negative
// [ExchangerConfig.GraceTTL] to disable the window entirely.
const GraceTTLDefault = 60 * time.Second

// Sentinel errors. The HTTP layer maps these to OAuth wire codes:
//
//   - ErrTokenMissing → invalid_grant.
//   - ErrTokenExpired → invalid_grant.
//   - ErrTokenReplayed → invalid_grant; the chain is retired by the
//     exchanger inline, or by the caller's [Exchanger.RevokeReplayedChain]
//     when it opted into [ExchangerConfig.DeferReplayCascade].
//   - ErrClientMismatch → invalid_grant.
//   - ErrScopeWidening → invalid_scope.
var (
	// ErrTokenMissing indicates the supplied token is empty or unknown.
	ErrTokenMissing = errors.New("refresh: token does not exist")

	// ErrTokenExpired indicates the consumed token's ExpiresAt is in
	// the past. The store may also surface expiry as ErrNotFound; both
	// converge on invalid_grant at the HTTP layer.
	ErrTokenExpired = errors.New("refresh: token expired")

	// ErrTokenReplayed indicates the token was consumed previously.
	// Unless the caller took ownership of the cascade through
	// [ExchangerConfig.DeferReplayCascade], the exchanger has already
	// retired the rotation history by the time this error is returned —
	// through [store.RefreshTokenStore.RevokeChain] on the chain root, or
	// [store.RefreshTokenStore.RevokeByGrant] when no root resolves; a
	// caller that did opt in MUST call [Exchanger.RevokeReplayedChain]
	// with the presented token.
	ErrTokenReplayed = errors.New("refresh: token already consumed")

	// ErrClientMismatch indicates the authenticated client does not match
	// the client_id recorded on the refresh token.
	ErrClientMismatch = errors.New("refresh: client_id does not match")

	// ErrScopeWidening indicates the requested scope contains an entry
	// not present in the token's bound scope. RFC 6749 §6 forbids
	// widening; downscoping is allowed.
	ErrScopeWidening = errors.New("refresh: requested scope widens grant")
)

// chainWalkLimit caps how far [Exchanger] walks parent pointers when
// computing a chain root after a replay detection. It is a resource guard
// against a pointer graph that loops or is otherwise corrupted, not a depth
// an honest rotation history cannot reach: nothing bounds the length of a
// legitimate chain, because every rotation slides the refresh-token expiry
// forward, so a grant that keeps being refreshed grows one node per refresh
// for as long as the client keeps refreshing it. Reaching the limit
// therefore MUST NOT weaken the RFC 9700 §2.2.2 cascade — see
// [Exchanger.revokeChainBestEffort], which falls back to the grant-scoped
// revocation, a superset of the chain.
const chainWalkLimit = 1024

// Issuer mints refresh tokens and persists them via a
// [store.RefreshTokenStore]. It is immutable after construction and safe
// for concurrent use.
type Issuer struct {
	store store.RefreshTokenStore
	clock func() time.Time
	ttl   time.Duration
}

// IssuerConfig is the parameter bundle for [NewIssuer].
type IssuerConfig struct {
	// Store is the substore the issuer will Save into; required.
	Store store.RefreshTokenStore

	// Clock returns the current wall-clock time. Defaults to
	// [timex.SystemClock.Now] when nil.
	Clock func() time.Time

	// TTL overrides [timex.RefreshTokenTTLDefault]. Zero or negative
	// values fall back to [timex.RefreshTokenTTLDefault].
	TTL time.Duration
}

// NewIssuer constructs an [Issuer] from cfg.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if cfg.Store == nil {
		return nil, errors.New("refresh: NewIssuer requires Store")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock.Now
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = timex.RefreshTokenTTLDefault
	}
	return &Issuer{store: cfg.Store, clock: clock, ttl: ttl}, nil
}

// IssueInput is the bundle passed to [Issuer.Issue]. ParentID is set
// during rotation (token endpoint after a successful Exchange) and left
// nil for fresh chains (token endpoint after a successful authorization
// code exchange).
type IssueInput struct {
	ClientID string
	Subject  string
	GrantID  string
	Scope    []string
	Resource string
	ParentID *string
	Origin   store.RefreshTokenOrigin

	SubjectPublic        bool
	AuthTime             time.Time
	ACR                  string
	AMR                  []string
	AuthorizationDetails []map[string]any
	AccessTokenExtra     map[string]any

	// DPoPJKT is the RFC 7638 thumbprint of the DPoP key the
	// associated access token is bound to (RFC 9449 §6.1). Non-empty
	// values are persisted on the [store.RefreshToken] record; the
	// rotation handler later requires a matching proof on every
	// refresh request. Empty means the refresh chain is bearer.
	DPoPJKT string

	// MTLSCertThumbprint is the RFC 8705 §3.1 thumbprint of the
	// client certificate the associated access token is bound to.
	// Non-empty values are persisted on the [store.RefreshToken]
	// record; the rotation handler later requires a matching cert
	// on every refresh request. Empty means the refresh chain is
	// not mTLS-bound.
	//
	// MTLSCertThumbprint and DPoPJKT are mutually exclusive on a
	// single record; the token endpoint never issues both at once.
	MTLSCertThumbprint string

	// Nonce is the OIDC Core 1.0 §3.1.2.1 nonce value from the
	// originating authorization request. The Issuer persists it on
	// the [store.RefreshToken] so the rotated id_token preserves it
	// per OIDC Core §12. Empty when the originating request omitted
	// the parameter.
	Nonce string
}

// Issue mints a new refresh token and persists it. It returns the opaque
// token value the OP places in the token response's "refresh_token"
// parameter.
func (i *Issuer) Issue(ctx context.Context, in IssueInput) (string, error) {
	id, rec, err := i.Prepare(in)
	if err != nil {
		return "", err
	}
	if err := i.store.Save(ctx, rec); err != nil {
		return "", fmt.Errorf("refresh: save: %w", err)
	}
	return id, nil
}

// Prepare mints a refresh-token bearer value and constructs its persistent
// record without writing it. Rotation callers use this to seal the complete
// token response (which contains the raw successor) before atomically storing
// both successor and retry response through store.RefreshRetryResponseStore.
func (i *Issuer) Prepare(in IssueInput) (string, *store.RefreshToken, error) {
	if err := validateIssue(in); err != nil {
		return "", nil, err
	}
	id, err := newID()
	if err != nil {
		return "", nil, err
	}
	now := i.clock().UTC()
	rec := &store.RefreshToken{
		ID:                   id,
		ClientID:             in.ClientID,
		Subject:              in.Subject,
		SubjectPublic:        in.SubjectPublic,
		GrantID:              in.GrantID,
		Scope:                slices.Clone(in.Scope),
		Resource:             in.Resource,
		Origin:               in.Origin,
		AuthTime:             in.AuthTime,
		ACR:                  in.ACR,
		AMR:                  slices.Clone(in.AMR),
		AuthorizationDetails: cloneObjectArray(in.AuthorizationDetails),
		AccessTokenExtra:     cloneClaims(in.AccessTokenExtra),
		ParentID:             cloneStringPtr(in.ParentID),
		ExpiresAt:            now.Add(i.ttl),
		CreatedAt:            now,
		DPoPJKT:              in.DPoPJKT,
		MTLSCertThumbprint:   in.MTLSCertThumbprint,
		Nonce:                in.Nonce,
	}
	return id, rec, nil
}

func validateIssue(in IssueInput) error {
	switch {
	case in.ClientID == "":
		return errors.New("refresh: Issue requires ClientID")
	case in.Subject == "":
		return errors.New("refresh: Issue requires Subject")
	case len(in.Scope) == 0:
		return errors.New("refresh: Issue requires Scope")
	}
	return nil
}

// Exchanger consumes refresh tokens and validates the rotation contract.
// It is immutable after construction and safe for concurrent use.
type Exchanger struct {
	store        store.RefreshTokenStore
	clock        func() time.Time
	graceTTL     time.Duration
	audit        audit.Emitter
	deferCascade bool
}

// ExchangerConfig is the parameter bundle for [NewExchanger].
type ExchangerConfig struct {
	Store store.RefreshTokenStore
	Clock func() time.Time

	// GraceTTL bounds the RFC 9700 §2.2.2 window during which a
	// just-rotated refresh token is still accepted. Three sentinels:
	//
	//   - Zero falls back to [GraceTTLDefault] (the typical case);
	//   - Positive values are used verbatim;
	//   - Negative values disable the window entirely so the
	//     exchanger returns [ErrTokenReplayed] on any re-presentation
	//     of a consumed token.
	//
	// When the window is in force and the presented token's
	// [store.RefreshToken.ConsumedAt] is at most GraceTTL in the past,
	// [Exchanger.Exchange] returns an [Exchanged] with
	// [Exchanged.InGrace] set to true so the caller skips the
	// rotation step (the canonical successor was already minted on
	// the first exchange).
	GraceTTL time.Duration

	// Audit, when non-nil, receives warn-level events when the chain
	// revoke side-effects of a replay detection encounter a transport
	// fault. The replay sentinel ([ErrTokenReplayed]) still surfaces
	// to the caller — the audit signal exists so SOC tooling can
	// distinguish "chain successfully revoked" from "chain revoke
	// silently failed" without grepping operational logs. Nil
	// collapses to [audit.Discard] so call sites do not need a nil
	// guard.
	Audit audit.Emitter

	// DeferReplayCascade hands ownership of the RFC 9700 §2.2.2 chain
	// cascade to the caller. When false (the default) [Exchanger.Exchange]
	// walks the chain and retires it inline before returning
	// [ErrTokenReplayed]. When true it only reports the replay, and the
	// caller MUST call [Exchanger.RevokeReplayedChain] with the presented
	// token to retire the chain.
	//
	// A caller that wraps Exchange in a [store.Tx] sets this. The cascade
	// touches one row per chain node, which a transactional backend has
	// to buffer against a bounded action limit,
	// so a long chain would be retired only in part — and breadth-first
	// from the root, leaving the newest node, the one a thief holds, alive.
	// Rollback would discard the cascade outright. Such a caller therefore
	// runs it after the transaction settles, on a non-transactional handle,
	// in both the commit and the rollback direction: the replay is the
	// finding regardless of what became of the rotation.
	DeferReplayCascade bool
}

// NewExchanger constructs an [Exchanger] from cfg.
func NewExchanger(cfg ExchangerConfig) (*Exchanger, error) {
	if cfg.Store == nil {
		return nil, errors.New("refresh: NewExchanger requires Store")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock.Now
	}
	graceTTL := cfg.GraceTTL
	switch {
	case graceTTL == 0:
		graceTTL = GraceTTLDefault
	case graceTTL < 0:
		graceTTL = 0 // explicit disable
	}
	em := cfg.Audit
	if em == nil {
		em = audit.Discard()
	}
	return &Exchanger{
		store:        cfg.Store,
		clock:        clock,
		graceTTL:     graceTTL,
		audit:        em,
		deferCascade: cfg.DeferReplayCascade,
	}, nil
}

// ExchangeInput is the bundle of fields the token endpoint extracts from
// a "grant_type=refresh_token" request.
type ExchangeInput struct {
	// Token is the refresh_token value the RP presents.
	Token string

	// ClientID is the authenticated client's id.
	ClientID string

	// RequestedScope is the optional "scope" parameter the RP supplied
	// to narrow the token's bound scope. Nil or empty means "use the
	// scope recorded at issuance verbatim".
	RequestedScope []string
}

// Exchanged is the projection of the consumed [store.RefreshToken]
// returned to the token endpoint after a successful exchange. It carries
// the fields the caller needs to build the response and to call
// [Issuer.Issue] with ParentID set to ConsumedID.
type Exchanged struct {
	// ConsumedID is the ID of the refresh token that was just consumed.
	// Callers pass this as ParentID when minting the next-generation
	// token via [Issuer.Issue].
	ConsumedID string

	// ClientID is the client_id recorded on the token, echoed for audit.
	ClientID string

	// Subject is the OP-internal stable identifier of the end-user.
	Subject string

	// SubjectPublic is copied from the consumed record. When true, the
	// token endpoint uses Subject as the already-public wire subject and
	// skips subject projection.
	SubjectPublic bool

	// GrantID points at the [store.Grant] that captured the user's
	// consent for the chain.
	GrantID string

	// Scope is the resulting scope: the caller's requested scope when
	// it narrowed the token, otherwise the token's bound scope.
	Scope []string

	// Resource is the RFC 8707 resource indicator the chain is bound to.
	// Empty means the originating grant omitted the parameter.
	Resource string

	Origin               store.RefreshTokenOrigin
	AuthTime             time.Time
	ACR                  string
	AMR                  []string
	AuthorizationDetails []map[string]any
	AccessTokenExtra     map[string]any

	// ConsumedAt is the wall-clock time at which the store committed
	// the consumption. It is populated by the store, not the exchanger's
	// clock, so the audit trail reflects the persistence layer.
	ConsumedAt time.Time

	// IssuedAt is the wall-clock time at which the consumed refresh
	// token was first persisted (its [store.RefreshToken.CreatedAt]).
	// The token endpoint reads it under
	// [store.RevocationStrategyGrantTombstone] to enforce the "iat <=
	// RevokedAt" mint-refusal rule before signing the rotated access
	// token: a tombstoned grant whose tombstone post-dates the chain's
	// first issuance MUST refuse a fresh AT, closing the race window.
	IssuedAt time.Time

	// DPoPJKT is the RFC 7638 thumbprint the chain was bound to at
	// issuance, copied verbatim from the consumed record. Empty means
	// the chain is bearer; non-empty means the rotation handler MUST
	// require a DPoP proof whose JWK thumbprint equals this value
	// before minting the next-generation token.
	DPoPJKT string

	// MTLSCertThumbprint is the RFC 8705 §3.1 thumbprint the chain
	// was bound to at issuance, copied verbatim from the consumed
	// record. Empty means the chain is not mTLS-bound; non-empty
	// means the rotation handler MUST require a client cert whose
	// DER bytes hash to this value before minting the next-
	// generation token.
	MTLSCertThumbprint string

	// Nonce is the OIDC Core 1.0 §3.1.2.1 nonce stamped on the chain
	// at the originating authorization request, copied verbatim from
	// the consumed record. The rotation handler threads it onto the
	// rotated id_token (OIDC Core §12) and onto the persisted next-
	// generation refresh token so the nonce survives an arbitrary
	// number of refreshes. Empty when the chain was not OIDC or when
	// the originating request omitted the parameter.
	Nonce string

	// InGrace reports that this exchange resolved through the RFC
	// 9700 §2.2.2 grace window: the presented token had already
	// been consumed within [ExchangerConfig.GraceTTL]. Callers MUST
	// NOT mint a new refresh token on the grace path — the original
	// rotation succeeded and its successor remains the canonical
	// next-generation token. When retry-response recovery is configured,
	// the token endpoint re-emits the sealed response from that original
	// successful rotation rather than minting another token set.
	InGrace bool
}

// Exchange consumes the token, verifies the bindings, and returns the
// projection the token endpoint needs to mint the next-generation
// refresh token. The package handles replay defence: when the underlying
// store reports [store.ErrAlreadyConsumed], Exchange consults the
// configured grace window — within it the presented token is treated
// as still valid (RFC 9700 §2.2.2) and an [Exchanged] with InGrace=true
// is returned; outside it [ErrTokenReplayed] is surfaced and the chain is
// retired, inline or through the caller's later
// [Exchanger.RevokeReplayedChain] depending on
// [ExchangerConfig.DeferReplayCascade].
func (e *Exchanger) Exchange(ctx context.Context, in ExchangeInput) (*Exchanged, error) {
	if in.Token == "" {
		return nil, ErrTokenMissing
	}
	rec, err := e.store.Consume(ctx, in.Token)
	if err == nil && rec == nil {
		// A nil record alongside a nil error violates the store contract.
		// The exchange cannot prove the token was ever issued, so it takes
		// the same path an unknown token takes.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			existing, handled, gerr := e.tryGrace(ctx, in)
			if handled {
				return existing, gerr
			}
		}
		return nil, e.mapConsumeError(ctx, in.Token, err)
	}
	if rec.ConsumedAt == nil {
		return nil, errors.New("refresh: store returned record without ConsumedAt")
	}
	if e.clock().UTC().After(rec.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	if rec.ClientID != in.ClientID {
		return nil, ErrClientMismatch
	}
	resolvedScope, err := resolveScope(rec.Scope, in.RequestedScope)
	if err != nil {
		return nil, err
	}
	return &Exchanged{
		ConsumedID:           rec.ID,
		ClientID:             rec.ClientID,
		Subject:              rec.Subject,
		SubjectPublic:        rec.SubjectPublic,
		GrantID:              rec.GrantID,
		Scope:                resolvedScope,
		Resource:             rec.Resource,
		Origin:               rec.Origin,
		AuthTime:             rec.AuthTime,
		ACR:                  rec.ACR,
		AMR:                  slices.Clone(rec.AMR),
		AuthorizationDetails: cloneObjectArray(rec.AuthorizationDetails),
		AccessTokenExtra:     cloneClaims(rec.AccessTokenExtra),
		ConsumedAt:           *rec.ConsumedAt,
		IssuedAt:             rec.CreatedAt,
		DPoPJKT:              rec.DPoPJKT,
		MTLSCertThumbprint:   rec.MTLSCertThumbprint,
		Nonce:                rec.Nonce,
	}, nil
}

// mapConsumeError translates raw store errors into refresh sentinels and,
// in the replay case, records the finding through
// [Exchanger.onReplayDetected] before returning [ErrTokenReplayed].
// Callers reach this only when the presented token is genuinely outside
// the [ExchangerConfig.GraceTTL] window — the grace branch in
// [Exchanger.Exchange] short-circuits before this function runs.
func (e *Exchanger) mapConsumeError(ctx context.Context, presentedID string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrTokenMissing
	case errors.Is(err, store.ErrAlreadyConsumed):
		e.onReplayDetected(ctx, presentedID)
		return ErrTokenReplayed
	default:
		return fmt.Errorf("refresh: consume: %w", err)
	}
}

// tryGrace looks up the (already-consumed) record and, when its
// ConsumedAt timestamp falls inside the configured grace window AND
// the presented credentials match the consumed record, returns the
// [Exchanged] projection callers should use without rotating the
// chain.
//
// The handled return signals whether the caller should treat the
// (existing, gerr) pair as the final answer or fall through to the
// regular replay path:
//
//   - handled=false: tryGrace did not engage (window disabled, record
//     missing, ConsumedAt outside the window); caller routes to
//     [Exchanger.mapConsumeError] which records the replay and surfaces
//     [ErrTokenReplayed].
//   - handled=true with gerr=nil: idempotent re-emission inside the
//     grace window; existing carries the projection.
//   - handled=true with gerr=[ErrTokenExpired]: the consumed record's
//     ExpiresAt is in the past; grace extends rotation idempotency,
//     not record lifetime, so the caller surfaces invalid_grant
//     without revoking the chain.
//
// Validation failure inside the grace window (client_id mismatch or
// scope widening) is treated as evidence of a stolen consumed token:
// per RFC 9700 §2.2.2 such replays MUST revoke the chain. tryGrace
// invokes [Exchanger.onReplayDetected] directly on that branch and
// returns handled=true with [ErrTokenReplayed] so the caller does not
// run [Exchanger.mapConsumeError] and double-count the replay. A caller
// that set [ExchangerConfig.DeferReplayCascade] owns the cascade for
// this branch too — the sentinel it keys off is the same one.
func (e *Exchanger) tryGrace(ctx context.Context, in ExchangeInput) (*Exchanged, bool, error) {
	if e.graceTTL <= 0 {
		return nil, false, nil
	}
	rec, err := e.store.Find(ctx, in.Token)
	if err != nil || rec == nil {
		if err == nil || errors.Is(err, store.ErrNotFound) {
			// A miss means the token cannot be proven inside the grace
			// window; fall through to the replay path.
			return nil, false, nil
		}
		// Transport faults are not replay evidence. Surface them as
		// server-side failures instead of revoking a healthy chain.
		return nil, true, fmt.Errorf("refresh: grace lookup: %w", err)
	}
	if !e.withinGraceWindow(rec) {
		return nil, false, nil
	}
	exchanged, gerr := e.graceExchange(rec, in)
	if gerr != nil {
		if errors.Is(gerr, ErrTokenExpired) {
			// Expiry is the record's own contract — the chain is
			// otherwise intact, and revoking it would penalise the
			// legitimate RP for a clock-skew race. Surface
			// invalid_grant directly without cascading the chain
			// revoke.
			return nil, true, gerr
		}
		// Validation failure inside the grace window (client mismatch
		// or scope widening). Surface as replay so the chain is
		// revoked: a consumed token presented by a different client,
		// or with a widened scope, is the same threat shape RFC 9700
		// §2.2.2 calls out. Record the replay explicitly here so the
		// cascade is anchored to the validation point without
		// double-emitting through mapConsumeError.
		e.onReplayDetected(ctx, in.Token)
		return nil, true, ErrTokenReplayed
	}
	return exchanged, true, nil
}

// onReplayDetected records a confirmed RFC 9700 §2.2.2 replay: it raises
// the replay audit event and, unless the caller took ownership through
// [ExchangerConfig.DeferReplayCascade], retires the chain inline.
//
// The audit event fires in both modes and at the same point, so a deferring
// caller cannot lose the finding by failing to run the cascade.
func (e *Exchanger) onReplayDetected(ctx context.Context, presentedID string) {
	e.emitReplayDetected(ctx, presentedID)
	if e.deferCascade {
		return
	}
	e.revokeChainBestEffort(ctx, presentedID)
}

// RevokeReplayedChain retires the rotation chain behind a replay the
// exchanger reported as [ErrTokenReplayed] while
// [ExchangerConfig.DeferReplayCascade] was set. presentedToken is the
// refresh_token value the client sent; the chain root and the grant it
// belongs to are both derived from it, so no other state has to survive
// the round trip from Exchange to here.
//
// The call is best effort in exactly the sense the inline cascade is: a
// transport fault raises a warn-level audit event and returns normally, so
// a caller that has already settled on invalid_grant never has to convert
// a storage failure into a server error. It is safe to call after the
// surrounding transaction has committed or rolled back — the presented
// record is already consumed either way, which is what the chain walk
// reads.
//
// The return is the grant the replayed chain was issued under, so the
// caller can retire the access tokens descended from the same grant. It
// is empty when the presented record no longer resolves; a caller MUST
// treat that as "the grant is unknown", not as "there is nothing left to
// retire".
func (e *Exchanger) RevokeReplayedChain(ctx context.Context, presentedToken string) string {
	if presentedToken == "" {
		return ""
	}
	return e.revokeChainBestEffort(ctx, presentedToken)
}

// emitReplayDetected fires [auditRefreshReplayDetected]. The Extras
// carry a [audit.Fingerprint] of the presented token rather than the
// raw value: the token is the bearer secret itself, and a custom
// [audit.Emitter] the embedder wires in has no guarantee of routing
// through the key-name redaction the built-in Slog emitter applies.
//
// The key deliberately avoids the word "token". Key-name redaction
// masks any attribute whose name contains it, and this event's only
// correlation field is what tells an operator which rotation chain
// was replayed — the single most security-relevant record the OP
// writes would otherwise reach the sink as the redaction sentinel.
// Exempting a token-shaped key name would instead carve a hole that
// any future caller could put a raw token through; naming the field
// after what it actually holds keeps both properties.
func (e *Exchanger) emitReplayDetected(ctx context.Context, presentedID string) {
	e.audit.Emit(ctx, audit.Event{
		Name:    auditRefreshReplayDetected,
		Level:   audit.LevelWarn,
		Message: "refresh-token replay detected",
		Extras: map[string]any{
			"refresh_chain_fingerprint": audit.Fingerprint(presentedID),
		},
	})
}

// graceExchange resolves a presented token whose ConsumedAt is at most
// [Exchanger.graceTTL] in the past. The function re-validates the
// client and scope bindings against the consumed record and returns an
// [Exchanged] with InGrace=true so the token endpoint can recover the
// response from the original rotation without rotating the refresh chain.
//
// The returned ConsumedID is the presented token's id rather than its
// canonical successor's: callers use ConsumedID only as the parent for
// the next rotation, and the grace path forbids rotation entirely.
// Surfacing the presented id keeps the audit trail aligned with the
// request.
func (e *Exchanger) graceExchange(rec *store.RefreshToken, in ExchangeInput) (*Exchanged, error) {
	// The strict (non-grace) path checks ExpiresAt after Consume; the
	// grace path runs against a Find-only record so we must apply the
	// same gate explicitly. Without it, a refresh whose ExpiresAt has
	// elapsed inside the grace window would still mint a fresh access
	// token — which the grace window must not permit: it
	// extends rotation idempotency, not record lifetime.
	if e.clock().UTC().After(rec.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	if rec.ClientID != in.ClientID {
		return nil, ErrClientMismatch
	}
	resolvedScope, err := resolveScope(rec.Scope, in.RequestedScope)
	if err != nil {
		return nil, err
	}
	return &Exchanged{
		ConsumedID:           rec.ID,
		ClientID:             rec.ClientID,
		Subject:              rec.Subject,
		SubjectPublic:        rec.SubjectPublic,
		GrantID:              rec.GrantID,
		Scope:                resolvedScope,
		Resource:             rec.Resource,
		Origin:               rec.Origin,
		AuthTime:             rec.AuthTime,
		ACR:                  rec.ACR,
		AMR:                  slices.Clone(rec.AMR),
		AuthorizationDetails: cloneObjectArray(rec.AuthorizationDetails),
		AccessTokenExtra:     cloneClaims(rec.AccessTokenExtra),
		ConsumedAt:           *rec.ConsumedAt,
		IssuedAt:             rec.CreatedAt,
		DPoPJKT:              rec.DPoPJKT,
		MTLSCertThumbprint:   rec.MTLSCertThumbprint,
		Nonce:                rec.Nonce,
		InGrace:              true,
	}, nil
}

// withinGraceWindow reports whether rec is eligible for the RFC 9700
// §2.2.2 grace re-emission: ConsumedAt is non-nil, the record was NOT
// revoked through [store.RefreshTokenStore.RevokeChain], and the
// timestamp is at most [Exchanger.graceTTL] in the past. A zero
// graceTTL is impossible after [NewExchanger] (it normalises
// non-positive inputs to the default), so the receiver-state guard
// is purely defensive.
func (e *Exchanger) withinGraceWindow(rec *store.RefreshToken) bool {
	if e.graceTTL <= 0 || rec == nil || rec.ConsumedAt == nil || rec.Revoked {
		return false
	}
	elapsed := e.clock().UTC().Sub(rec.ConsumedAt.UTC())
	return elapsed >= 0 && elapsed <= e.graceTTL
}

// revokeChainBestEffort retires the rotation history behind a detected
// replay. It is reached from [Exchanger.onReplayDetected] in the inline mode
// and from [Exchanger.RevokeReplayedChain] when the caller deferred the
// cascade.
//
// The cascade has two rungs, and it takes the second whenever the first
// cannot be shown to have run:
//
//   - Walk parent pointers to the chain root and call
//     [store.RefreshTokenStore.RevokeChain] on it. This retires exactly the
//     replayed chain.
//   - Otherwise call [store.RefreshTokenStore.RevokeByGrant] on the grant the
//     presented token was issued under. Every token in a chain inherits the
//     grant it was issued under, so the grant is a superset of the chain: the
//     fallback may retire sibling chains issued under the same consent, but it
//     cannot leave a live successor of the replayed chain behind.
//
// The second rung is what keeps [chainWalkLimit] from being load-bearing. A
// chain longer than the limit resolves no root, and a chain that long is the
// ordinary outcome of a client that has simply kept refreshing — the exact
// case where an attacker holding a live successor has had the most time to
// work with it. Retiring the whole grant is the safe direction there: RFC 9700
// §2.2.2 requires the compromised chain to die, and a warn-level log is not a
// revocation.
//
// Access tokens descended from the replayed chain are NOT retired here.
// Which mechanism makes a JWT access token stop verifying is a property of
// the caller's [store.AccessTokenRevocationStrategy], and an opaque access
// token lives in a substore this package does not hold; the resolved grant
// is returned instead so the caller runs that teardown through the one
// implementation every other grant-teardown site uses.
//
// The "best effort" qualifier covers the one state neither rung can act on:
// the presented record no longer resolves at all (already garbage-collected,
// store hiccup), leaving neither a chain root nor a grant to key on. That, and
// transport faults on either rung, are surfaced as warn-level audit events
// (auditRefreshChainRevokeFailed / auditRefreshGrantRevokeFailed) so SOC
// tooling can spot a silent failure even though the wire response stays at the
// user-visible invalid_grant contract via [ErrTokenReplayed].
func (e *Exchanger) revokeChainBestEffort(ctx context.Context, presentedID string) string {
	// The grant is resolved before anything is revoked. The fallback rung
	// and the caller's access-token teardown both key on it, and either
	// cascade rewrites the records it would otherwise have to be read back
	// from.
	grantID := e.presentedGrantID(ctx, presentedID)
	if !e.revokeChainFromRoot(ctx, presentedID) {
		e.revokeWholeGrant(ctx, grantID)
	}
	return grantID
}

// presentedGrantID resolves the grant the replayed token was issued under.
// presentedID is the bearer value the client sent, so it goes through the
// hash-only credential path rather than the chain-handle path. An empty
// result means the record could not be read at all; callers treat that as
// "no grant to cascade onto" rather than revoking the zero value.
func (e *Exchanger) presentedGrantID(ctx context.Context, presentedID string) string {
	rec, err := e.store.Find(ctx, presentedID)
	if err != nil || rec == nil {
		return ""
	}
	return rec.GrantID
}

// revokeChainFromRoot runs the chain-scoped rung and reports whether it
// completed. A false result means the replayed chain still has redeemable
// successors — the walk produced no root, or the store rejected the cascade —
// so the caller MUST run the grant-scoped rung.
func (e *Exchanger) revokeChainFromRoot(ctx context.Context, presentedID string) bool {
	rootID, ok := e.findChainRoot(ctx, presentedID)
	if !ok {
		e.emitChainRevokeFailed(ctx,
			"refresh chain root lookup failed after replay detection", "chain_root_lookup_failed")
		return false
	}
	if err := e.store.RevokeChain(ctx, rootID); err != nil {
		e.emitChainRevokeFailed(ctx,
			"refresh chain revoke failed after replay detection", err.Error())
		return false
	}
	return true
}

// revokeWholeGrant runs the grant-scoped rung of the cascade. An empty
// grantID is reported rather than ignored: it is the only state in which the
// OP has confirmed a replay and retired nothing.
func (e *Exchanger) revokeWholeGrant(ctx context.Context, grantID string) {
	if grantID == "" {
		e.emitChainRevokeFailed(ctx,
			"refresh grant lookup failed after replay detection", "grant_lookup_failed")
		return
	}
	if err := e.store.RevokeByGrant(ctx, grantID); err != nil {
		e.emitChainRevokeFailed(ctx,
			"refresh grant revoke failed after replay detection", err.Error())
	}
}

// emitChainRevokeFailed raises the warn-level signal that one rung of the
// post-replay cascade did not run. reason carries either a transport error or
// the name of the resolution step that produced nothing, so an operator can
// tell an unreachable backend from an unresolvable chain.
func (e *Exchanger) emitChainRevokeFailed(ctx context.Context, message, reason string) {
	e.audit.Emit(ctx, audit.Event{
		Name:    auditRefreshChainRevokeFailed,
		Level:   audit.LevelWarn,
		Message: message,
		Extras: map[string]any{
			"reason": reason,
		},
	})
}

// findChainRoot follows parent pointers up to the chain's root or returns
// ok=false if the walk fails / loops / exceeds [chainWalkLimit]. The walk
// terminates at the first record whose ParentID is nil.
func (e *Exchanger) findChainRoot(ctx context.Context, startID string) (string, bool) {
	return refreshchain.FindRoot(ctx, e.store, startID, chainWalkLimit)
}

// resolveScope returns the scope to bind to the rotated token. When the
// RP supplied a non-empty RequestedScope, the resolver verifies every
// requested entry is present in the token's bound scope (RFC 6749 §6
// forbids widening) and returns the requested list. When RequestedScope
// is empty the resolver returns a clone of the bound scope so callers do
// not share storage with the store.
func resolveScope(bound, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return slices.Clone(bound), nil
	}
	allowed := make(map[string]struct{}, len(bound))
	for _, s := range bound {
		allowed[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := allowed[s]; !ok {
			return nil, ErrScopeWidening
		}
	}
	return slices.Clone(requested), nil
}

// newID returns a 256-bit base64url-encoded value suitable for the
// refresh_token parameter.
func newID() (string, error) {
	buf := make([]byte, IDLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("refresh: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// cloneStringPtr returns a fresh *string with the same value as p, or
// nil when p is nil. The package returns its records to a store that
// shares pointer aliasing with later reads; cloning the parent pointer
// guards against accidental mutation through the original input.
func cloneStringPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneObjectArray(in []map[string]any) []map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, obj := range in {
		if obj == nil {
			continue
		}
		cp := make(map[string]any, len(obj))
		for k, v := range obj {
			cp[k] = v
		}
		out[i] = cp
	}
	return out
}

func cloneClaims(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
