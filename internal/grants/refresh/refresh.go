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
//     [store.ErrAlreadyConsumed], the Exchanger walks the rotation chain
//     to its root and calls [store.RefreshTokenStore.RevokeChain]
//     synchronously. The caller sees [ErrTokenReplayed] and is free to
//     surface invalid_grant without further bookkeeping.
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

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// IDLength is the byte length of a randomly-generated refresh token. 32
// bytes (256 bits) matches RFC 6819 §5.1.4.2 and the value used for
// authorization codes.
const IDLength = 32

// TTLDefault is the default lifetime of a refresh token. The library does
// not set a global maximum, but the default leans short to discourage
// "forever" tokens; deployments that need longer lifetimes set the TTL
// explicitly via [IssuerConfig].
const TTLDefault = 30 * 24 * time.Hour

// Sentinel errors. The HTTP layer maps these to OAuth wire codes:
//
//   - ErrTokenMissing → invalid_grant.
//   - ErrTokenExpired → invalid_grant.
//   - ErrTokenReplayed → invalid_grant; the chain has already been revoked
//     by the exchanger, so the caller does not need to call RevokeChain.
//   - ErrClientMismatch → invalid_grant.
//   - ErrScopeWidening → invalid_scope.
var (
	// ErrTokenMissing indicates the supplied token is empty or unknown.
	ErrTokenMissing = errors.New("refresh: token does not exist")

	// ErrTokenExpired indicates the consumed token's ExpiresAt is in
	// the past. The store may also surface expiry as ErrNotFound; both
	// converge on invalid_grant at the HTTP layer.
	ErrTokenExpired = errors.New("refresh: token expired")

	// ErrTokenReplayed indicates the token was consumed previously. The
	// exchanger has already invoked [store.RefreshTokenStore.RevokeChain]
	// on the chain root by the time this error is returned.
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
// computing a chain root after a replay detection. The limit is
// intentionally generous — production grants rotate at most once per
// access-token lifetime — but it prevents a corrupted store from looping
// forever.
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

	// TTL overrides [TTLDefault]. Zero or negative values fall back to
	// [TTLDefault].
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
		ttl = TTLDefault
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
	ParentID *string

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
}

// Issue mints a new refresh token and persists it. It returns the opaque
// token value the OP places in the token response's "refresh_token"
// parameter.
func (i *Issuer) Issue(ctx context.Context, in IssueInput) (string, error) {
	if err := validateIssue(in); err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := i.clock().UTC()
	rec := &store.RefreshToken{
		ID:                 id,
		ClientID:           in.ClientID,
		Subject:            in.Subject,
		GrantID:            in.GrantID,
		Scope:              slices.Clone(in.Scope),
		ParentID:           cloneStringPtr(in.ParentID),
		ExpiresAt:          now.Add(i.ttl),
		CreatedAt:          now,
		DPoPJKT:            in.DPoPJKT,
		MTLSCertThumbprint: in.MTLSCertThumbprint,
	}
	if err := i.store.Save(ctx, rec); err != nil {
		return "", fmt.Errorf("refresh: save: %w", err)
	}
	return id, nil
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
	store store.RefreshTokenStore
	clock func() time.Time
}

// ExchangerConfig is the parameter bundle for [NewExchanger].
type ExchangerConfig struct {
	Store store.RefreshTokenStore
	Clock func() time.Time
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
	return &Exchanger{store: cfg.Store, clock: clock}, nil
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

	// GrantID points at the [store.Grant] that captured the user's
	// consent for the chain.
	GrantID string

	// Scope is the resulting scope: the caller's requested scope when
	// it narrowed the token, otherwise the token's bound scope.
	Scope []string

	// ConsumedAt is the wall-clock time at which the store committed
	// the consumption. It is populated by the store, not the exchanger's
	// clock, so the audit trail reflects the persistence layer.
	ConsumedAt time.Time

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
}

// Exchange consumes the token, verifies the bindings, and returns the
// projection the token endpoint needs to mint the next-generation
// refresh token. The package handles replay defence: when the underlying
// store reports [store.ErrAlreadyConsumed], Exchange walks the chain
// root and revokes every descendant before returning [ErrTokenReplayed].
func (e *Exchanger) Exchange(ctx context.Context, in ExchangeInput) (*Exchanged, error) {
	if in.Token == "" {
		return nil, ErrTokenMissing
	}
	rec, err := e.store.Consume(ctx, in.Token)
	if err != nil {
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
		ConsumedID:         rec.ID,
		ClientID:           rec.ClientID,
		Subject:            rec.Subject,
		GrantID:            rec.GrantID,
		Scope:              resolvedScope,
		ConsumedAt:         *rec.ConsumedAt,
		DPoPJKT:            rec.DPoPJKT,
		MTLSCertThumbprint: rec.MTLSCertThumbprint,
	}, nil
}

// mapConsumeError translates raw store errors into refresh sentinels and,
// in the replay case, performs the chain revocation before returning
// [ErrTokenReplayed].
func (e *Exchanger) mapConsumeError(ctx context.Context, presentedID string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrTokenMissing
	case errors.Is(err, store.ErrAlreadyConsumed):
		e.revokeChainBestEffort(ctx, presentedID)
		return ErrTokenReplayed
	default:
		return fmt.Errorf("refresh: consume: %w", err)
	}
}

// revokeChainBestEffort walks parent pointers from presentedID up to the
// chain root and calls [store.RefreshTokenStore.RevokeChain] on it. The
// "best effort" qualifier reflects the failure modes: if the consumed
// record is no longer findable (already garbage-collected, store hiccup)
// we cannot compute a root and quietly drop the revocation. The token
// endpoint still returns invalid_grant via [ErrTokenReplayed], which is
// the user-visible contract.
func (e *Exchanger) revokeChainBestEffort(ctx context.Context, presentedID string) {
	rootID, ok := e.findChainRoot(ctx, presentedID)
	if !ok {
		return
	}
	_ = e.store.RevokeChain(ctx, rootID)
}

// findChainRoot follows parent pointers up to the chain's root or returns
// ok=false if the walk fails / loops. The walk terminates at the first
// record whose ParentID is nil; chainWalkLimit caps the iteration count.
func (e *Exchanger) findChainRoot(ctx context.Context, startID string) (string, bool) {
	current := startID
	for range chainWalkLimit {
		rec, err := e.store.Find(ctx, current)
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
