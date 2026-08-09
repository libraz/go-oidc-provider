// Package authcode implements the authorization_code grant (RFC 6749 §4.1,
// OpenID Connect Core 1.0 §3.1.3).
//
// The package owns two state transitions:
//
//   - Issue: at the authorization endpoint, after the user has consented and
//     the OP has decided to mint a code. The package validates the PKCE
//     challenge, generates the opaque code ID, and persists the record via
//     [store.AuthorizationCodeStore.Save].
//
//   - Exchange: at the token endpoint, when the RP presents the code with a
//     PKCE verifier. The package consumes the code atomically (replay
//     protection) and verifies the client_id, redirect_uri, expiry, and PKCE
//     pair. The returned [Exchanged] value carries the fields the token
//     endpoint needs to mint access / id / refresh tokens.
//
// The package never reads the wall clock directly: callers inject a clock via
// [Issuer.Clock] / [Exchanger.Clock] so tests can advance time deterministically.
package authcode

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// IDLength is the byte length of randomly-generated authorization_code
// values. 32 bytes (256 bits) is well above the birthday bound for a single
// OP deployment and matches the recommendation in RFC 6819 §5.1.4.2.
const IDLength = 32

// TTLDefault is the default lifetime of an authorization code, applied when
// no override is configured. RFC 6749 §4.1.2 requires "short" TTLs and §10.5
// recommends a maximum of 10 minutes; the OP picks 60 seconds to keep the
// replay window narrow while spanning a typical browser redirect bounce.
const TTLDefault = 60 * time.Second

// Sentinel errors. The HTTP layer maps these to OAuth wire codes:
//
//   - ErrCodeMissing / ErrInvalidVerifier / ErrChallengeMismatch (PKCE
//     errors re-exported from [pkce]) → invalid_grant or invalid_request
//     depending on the layer.
//   - ErrClientMismatch / ErrRedirectURIMismatch → invalid_grant.
//   - ErrCodeReplayed → invalid_grant, plus the caller MUST revoke any
//     refresh tokens that descend from this grant (RFC 6819 §5.2.1.1).
//   - ErrCodeExpired → invalid_grant.
var (
	// ErrCodeMissing indicates the supplied code does not exist (or has
	// already been garbage-collected). Maps to invalid_grant.
	ErrCodeMissing = errors.New("authcode: code does not exist")

	// ErrCodeExpired indicates the code's ExpiresAt is in the past. The
	// store may also surface this as ErrNotFound when it garbage-collects
	// expired rows; both routes converge on invalid_grant.
	ErrCodeExpired = errors.New("authcode: code expired")

	// ErrCodeReplayed indicates the code was already consumed by a prior
	// token exchange. The token endpoint MUST revoke every refresh token
	// descending from this code's grant.
	ErrCodeReplayed = errors.New("authcode: code already consumed")

	// ErrClientMismatch indicates the authenticated client does not match
	// the client_id recorded at issuance.
	ErrClientMismatch = errors.New("authcode: client_id does not match")

	// ErrRedirectURIMismatch indicates the redirect_uri sent at the token
	// endpoint differs from the one presented at issuance (RFC 6749 §4.1.3).
	ErrRedirectURIMismatch = errors.New("authcode: redirect_uri does not match")
)

// ReplayError wraps [ErrCodeReplayed] with the grant id recorded on the
// consumed authorization code. Stores are allowed to hide consumed rows from
// Find, so the token endpoint needs this metadata on the replay error itself
// to run the RFC 6749 §4.1.2 descendant-token revocation cascade.
type ReplayError struct {
	GrantID string
}

func (e *ReplayError) Error() string { return ErrCodeReplayed.Error() }

func (e *ReplayError) Unwrap() error { return ErrCodeReplayed }

// ReplayGrantID extracts the grant id attached to a replay error, if the
// backing store surfaced it during Consume.
func ReplayGrantID(err error) string {
	var replay *ReplayError
	if errors.As(err, &replay) {
		return replay.GrantID
	}
	return ""
}

// Issuer mints authorization codes and persists them via a
// [store.AuthorizationCodeStore]. It is immutable after construction and
// safe for concurrent use.
type Issuer struct {
	store store.AuthorizationCodeStore
	clock func() time.Time
	ttl   time.Duration
}

// IssuerConfig is the parameter bundle for [NewIssuer].
type IssuerConfig struct {
	// Store is the substore the issuer will Save into; required.
	Store store.AuthorizationCodeStore

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
		return nil, errors.New("authcode: NewIssuer requires Store")
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

// IssueInput collects the parameters captured at the authorization endpoint.
// Field semantics mirror [store.AuthorizationCode]; see that type's godoc for
// the per-field invariants.
type IssueInput struct {
	ClientID            string
	Subject             string
	GrantID             string
	RedirectURI         string
	Scope               []string
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	State               string
	DPoPJKT             string
}

// Issue validates the PKCE pair, generates an opaque code, and persists the
// record. Required fields (ClientID, Subject, RedirectURI, CodeChallenge,
// CodeChallengeMethod) are checked; Scope, Nonce, and State are passed
// through verbatim.
//
// On success the returned string is the code value the OP places in the
// authorization response's "code" parameter.
func (i *Issuer) Issue(ctx context.Context, in IssueInput) (string, error) {
	if err := validateIssue(in); err != nil {
		return "", err
	}
	// PKCE is opt-in at the request layer: an empty challenge here means
	// the authorize layer accepted a non-PKCE request because the active
	// profile does not require it. The exchange-side check
	// ([Exchanger.Exchange]) mirrors this — when the stored challenge is
	// empty, the verifier is also forbidden, so a client cannot fabricate
	// a code_verifier for a code that was never bound to one.
	if in.CodeChallenge != "" {
		if err := pkce.ValidateChallenge(in.CodeChallenge, in.CodeChallengeMethod); err != nil {
			return "", err
		}
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := i.clock().UTC()
	rec := &store.AuthorizationCode{
		ID:                  id,
		ClientID:            in.ClientID,
		Subject:             in.Subject,
		GrantID:             in.GrantID,
		RedirectURI:         in.RedirectURI,
		Scope:               append([]string(nil), in.Scope...),
		Resource:            in.Resource,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		Nonce:               in.Nonce,
		State:               in.State,
		DPoPJKT:             in.DPoPJKT,
		ExpiresAt:           now.Add(i.ttl),
		CreatedAt:           now,
	}
	if err := i.store.Save(ctx, rec); err != nil {
		return "", fmt.Errorf("authcode: save: %w", err)
	}
	return id, nil
}

func validateIssue(in IssueInput) error {
	switch {
	case in.ClientID == "":
		return errors.New("authcode: Issue requires ClientID")
	case in.Subject == "":
		return errors.New("authcode: Issue requires Subject")
	case in.RedirectURI == "":
		return errors.New("authcode: Issue requires RedirectURI")
	}
	return nil
}

// Exchanger consumes authorization codes and validates the exchange. It is
// immutable after construction and safe for concurrent use.
type Exchanger struct {
	store store.AuthorizationCodeStore
	clock func() time.Time
}

// ExchangerConfig is the parameter bundle for [NewExchanger].
type ExchangerConfig struct {
	// Store is the substore the exchanger will Consume from; required.
	Store store.AuthorizationCodeStore

	// Clock returns the current wall-clock time. Defaults to
	// [timex.SystemClock.Now] when nil.
	Clock func() time.Time
}

// NewExchanger constructs an [Exchanger] from cfg.
func NewExchanger(cfg ExchangerConfig) (*Exchanger, error) {
	if cfg.Store == nil {
		return nil, errors.New("authcode: NewExchanger requires Store")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock.Now
	}
	return &Exchanger{store: cfg.Store, clock: clock}, nil
}

// ExchangeInput is the bundle of fields the token endpoint extracts from a
// "grant_type=authorization_code" request.
type ExchangeInput struct {
	// Code is the authorization_code value the RP presents.
	Code string

	// ClientID is the authenticated client's id (from client authentication
	// or the body's client_id parameter for public clients).
	ClientID string

	// RedirectURI is the redirect_uri parameter the RP sent. Must match
	// the value bound to the code at issuance (RFC 6749 §4.1.3).
	RedirectURI string

	// CodeVerifier is the PKCE verifier from RFC 7636. Required because
	// the OP rejects code issuance without a challenge.
	CodeVerifier string
}

// Exchanged is the projection of [store.AuthorizationCode] returned to the
// token endpoint after a successful exchange. It omits PKCE / state /
// redirect_uri because the token endpoint does not need to re-emit them.
type Exchanged struct {
	// ClientID is the client_id recorded at issuance, echoed for audit.
	ClientID string

	// Subject is the OP-internal stable identifier of the end-user.
	Subject string

	// GrantID points at the [store.Grant] record that captured the user's
	// consent — the token endpoint uses it to attach the freshly minted
	// refresh token to the same grant.
	GrantID string

	// Scope is the list of scopes the user consented to for this code.
	Scope []string

	// Resource is the RFC 8707 resource indicator the code was bound to.
	// Empty means the authorization request omitted the parameter.
	Resource string

	// Nonce is the nonce parameter the client supplied at the
	// authorization endpoint, copied into the issued ID Token.
	Nonce string

	// DPoPJKT is the SHA-256 thumbprint the client committed to via
	// the RFC 9449 §10 "dpop_jkt" parameter at the authorization
	// endpoint. Empty when no commitment was made. The token endpoint
	// rejects an inbound DPoP proof whose thumbprint does not match a
	// non-empty value here.
	DPoPJKT string

	// HadCodeChallenge reports whether the consumed code carried a
	// PKCE challenge at issuance. The token endpoint consults this to
	// run the RFC 9700 §2.1.1 downgrade guard: a public
	// client whose code was issued without PKCE MUST be rejected at
	// /token as defence-in-depth, regardless of the active profile's
	// PKCE-mandatory posture. Surfacing the bit instead of the raw
	// challenge string keeps the secret in the store while letting
	// the token endpoint observe the boolean fact.
	HadCodeChallenge bool

	// ConsumedAt is the wall-clock time at which the store committed the
	// consumption. It is populated by the store, not the clock injected
	// into the exchanger, so the audit trail reflects the persistence
	// layer's view of "when".
	ConsumedAt time.Time

	// IssuedAt is the wall-clock time at which the authorization code was
	// first persisted (its [store.AuthorizationCode.CreatedAt]). The token
	// endpoint uses it as the iat for the grant-tombstone mint-refusal
	// probe: a grant tombstoned after the code was issued MUST refuse
	// redemption even when the redemption happens later, so the probe is
	// keyed on the code's issuance instant — not the redemption clock —
	// mirroring the refresh path's use of the consumed token's IssuedAt.
	IssuedAt time.Time
}

// Exchange consumes the code and verifies the bindings recorded at issuance.
// On success the returned [Exchanged] carries the fields the token endpoint
// needs to mint tokens; on failure the returned error matches one of the
// sentinels declared in this package.
//
// Replay detection: when the underlying store returns
// [store.ErrAlreadyConsumed], Exchange returns [ErrCodeReplayed]. If the store
// also returns the consumed record, the error carries its GrantID; the token
// endpoint MUST revoke any refresh tokens that descend from this grant.
//
//nolint:gocognit // Exchange enumerates the code-replay / binding / expiry gates in flat shape; refactor would obscure spec mapping.
func (e *Exchanger) Exchange(ctx context.Context, in ExchangeInput) (*Exchanged, error) {
	if in.Code == "" {
		return nil, ErrCodeMissing
	}
	rec, err := e.consume(ctx, in.Code)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil, ErrCodeMissing
		case errors.Is(err, store.ErrAlreadyConsumed):
			if rec != nil && rec.GrantID != "" {
				return nil, &ReplayError{GrantID: rec.GrantID}
			}
			return nil, ErrCodeReplayed
		default:
			return nil, fmt.Errorf("authcode: consume: %w", err)
		}
	}
	if rec.ConsumedAt == nil {
		// A well-behaved store always sets ConsumedAt on a successful
		// Consume; treat a missing field as a backend bug.
		return nil, errors.New("authcode: store returned record without ConsumedAt")
	}
	if e.clock().UTC().After(rec.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	if rec.ClientID != in.ClientID {
		return nil, ErrClientMismatch
	}
	if rec.RedirectURI != in.RedirectURI {
		return nil, ErrRedirectURIMismatch
	}
	// PKCE is opt-in. When the issued record carries a challenge the
	// exchange MUST verify against it; when it does not the exchange
	// MUST forbid a code_verifier so a client cannot smuggle one onto
	// a code that was never bound to PKCE.
	if rec.CodeChallenge == "" {
		if in.CodeVerifier != "" {
			return nil, pkce.ErrVerifierMismatch
		}
	} else {
		if err := pkce.Verify(rec.CodeChallenge, rec.CodeChallengeMethod, in.CodeVerifier); err != nil {
			return nil, err
		}
	}
	return &Exchanged{
		ClientID:         rec.ClientID,
		Subject:          rec.Subject,
		GrantID:          rec.GrantID,
		Scope:            append([]string(nil), rec.Scope...),
		Resource:         rec.Resource,
		Nonce:            rec.Nonce,
		DPoPJKT:          rec.DPoPJKT,
		HadCodeChallenge: rec.CodeChallenge != "",
		ConsumedAt:       *rec.ConsumedAt,
		IssuedAt:         rec.CreatedAt,
	}, nil
}

// consume redeems the code and normalises the store-contract violation of a
// nil record returned alongside a nil error onto [store.ErrNotFound]: the
// exchange cannot prove the code was ever issued, so it takes the same path
// an unknown code takes rather than dereferencing the missing record.
func (e *Exchanger) consume(ctx context.Context, code string) (*store.AuthorizationCode, error) {
	rec, err := e.store.Consume(ctx, code)
	if err == nil && rec == nil {
		return nil, store.ErrNotFound
	}
	return rec, err
}

// newID returns a 256-bit base64url-encoded value suitable for the "code"
// parameter. The output uses the unpadded alphabet so it is URL-safe without
// further encoding.
func newID() (string, error) {
	buf := make([]byte, IDLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authcode: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
