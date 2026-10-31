package tokenexchange

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// GrantType is the wire URN the dispatcher matches against the
// grant_type form parameter. It is duplicated here (rather than
// imported from op/) because internal/* must not import op/; the
// constant agrees byte-for-byte with op.TokenExchangeGrantType.
const GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// MaxActChainDepth caps the nested act chain at five levels. A request
// whose construction would produce a deeper chain is rejected with
// invalid_grant. Five accommodates a typical service-mesh fan-out
// (end-user → frontend → backend → mesh-egress) plus headroom.
const MaxActChainDepth = 5

// Token-type URNs accepted on the wire (RFC 8693 §3).
const (
	TokenTypeAccessToken = customgrant.IssuedTokenTypeAccessToken
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"      //nolint:gosec // URN, not a credential
	TokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token" //nolint:gosec // URN, not a credential

	// TokenTypeIDJAG names the Identity Assertion JWT Authorization
	// Grant (draft-ietf-oauth-identity-assertion-authz-grant §4.3) as a
	// requested_token_type and as the issued_token_type.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag" //nolint:gosec // URN, not a credential
)

// TokenView is the read-only projection of a verified subject_token
// or actor_token surfaced to the policy. It mirrors the public
// op.SubjectTokenView shape but stays internal so the handler can
// build it without touching op/.
type TokenView struct {
	// Type is the URN that named the token in the wire request.
	Type string

	// ClientID is the identifier of the client the original token was
	// issued to.
	ClientID string

	// Subject is the resolved sub of the original token.
	Subject string

	// Scope is the scope set the original token carried.
	Scope []string

	// Audience is the audience set the original token carried, in
	// RFC 8707 §2 normalised form.
	Audience []string

	// ExpiresAt is the wall-clock time the original token expires.
	ExpiresAt time.Time

	// Confirmation projects the cnf claim of the original token. Nil
	// when the token was unbound.
	Confirmation *Confirmation

	// ActChainDepth counts the existing nested act levels on the
	// original token.
	ActChainDepth int

	// Act is the raw act claim object carried on the original token,
	// or nil when the token had no act. Used by the chain builder to
	// preserve prior delegation history when nesting a new entry.
	Act map[string]any

	// AuthTime is when the subject authenticated, as the original token
	// states it. Zero when the token carries no auth_time; an exchange never
	// substitutes its own clock for it.
	AuthTime time.Time

	// GrantID is the grant the original token was issued under: the
	// "gid" claim, the opaque row's GrantID, or the consent record an
	// id_token was matched to. Empty when the token names none.
	GrantID string
}

// Confirmation mirrors op.ConfirmationProof for the internal layer. A
// token carrying both [JKT] and [X5tS256] is admitted (RFC 7800 §3 allows
// multiple confirmation methods); callers MUST verify every populated
// method against the request rather than short-circuiting on the first.
type Confirmation struct {
	JKT     string
	X5tS256 string
}

// RequestView is the input the [PolicyFunc] receives. The struct is
// the internal-package mirror of op.TokenExchangeRequest; the bridge
// in op/tokenexchange_adapter.go translates between the two shapes.
type RequestView struct {
	Client            *store.Client
	Subject           string
	SubjectToken      TokenView
	Actor             string
	ActorToken        *TokenView
	RequestedAudience []string
	RequestedScope    []string
	DPoPJKT           string
	DPoPJTI           string
	MTLSCert          *x509.Certificate
}

// Decision is the policy-side override bundle. Mirrors
// op.TokenExchangeDecision.
type Decision struct {
	GrantedScope      []string
	GrantedAudience   []string
	GrantedTTL        time.Duration
	IssueIDToken      *bool
	IssueRefreshToken *bool
	ExtraClaims       map[string]any
}

// PolicyFunc is the embedder-supplied admission hook bridged across
// the package boundary. The op-side adapter converts the public
// TokenExchangePolicy.Allow into this shape before constructing the
// handler so the internal package never imports op/.
type PolicyFunc func(ctx context.Context, req RequestView) (*Decision, error)

// IDJAGRequest is the input the [IDJAGPolicyFunc] receives. Mirrors
// op.IDJAGRequest; the bridge in op/tokenexchange_adapter.go translates
// between the two shapes.
type IDJAGRequest struct {
	Client   *store.Client
	Subject  string
	Audience string
	Resource []string
	Scope    []string
}

// IDJAGDecision mirrors op.IDJAGDecision.
type IDJAGDecision struct {
	ClientID string
	Scope    []string
	Resource []string
	Email    string
	TTL      time.Duration
}

// IDJAGPolicyFunc is the embedder-supplied ID-JAG issuance hook bridged
// across the package boundary, the ID-JAG counterpart of [PolicyFunc].
// The op-side adapter maps op.ErrIDJAGUnknownAudience and
// op.ErrIDJAGDenied onto [ErrIDJAGUnknownAudience] and [ErrIDJAGDenied].
type IDJAGPolicyFunc func(ctx context.Context, req IDJAGRequest) (*IDJAGDecision, error)

// Sentinels an [IDJAGPolicyFunc] returns; see op.ErrIDJAGUnknownAudience
// and op.ErrIDJAGDenied.
var (
	ErrIDJAGUnknownAudience = errors.New("tokenexchange: ID-JAG audience is not a known authorization server")
	ErrIDJAGDenied          = errors.New("tokenexchange: ID-JAG issuance denied")
)
