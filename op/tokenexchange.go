package op

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TokenExchangeGrantType is the wire URN the token endpoint matches
// against the grant_type parameter for RFC 8693 token-exchange
// requests. The constant is exported so embedders writing their own
// admission control or telemetry can compare without duplicating the
// literal.
//
// Stable since v0.9.1.
const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // URN, not a credential

// TokenExchangePolicy decides which subject / actor combinations may
// exchange tokens, and what the issued credential may carry. The
// interface is the embedder seam mandated by [RegisterTokenExchange];
// the provider rejects op.New when the option is supplied with a nil
// policy, so deployments cannot accidentally enable token-exchange
// without a deny-by-default hook.
//
// The provider runs every structural check (subject_token /
// actor_token verification, audience normalisation, scope downscope,
// audience filtering against client.Resources, TTL ceiling, act
// chain construction, cnf rebinding) before invoking [Allow]. The
// policy therefore never sees a request the provider would reject
// anyway; implementations focus on business rules — tenant
// isolation, client-pair allowlists, rate-of-exchange budgets,
// request-context risk scoring.
//
// Stable since v0.9.1.
type TokenExchangePolicy interface {
	// Allow is invoked once per token-exchange request after the
	// provider has resolved both tokens, normalised the audience,
	// and computed the default downscope set. The returned values
	// drive the issuance:
	//
	//   - A nil decision and nil error allow the exchange with
	//     every provider-computed default.
	//   - A non-nil decision and nil error allow the exchange with
	//     the named overrides (any zero-value field falls through
	//     to the provider default).
	//   - A non-nil error of type [*Error] denies the exchange and
	//     is preserved verbatim in the wire response.
	//   - A non-nil error of any other type collapses to
	//     invalid_grant on the wire; the original cause is logged
	//     server-side only.
	//
	// The callback runs in the request goroutine. Implementations
	// that consult external systems SHOULD wrap the body in
	// [context.WithTimeout] — the provider does not impose its own
	// deadline because policy latency profiles are deployment-
	// specific.
	Allow(ctx context.Context, req TokenExchangeRequest) (*TokenExchangeDecision, error)
}

// TokenExchangeRequest is the read-only projection passed to a
// [TokenExchangePolicy.Allow] call. Fields mirror RFC 8693 §2.1 with
// the entities resolved against the provider's stores. Handlers MUST
// NOT mutate any embedded slice or map; the provider retains the
// references for audit emission.
//
// Stable since v0.9.1.
type TokenExchangeRequest struct {
	// Client is the authenticated calling client — the principal
	// that submitted the token-exchange request. Non-nil; the
	// provider has already verified credentials and grant_type
	// allowance before reaching the policy.
	Client *store.Client

	// Subject is the resource owner the issued token will name in
	// its sub claim, resolved from subject_token. Non-zero on every
	// invocation; an unresolved subject is rejected structurally
	// before the policy runs.
	Subject Subject

	// SubjectToken is the read-only view of the verified
	// subject_token (type, scope, audience, expiry, confirmation).
	SubjectToken SubjectTokenView

	// Actor is the resolved actor identity for delegation requests,
	// nil for impersonation and self-exchange. When non-nil, the
	// value differs from [Subject]; a request whose actor_token
	// resolves to the same identity as the subject is rejected
	// before the policy runs.
	Actor *Subject

	// ActorToken is the read-only view of the verified actor_token,
	// nil when [Actor] is nil. The view's act-chain depth has
	// already been counted against the provider's nesting limit.
	ActorToken *SubjectTokenView

	// RequestedAudience is the audience list after RFC 8707 §2
	// normalisation (lowercase scheme + host, trailing-slash
	// stripped) and after default-fill from the subject_token's
	// audience when the request omitted the parameter. Non-empty
	// on every invocation.
	RequestedAudience []string

	// RequestedScope is the scope list after default-fill from the
	// subject_token's scope when the request omitted the parameter.
	// The set has already been intersected with the calling
	// client's allowed scopes; the policy may only narrow it
	// further.
	RequestedScope []string

	// DPoP is the public projection of the verified RFC 9449 proof
	// when the request presented one; nil otherwise. The provider
	// has already verified the proof and consumed the jti by the
	// time the policy runs. The issued token's cnf binding will be
	// stamped from this proof, not from the subject_token's
	// original confirmation.
	DPoP *DPoPProof

	// MTLSCert is the request's verified leaf certificate when the
	// calling client authenticated via RFC 8705 mTLS, nil
	// otherwise. The issued token's cnf.x5t#S256 will be the SHA-256
	// thumbprint of this certificate.
	MTLSCert *x509.Certificate
}

// TokenExchangeDecision carries the policy-side overrides applied to
// the provider-computed defaults. Every field is optional; a zero or
// nil value means "keep the provider default". The interpretation of
// each field is documented inline; cross-cutting rules (scope
// subset, audience subset, TTL ceiling) are enforced even when the
// policy returns explicit overrides — the values supplied here may
// only narrow, never broaden.
//
// Stable since v0.9.1.
type TokenExchangeDecision struct {
	// GrantedScope, when non-empty, replaces the provider-computed
	// scope set. The supplied entries MUST be a subset of
	// [TokenExchangeRequest.RequestedScope]; a value naming a scope
	// outside that set yields invalid_scope on the wire.
	GrantedScope []string

	// GrantedAudience, when non-empty, replaces the
	// provider-computed audience set. The supplied entries MUST be
	// a subset of [TokenExchangeRequest.RequestedAudience]; a value
	// naming an audience outside that set yields invalid_target on
	// the wire.
	GrantedAudience []string

	// GrantedTTL, when non-zero, narrows the issued access-token
	// lifetime below the provider-computed cap. A value greater
	// than the cap is silently truncated to the cap with an audit
	// warning; a negative value is rejected.
	GrantedTTL time.Duration

	// IssueIDToken, when non-nil, overrides the provider's
	// id_token-emission default. The default is true when the
	// subject_token was an id_token and false otherwise; the
	// policy may force either direction.
	IssueIDToken *bool

	// IssueRefreshToken, when non-nil, overrides the provider's
	// refresh_token-emission default. The default is false (refresh
	// on token-exchange is uncommon and creates long-lived chained
	// delegations); the policy MUST set the field to a non-nil
	// pointer-to-true to opt in. Issuance audits the decision.
	IssueRefreshToken *bool

	// ExtraClaims are merged into the id_token the provider signs
	// when [IssueIDToken] resolves to true. The reserved-claim
	// filter applies: keys naming protocol-managed claims (iss /
	// sub / aud / iat / exp / auth_time / nonce / acr / amr / azp /
	// at_hash / c_hash / sid / act) are dropped without error so
	// the policy cannot rewrite the act chain or hijack the sub.
	ExtraClaims map[string]any
}

// SubjectTokenView is the read-only projection of a verified
// subject_token or actor_token handed to a [TokenExchangePolicy].
// The fields are populated from the provider's stores
// ([store.AccessTokenRegistry] for JWT access tokens,
// [store.OpaqueAccessTokenStore] for opaque access tokens, the
// active signing keyset for id_tokens) so the policy can read
// scope, audience, and binding metadata without re-implementing
// verification.
//
// Stable since v0.9.1.
type SubjectTokenView struct {
	// Type is the URN that named this token in the wire request:
	// urn:ietf:params:oauth:token-type:access_token,
	// urn:ietf:params:oauth:token-type:jwt, or
	// urn:ietf:params:oauth:token-type:id_token. The provider
	// rejects any other value before the policy runs.
	Type string

	// ClientID is the identifier of the client the original token
	// was issued to. Used by self-exchange detection: when this
	// matches [TokenExchangeRequest.Client.ID], no act entry is
	// added for the calling client.
	ClientID string

	// Scope is the scope set the original token carried. The
	// provider has already verified the requested scope is a
	// subset of this value; policies inspect it for risk-scoring
	// or audit context.
	Scope []string

	// Audience is the audience set the original token carried.
	// Each entry is in its RFC 8707 §2 normalised form.
	Audience []string

	// ExpiresAt is the wall-clock time the original token expires.
	// The provider has already verified the value is in the
	// future; the policy may inspect the remaining TTL when
	// deciding whether to issue a shorter-lived exchange.
	ExpiresAt time.Time

	// Confirmation is the cnf claim the original token carried, or
	// nil when the token was unbound. The provider does not require
	// the issued token to inherit the binding mode (RFC 8693 is
	// silent on this and the rebinding to the request's own DPoP /
	// mTLS credential is the natural read), but policies that want
	// to refuse the unbind transition can read this field.
	Confirmation *ConfirmationProof

	// ActChainDepth is the number of nested act levels already
	// present on this token. The provider has already verified
	// that one more level (the calling actor) would not exceed
	// the maximum chain depth.
	ActChainDepth int
}

// ConfirmationProof is the public projection of an RFC 7800 cnf
// claim from a verified subject_token or actor_token. At most one
// of [JKT] and [X5tS256] is non-empty; both empty means the token
// was unbound (the cnf claim was absent).
//
// Stable since v0.9.1.
type ConfirmationProof struct {
	// JKT is the RFC 7638 SHA-256 thumbprint of the DPoP key the
	// original token was bound to, base64url-no-pad. Empty when
	// the token did not carry cnf.jkt.
	JKT string

	// X5tS256 is the SHA-256 thumbprint of the mTLS leaf
	// certificate the original token was bound to, base64url-no-
	// pad. Empty when the token did not carry cnf.x5t#S256.
	X5tS256 string
}
