package ciba

import (
	"errors"
	"slices"

	"github.com/libraz/go-oidc-provider/op/store"
)

// grantTypeWire is the CIBA Core §11 grant_type wire string. It is
// duplicated here (rather than imported from op/grant) so the
// authorization layer stays free of the public op/ namespace; the
// constant matches op/grant.CIBA.String() by construction and is
// covered by a compile-time assertion in the test suite.
const grantTypeWire = "urn:openid:params:grant-type:ciba"

// Sentinel errors. The HTTP layer maps these to OAuth wire codes:
//
//   - ErrGrantNotPermitted        → unauthorized_client.
//   - ErrScopeForbidden           → invalid_scope.
//   - ErrCnfBindingMismatch       → invalid_grant.
//   - ErrCnfBindingMissing        → invalid_grant.
//   - ErrPendingApproval          → authorization_pending (not strictly
//     a wire error here — the token-endpoint layer maps polling
//     state to the matching CIBA Core §11 wire code).
//   - ErrDenied                   → access_denied.
//   - ErrExpiredOrConsumed        → expired_token.
var (
	// ErrGrantNotPermitted indicates the client is not registered
	// for the CIBA grant. The check guards against a confidential
	// client repurposing a credential beyond the role embedders
	// intended.
	ErrGrantNotPermitted = errors.New("ciba: client is not permitted to use ciba")

	// ErrScopeForbidden indicates the granted scope contains an
	// entry outside the client's registered Scopes set. Mirrors the
	// devicecode-grant posture: any post-issue widening attempt is
	// refused rather than silently dropped.
	ErrScopeForbidden = errors.New("ciba: requested scope is not permitted for client")

	// ErrCnfBindingMismatch indicates the bc-authorize record
	// committed to a DPoP / mTLS thumbprint that does not match the
	// polling client's presented credential. This typically means a
	// third party stole the auth_req_id and is polling on the
	// consuming device's behalf; the issued token, even if minted,
	// would be bound to the legitimate device's key rather than the
	// attacker's.
	ErrCnfBindingMismatch = errors.New("ciba: cnf binding does not match the bc-authorize record")

	// ErrCnfBindingMissing indicates the consuming device committed
	// to a DPoP / mTLS thumbprint at /bc-authorize but the polling
	// /token request arrived without one. The token endpoint
	// refuses to mint an unbound token from a bound record.
	ErrCnfBindingMissing = errors.New("ciba: cnf binding required by record is missing on poll")

	// ErrPendingApproval signals the CIBA record is still in the
	// Pending state — the user has not yet approved on the
	// authentication device.
	ErrPendingApproval = errors.New("ciba: authorization is still pending")

	// ErrDenied signals the user explicitly denied the request, the
	// authentication device timed out, or the poll-abuse gate
	// terminated the record.
	ErrDenied = errors.New("ciba: authorization was denied")

	// ErrExpiredOrConsumed signals the auth_req_id expired before
	// the user approved, or the record was already consumed by an
	// earlier successful poll.
	ErrExpiredOrConsumed = errors.New("ciba: auth_req_id expired or already consumed")
)

// AuthorizeInput is the parameter bundle [Authorize] consumes.
type AuthorizeInput struct {
	// Client is the authenticated polling client. The caller has
	// already verified credentials; Authorize only consults policy
	// fields.
	Client *store.Client

	// Record is the resolved bc-authorize record. The caller has
	// already looked it up via [store.CIBARequestStore.FindByAuthReqID];
	// Authorize never performs I/O.
	Record *store.CIBARequest

	// PresentedDPoPJKT is the SHA-256 thumbprint of the DPoP key
	// the polling /token request presented (RFC 9449), or empty
	// when the request did not carry a proof.
	PresentedDPoPJKT string

	// PresentedMTLSCertS256 is the SHA-256 thumbprint of the mTLS
	// leaf certificate the polling /token request presented (RFC
	// 8705), or empty when the connection was not mTLS-
	// authenticated.
	PresentedMTLSCertS256 string
}

// Authorized is the successful return of [Authorize].
type Authorized struct {
	// Scope is the granted scope set, freshly allocated so the
	// caller may mutate it without affecting the input.
	Scope []string

	// Audience is the list of resource indicators the issued
	// access token's aud claim will carry, freshly allocated and
	// already RFC 8707 §2 normalised by the bc-authorize handler.
	Audience []string

	// Subject is the OP-internal stable identifier of the
	// approving end-user, taken verbatim from the record.
	Subject string

	// SenderConstraint names the binding stamped on the eventual
	// access token: "dpop", "mtls", or "bearer". The caller uses
	// this to decide cnf claim shape and to populate the
	// ciba.token.issued audit extras.
	SenderConstraint string

	// ACRValues is the slice of Authentication Context Class
	// References the CIBA record committed to at /bc-authorize.
	// The caller threads them onto the issued id_token's acr / amr
	// claims when present; an empty slice signals "no acr claim
	// requested".
	ACRValues []string
}

// Authorize applies the CIBA-specific authorization gates:
//
//  1. Client must list the CIBA grant in its registered grant_types.
//  2. Record state must be Approved (Pending → pending wire code,
//     Denied → denied, Expired/Consumed → expired_token; Authorize
//     surfaces the cause via the matching sentinel).
//  3. cnf binding presented at /token must match the binding the
//     consuming device committed to at /bc-authorize. Empty matches
//     empty (bearer flow); a record-side binding without a request-
//     side one is a silent downgrade attempt.
//  4. The record's scope is the binding ceiling; Authorize re-checks
//     the subset relationship against the client's registered
//     Scopes so a post-issue client mutation cannot widen the grant.
//
// The function is deliberately silent on TTL bucketing and
// refresh-token issuance: those are token-endpoint concerns the
// caller composes separately.
func Authorize(in AuthorizeInput) (*Authorized, error) {
	if in.Client == nil {
		return nil, errors.New("ciba: nil client")
	}
	if in.Record == nil {
		return nil, errors.New("ciba: nil ciba-request record")
	}
	if !slices.Contains(in.Client.GrantTypes, grantTypeWire) {
		return nil, ErrGrantNotPermitted
	}
	if err := mapStatusToError(in.Record.Status); err != nil {
		return nil, err
	}
	binding, err := matchCnfBinding(in)
	if err != nil {
		return nil, err
	}
	if err := requireScopeSubset(in.Record.Scope, in.Client.Scopes); err != nil {
		return nil, err
	}
	return &Authorized{
		Scope:            slices.Clone(in.Record.Scope),
		Audience:         slices.Clone(in.Record.Resource),
		Subject:          in.Record.Subject,
		SenderConstraint: binding,
		ACRValues:        slices.Clone(in.Record.ACRValues),
	}, nil
}

// mapStatusToError translates a [store.CIBARequestStatus] value into
// the matching package sentinel. The handler at the call site
// translates each sentinel into the wire CIBA Core §11 / RFC 6749
// §5.2 code alongside the audit extras.
func mapStatusToError(s store.CIBARequestStatus) error {
	switch s {
	case store.CIBARequestStatusApproved:
		return nil
	case store.CIBARequestStatusPending:
		return ErrPendingApproval
	case store.CIBARequestStatusDenied:
		return ErrDenied
	case store.CIBARequestStatusConsumed:
		return ErrExpiredOrConsumed
	default:
		return ErrExpiredOrConsumed
	}
}

// matchCnfBinding compares the binding stored on the record against
// the one the polling client presented. It returns the binding label
// ("dpop", "mtls", or "bearer") on success, [ErrCnfBindingMissing]
// when the record requires a binding the request did not present,
// and [ErrCnfBindingMismatch] when the labels differ or the
// thumbprints do not match.
func matchCnfBinding(in AuthorizeInput) (string, error) {
	switch {
	case in.Record.DPoPJKT != "":
		if in.PresentedDPoPJKT == "" {
			return "", ErrCnfBindingMissing
		}
		if in.PresentedDPoPJKT != in.Record.DPoPJKT {
			return "", ErrCnfBindingMismatch
		}
		return "dpop", nil
	case in.Record.MTLSCertS256 != "":
		if in.PresentedMTLSCertS256 == "" {
			return "", ErrCnfBindingMissing
		}
		if in.PresentedMTLSCertS256 != in.Record.MTLSCertS256 {
			return "", ErrCnfBindingMismatch
		}
		return "mtls", nil
	default:
		// Bearer flow — record was unbound. The /bc-authorize
		// handler MUST have already rejected this combination
		// under FAPI 2.0 baseline / FAPI-CIBA.
		return "bearer", nil
	}
}

// requireScopeSubset reports [ErrScopeForbidden] when granted is
// not a subset of allowed. An empty granted set is a subset of any
// allowed set; an empty allowed set rejects every non-empty grant.
func requireScopeSubset(granted, allowed []string) error {
	if len(granted) == 0 {
		return nil
	}
	idx := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		idx[s] = struct{}{}
	}
	for _, s := range granted {
		if _, ok := idx[s]; !ok {
			return ErrScopeForbidden
		}
	}
	return nil
}
