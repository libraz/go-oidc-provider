package devicecode

import (
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/pollgrant"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// grantTypeWire is the RFC 8628 §3.4 grant_type wire string.
var grantTypeWire = grant.DeviceCode.String()

// Sentinel errors. The HTTP layer maps these to OAuth wire codes:
//
//   - ErrGrantNotPermitted        → unauthorized_client.
//   - ErrScopeForbidden           → invalid_scope.
//   - ErrCnfBindingMismatch       → invalid_grant.
//   - ErrCnfBindingMissing        → invalid_grant.
//   - ErrPendingApproval          → authorization_pending (not strictly
//     a wire error here — the token-endpoint layer maps polling
//     state to the matching RFC 8628 §3.5 wire code).
//   - ErrDenied                   → access_denied.
//   - ErrExpiredOrConsumed        → expired_token.
//   - ErrSubjectMissing           → invalid_grant.
var (
	// ErrGrantNotPermitted indicates the client is not registered
	// for the device_code grant. The check guards against a
	// confidential client repurposing a credential beyond the role
	// embedders intended.
	ErrGrantNotPermitted = errors.New("devicecode: client is not permitted to use device_code")

	// ErrScopeForbidden indicates the requested scope contains an
	// entry outside the client's registered Scopes set. RFC 6749
	// §3.3 permits the OP to narrow the requested scope; the
	// library's posture is to reject any out-of-set entry rather
	// than silently dropping it.
	ErrScopeForbidden = errors.New("devicecode: requested scope is not permitted for client")

	// ErrCnfBindingMismatch indicates the device-authorization
	// record committed to a DPoP / mTLS thumbprint that does not
	// match the polling client's presented credential. This
	// typically means a third party stole the device_code and is
	// polling on the device's behalf; the issued token, even if
	// minted, would be bound to the legitimate device's key, not
	// the attacker's.
	ErrCnfBindingMismatch = errors.New("devicecode: cnf binding does not match the device-authorization record")

	// ErrCnfBindingMissing indicates the device committed to a
	// DPoP / mTLS thumbprint at /device_authorization but the
	// polling /token request arrived without one. The token
	// endpoint refuses to mint an unbound token from a bound
	// record.
	ErrCnfBindingMissing = errors.New("devicecode: cnf binding required by record is missing on poll")

	// ErrPendingApproval signals the device_code record is still
	// in the Pending state — the user has not completed the
	// verification ceremony.
	ErrPendingApproval = errors.New("devicecode: authorization is still pending")

	// ErrDenied signals the user explicitly denied the request or
	// the brute-force gate terminated the record.
	ErrDenied = errors.New("devicecode: authorization was denied")

	// ErrExpiredOrConsumed signals the device_code expired before
	// the user approved, or the record was already consumed by an
	// earlier successful poll.
	ErrExpiredOrConsumed = errors.New("devicecode: device_code expired or already consumed")

	// ErrSubjectMissing indicates the record reached the Approved
	// state without an end-user subject. OIDC Core 1.0 §2 makes "sub"
	// REQUIRED, so a verification ceremony that was never tied to a
	// user cannot produce a credential: an id_token with an empty
	// "sub" is an anonymous assertion a relying party may map onto the
	// empty-string key and confuse with another account. The record is
	// refused outright rather than issued with a placeholder, and the
	// refusal is independent of scope, refresh eligibility, and the
	// embedder's subject projection so the same wire code comes back on
	// every configuration.
	ErrSubjectMissing = errors.New("devicecode: approved record has no subject")
)

// AuthorizeInput is the parameter bundle [Authorize] consumes.
type AuthorizeInput struct {
	// Client is the authenticated polling client. The caller has
	// already verified credentials; Authorize only consults policy
	// fields.
	Client *store.Client

	// Record is the resolved device-authorization record. The
	// caller has already looked it up via
	// [store.DeviceCodeStore.FindByDeviceCode]; Authorize never
	// performs I/O.
	Record *store.DeviceCode

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
	// already RFC 8707 §2 normalised.
	Audience []string

	// Subject is the OP-internal stable identifier of the
	// approving end-user, taken verbatim from the record.
	Subject string

	// AuthTime is the wall-clock time at which the end user
	// completed the verification ceremony, taken verbatim from
	// the record. Zero when the substore did not retain the
	// value (e.g. legacy records persisted before the field was
	// introduced); the token endpoint reads it back when the
	// issued id_token requires the auth_time claim.
	AuthTime time.Time

	// SenderConstraint names the binding stamped on the eventual
	// access token: "dpop", "mtls", "dpop+mtls" (record committed to
	// both methods and the poll satisfied both), or "bearer". The
	// caller uses this to decide cnf claim shape and to populate the
	// device_code.token.issued audit extras.
	SenderConstraint string
}

// Authorize applies the device_code-specific authorization gates:
//
//  1. Client must list device_code in its registered grant_types.
//  2. Record state must be Approved (Pending → pending wire code,
//     Denied → denied, Expired/Consumed → expired_token; Authorize
//     surfaces the cause via the matching sentinel).
//  3. The record must name a subject; an approval without one cannot
//     certify anyone (ErrSubjectMissing).
//  4. Every cnf binding the device committed to at
//     /device_authorization must be satisfied by the /token request;
//     methods are evaluated independently and ANDed. Empty matches
//     empty (bearer flow); a record-side binding without a request-
//     side one is a silent downgrade attempt.
//  5. The record's scope is the binding ceiling; Authorize re-checks
//     the subset relationship against the client's registered
//     Scopes so a post-issue client mutation cannot widen the grant.
//
// The function is deliberately silent on TTL bucketing and
// refresh-token issuance: those are token-endpoint concerns the
// caller composes separately.
func Authorize(in AuthorizeInput) (*Authorized, error) {
	if in.Client == nil {
		return nil, errors.New("devicecode: nil client")
	}
	if in.Record == nil {
		return nil, errors.New("devicecode: nil device-code record")
	}
	approval, err := pollgrant.Authorize(in.Client, grantTypeWire, pollgrant.Record{
		Subject:      in.Record.Subject,
		Scope:        in.Record.Scope,
		Resource:     in.Record.Resource,
		AuthTime:     in.Record.AuthTime,
		DPoPJKT:      in.Record.DPoPJKT,
		MTLSCertS256: in.Record.MTLSCertS256,
	}, pollgrant.Presented{
		DPoPJKT:      in.PresentedDPoPJKT,
		MTLSCertS256: in.PresentedMTLSCertS256,
	}, mapStatusToError(in.Record.Status), pollgrant.Errors{
		NotPermitted:   ErrGrantNotPermitted,
		SubjectMissing: ErrSubjectMissing,
		CnfMissing:     ErrCnfBindingMissing,
		CnfMismatch:    ErrCnfBindingMismatch,
		ScopeForbidden: ErrScopeForbidden,
	})
	if err != nil {
		return nil, err
	}
	return &Authorized{
		Scope:            approval.Scope,
		Audience:         approval.Audience,
		Subject:          approval.Subject,
		AuthTime:         approval.AuthTime,
		SenderConstraint: approval.SenderConstraint,
	}, nil
}

// mapStatusToError translates a [store.DeviceCodeStatus] value into
// the matching package sentinel. The handler at the call site
// translates each sentinel into the wire RFC 8628 §3.5 code
// alongside the audit extras.
func mapStatusToError(s store.DeviceCodeStatus) error {
	switch s {
	case store.DeviceCodeStatusApproved:
		return nil
	case store.DeviceCodeStatusPending:
		return ErrPendingApproval
	case store.DeviceCodeStatusDenied:
		return ErrDenied
	case store.DeviceCodeStatusConsumed:
		return ErrExpiredOrConsumed
	default:
		return ErrExpiredOrConsumed
	}
}
