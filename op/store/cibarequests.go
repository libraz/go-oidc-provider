package store

import (
	"context"
	"time"
)

// CIBARequestStatus is the lifecycle state of a [CIBARequest] record.
// The state machine is closed: a record is created in
// [CIBARequestStatusPending], transitions to [CIBARequestStatusApproved]
// or [CIBARequestStatusDenied] when the embedder's authentication
// device interaction completes, and to [CIBARequestStatusConsumed] the
// moment the token endpoint atomically claims the approved record for
// token issuance. Backends MUST refuse writes that violate the
// transitions; the library treats a failed transition as proof of
// replay.
type CIBARequestStatus uint8

const (
	// cibaRequestStatusUnspecified is the zero value used to detect an
	// uninitialised [CIBARequestStatus]. It is not exported so backends
	// cannot accidentally persist a record with an undefined status.
	cibaRequestStatusUnspecified CIBARequestStatus = iota

	// CIBARequestStatusPending is the initial state every record enters
	// at /bc-authorize. The token endpoint maps a poll against a
	// Pending record to authorization_pending.
	CIBARequestStatusPending

	// CIBARequestStatusApproved means the embedder's authentication
	// device interaction completed with the user authorising the
	// request. The next token-endpoint poll succeeds and the substore
	// atomically transitions the record to [CIBARequestStatusConsumed].
	CIBARequestStatusApproved

	// CIBARequestStatusDenied means the user explicitly denied the
	// request, or the authentication device timed out. The token
	// endpoint maps a poll against a Denied record to access_denied.
	CIBARequestStatusDenied

	// CIBARequestStatusConsumed means the auth_req_id was atomically
	// claimed by the token endpoint for issuance. Subsequent polls
	// receive expired_token to prevent token-replay across the
	// approve-poll race window.
	CIBARequestStatusConsumed
)

// String returns the wire-friendly name of the status, for audit and
// log output. Unknown values surface as "unspecified" so callers cannot
// accidentally print a numeric byte that would later be confused with
// a documented state.
func (s CIBARequestStatus) String() string {
	switch s {
	case CIBARequestStatusPending:
		return "pending"
	case CIBARequestStatusApproved:
		return "approved"
	case CIBARequestStatusDenied:
		return "denied"
	case CIBARequestStatusConsumed:
		return "consumed"
	case cibaRequestStatusUnspecified:
		return "unspecified"
	default:
		return "unspecified"
	}
}

// CIBARequest is the persistent record of an OpenID Connect CIBA
// (Client-Initiated Backchannel Authentication) Core 1.0 request. The
// record is created at /bc-authorize, mutated by the embedder's
// authentication device interaction (Approve / Deny), polled at the
// token endpoint via FindByAuthReqID, and atomically consumed at token
// issuance.
//
// # Hash-on-store contract
//
// [CIBARequest.ID] is the opaque wire auth_req_id (256 bits of
// crypto/rand, base64url-no-pad). It is a bearer secret on the polling
// channel: possession alone authorises the holder to redeem tokens for
// the originating client. Backends therefore MUST hash [CIBARequest.ID]
// (SHA-256, ideally HMAC'd with a server-side pepper) before persisting
// it and MUST NOT store the raw value, mirroring the discipline
// established for authorization_code, pushed-authorization-request
// URIs, and device_code.
//
// # Lifetime
//
// A record's lifetime is bounded by [CIBARequest.ExpiresAt]. Backends
// MAY garbage-collect rows whose ExpiresAt is in the past; the library
// accepts a missing row as "expired_token" without further inquiry.
//
// # Hints (login_hint / id_token_hint / login_hint_token)
//
// Per OIDC CIBA Core §7.1 the client identifies the end-user with
// exactly one of `login_hint`, `id_token_hint`, or `login_hint_token`.
// The library resolves the hint to a stable [CIBARequest.Subject]
// before persistence so the substore never sees the original PII; the
// hint values themselves are dropped after resolution. Backends store
// only the resolved subject.
type CIBARequest struct {
	// ID is the opaque auth_req_id string returned to the client at
	// /bc-authorize. The token endpoint presents it as the auth_req_id
	// parameter at /token under
	// grant_type=urn:openid:params:grant-type:ciba.
	ID string

	// ClientID identifies the client that initiated the backchannel
	// request. The token endpoint rejects polls where the
	// authenticated client does not match.
	ClientID string

	// Subject is the OP-internal stable identifier of the end-user
	// the request is addressed to, resolved from the inbound
	// login_hint / id_token_hint / login_hint_token before persistence.
	// Empty when the OP has not yet resolved the hint (e.g. an
	// embedder that defers resolution to its authentication device);
	// the verification page populates the value via [CIBARequestStore.Approve].
	Subject string

	// Scope lists the scopes the client requested. The authentication
	// device renders the list when prompting the user; the token
	// endpoint copies the value into the issued credentials.
	Scope []string

	// Resource carries the RFC 8707 §2 normalised audience values the
	// client requested (lowercase scheme + host, trailing-slash
	// stripped). The token endpoint uses them to populate the issued
	// access token's aud claim.
	Resource []string

	// ACRValues carries the requested Authentication Context Class
	// Reference values (OIDC Core §3.1.2.1). The authentication device
	// must satisfy at least one before Approve.
	ACRValues []string

	// ACR is the Authentication Context Class Reference the
	// authentication device actually satisfied when approving the
	// request. Empty means the approval did not assert a concrete ACR;
	// token issuance MUST NOT infer one from ACRValues.
	ACR string

	// BindingMessage is the human-readable string the client supplied
	// for display on the authentication device (CIBA Core §7.1). The
	// library length-caps the value at 50 characters and rejects
	// Unicode control characters, but otherwise stores the value
	// verbatim (no HTML-escaping or other transformation) so the
	// authentication and consumption devices render an identical
	// string, as CIBA's anti-phishing interlock requires. Any
	// rendering-context escaping is the embedder's responsibility.
	BindingMessage string

	// UserCode is the out-of-band confirmation value CIBA Core §7.1
	// defines. The bundled /bc-authorize handler never populates it:
	// the OP advertises backchannel_user_code_parameter_supported as
	// false and refuses a non-empty user_code, so the field exists for
	// an embedder that drives the substore itself against its own
	// user-code registry. Backends store the value as supplied.
	UserCode string

	// DPoPJKT is the SHA-256 thumbprint of the DPoP proof the client
	// presented at /bc-authorize. Empty when the request did not
	// carry a DPoP proof. The token endpoint refuses to mint an
	// access token whose cnf.jkt would not match this value.
	DPoPJKT string

	// MTLSCertS256 is the SHA-256 thumbprint of the mTLS client
	// certificate the client authenticated with at /bc-authorize.
	// Empty when the request did not carry mTLS. The token endpoint
	// stamps cnf.x5t#S256 on the issued access token from this value.
	MTLSCertS256 string

	// Interval is the minimum poll interval the client MUST observe
	// (CIBA Core §11). The token endpoint compares LastPolledAt
	// against this value to detect slow_down conditions.
	Interval time.Duration

	// IssuedAt is the wall-clock time the record was created. Supplied
	// by the caller; backends never read the wall clock directly.
	IssuedAt time.Time

	// ExpiresAt is the wall-clock time the record becomes invalid.
	// Backends MAY garbage-collect rows whose ExpiresAt is in the
	// past.
	ExpiresAt time.Time

	// LastPolledAt is the wall-clock time the token endpoint last
	// observed a poll for this record, or nil when the client has
	// not polled yet. The slow_down detector reads this value.
	LastPolledAt *time.Time

	// AuthTime is the wall-clock time at which the end user
	// completed the authentication-device interaction. Populated
	// by Approve at the time the record transitions to Approved;
	// zero while the record is Pending or Denied. The token
	// endpoint reads this value when the issued id_token requires
	// the auth_time claim (per OIDC Core 1.0 §2 /
	// store.Client.RequireAuthTime).
	AuthTime time.Time

	// PollViolations counts how many polls the client has issued in
	// violation of the slow_down interval (i.e. polls that arrived
	// before LastPolledAt + Interval). The library increments the
	// counter on each violation and triggers a transition to Denied
	// with reason "poll_abuse" when the count crosses the
	// package-defined cap.
	PollViolations uint8

	// Status is the current lifecycle state. Backends enforce the
	// transitions documented on [CIBARequestStatus].
	Status CIBARequestStatus

	// DenyReason names the cause of denial when Status is
	// CIBARequestStatusDenied. The library populates this with
	// "user_denied", "auth_device_timeout", "poll_abuse", or an
	// embedder-supplied reason; values are opaque to the substore.
	DenyReason string
}

// CIBARequestStore is the substore for OpenID Connect CIBA Core 1.0
// backchannel-authentication records. It is intentionally outside the
// atomic-routing cluster: the approve→consume CAS embedded in
// [CIBARequestStore.Consume] provides the single-use guarantee on its
// own, and pairing the consume with the access-token / refresh-token
// writes inside one transaction would force every embedder to either
// hand the substore the same backend as the rest of the transactional
// cluster or reimplement the CAS in their composite layer. The token endpoint
// prepares the fallible token bundle before calling Consume, then discards
// pre-persisted opaque / refresh credentials if another poll wins the CAS.
// This preserves single use without losing an approved ceremony to a signing
// or persistence fault.
//
// Backends that have not yet provisioned the substore MAY fail to
// satisfy [Store.CIBARequests]; the library detects nil at op.New and
// rejects op.WithCIBA when the substore is missing.
type CIBARequestStore interface {
	// Save persists a freshly created CIBA record. Backends MUST hash
	// [CIBARequest.ID] before persisting it (see the type godoc) and
	// MUST return [ErrAlreadyExists] when a hashed-ID collision is
	// detected; the library treats that as a fatal randomness fault.
	Save(ctx context.Context, req *CIBARequest) error

	// FindByAuthReqID returns the record identified by authReqID.
	// Backends MUST hash the presented value before lookup. The
	// returned record's ID field MUST be set to the original
	// authReqID the caller supplied (not the digest) so callers can
	// log without re-hashing. Returns [ErrNotFound] when no such
	// record exists; expired records are reported as not found.
	FindByAuthReqID(ctx context.Context, authReqID string) (*CIBARequest, error)

	// Approve atomically transitions a Pending record to Approved
	// and stamps the supplied subject, satisfied ACR, and authTime. The library
	// invokes Approve from the embedder's authentication device
	// callback. If the record already has a non-empty Subject, subject
	// MUST be identical; a mismatch returns [ErrConflict] and leaves the
	// record untouched. A legacy/deferred record whose Subject is empty may
	// be populated exactly once by the approval. acr is the authentication
	// context class reference the
	// device actually satisfied; it may be empty when the deployment
	// has no comparable ACR vocabulary. authTime captures the wall-clock at which the end
	// user completed the authentication-device interaction; the
	// token endpoint reads it back when the issued id_token
	// requires the auth_time claim. A zero authTime is permitted
	// (clients without RequireAuthTime do not depend on it).
	// Returns [ErrNotFound] when the record does not exist or is
	// already expired, and [ErrConflict] when the record's current
	// status is not Pending.
	Approve(ctx context.Context, authReqID, subject, acr string, authTime time.Time) error

	// Deny atomically transitions a Pending record to Denied and
	// stores the supplied reason. The library uses Deny for explicit
	// user-denied transitions ("user_denied"), for authentication
	// device timeouts ("auth_device_timeout"), for poll-abuse
	// lockouts ("poll_abuse"), and for embedder-supplied reasons; the
	// reason is opaque to the substore. Returns [ErrNotFound] /
	// [ErrConflict] with the same semantics as Approve.
	Deny(ctx context.Context, authReqID, reason string) error

	// RecordPoll updates [CIBARequest.LastPolledAt] to when and
	// [CIBARequest.Interval] to nextInterval when nextInterval is greater
	// than the current value. The library calls RecordPoll after deciding
	// the current poll result but before writing the response, so the next
	// poll observes both the current timestamp and the escalated
	// slow_down interval. A nextInterval value less than or equal to the
	// current interval preserves the existing interval.
	//
	// Implementations MUST persist both fields atomically, but RecordPoll
	// is an observation update, not a compare-and-set gate: its signature
	// does not return the previous LastPolledAt / Interval. Under
	// deliberately concurrent polling, two handlers that already read the
	// same pre-poll snapshot can therefore make the same
	// authorization_pending vs slow_down decision. This is accepted for
	// the CIBA slow_down ladder; token issuance remains protected by
	// Consume's single-use CAS.
	//
	// Returns [ErrNotFound] when the record does not exist; the library
	// treats that as expired_token.
	RecordPoll(ctx context.Context, authReqID string, when time.Time, nextInterval time.Duration) error

	// IncrementPollViolation increments [CIBARequest.PollViolations]
	// by one and returns the new value. The library calls
	// IncrementPollViolation when a poll arrives before
	// LastPolledAt + Interval so the caller can decide whether to
	// trigger Deny with reason "poll_abuse". Returns [ErrNotFound]
	// when the record does not exist.
	IncrementPollViolation(ctx context.Context, authReqID string) (uint8, error)

	// Consume atomically transitions an Approved record to Consumed
	// and returns the record. The library calls Consume at the
	// token endpoint before assembling the issued credentials so a
	// duplicate poll cannot mint two token sets for the same
	// approval. Returns [ErrNotFound] for a missing record,
	// [ErrAlreadyConsumed] for a record already in the Consumed
	// state, and [ErrConflict] for any other status (Pending,
	// Denied) so the token endpoint can map the cause onto the
	// matching wire error.
	Consume(ctx context.Context, authReqID string) (*CIBARequest, error)
}
