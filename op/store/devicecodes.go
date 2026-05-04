package store

import (
	"context"
	"time"
)

// DeviceCodeStatus is the lifecycle state of a [DeviceCode] record. The
// state machine is closed: a record is created in [DeviceCodeStatusPending],
// transitions to [DeviceCodeStatusApproved] or [DeviceCodeStatusDenied]
// when the user completes the verification ceremony, and to
// [DeviceCodeStatusConsumed] the moment the token endpoint atomically
// claims the approved record for token issuance. Backends MUST refuse
// writes that violate the transitions; the library treats a failed
// transition as proof of replay.
type DeviceCodeStatus uint8

const (
	// deviceCodeStatusUnspecified is the zero value used to detect an
	// uninitialised [DeviceCodeStatus]. It is not exported so backends
	// cannot accidentally persist a record with an undefined status.
	deviceCodeStatusUnspecified DeviceCodeStatus = iota

	// DeviceCodeStatusPending is the initial state every record enters
	// at /device_authorization. The token endpoint maps a poll against
	// a Pending record to authorization_pending.
	DeviceCodeStatusPending

	// DeviceCodeStatusApproved means the user completed the
	// verification ceremony and authorised the device. The next token-
	// endpoint poll succeeds and the substore atomically transitions
	// the record to [DeviceCodeStatusConsumed].
	DeviceCodeStatusApproved

	// DeviceCodeStatusDenied means either the user explicitly denied
	// the request, or a brute-force lockout terminated the record (see
	// [DeviceCode.UserCodeStrikes]). The token endpoint maps a poll
	// against a Denied record to access_denied.
	DeviceCodeStatusDenied

	// DeviceCodeStatusConsumed means the device_code was atomically
	// claimed by the token endpoint for issuance. Subsequent polls
	// receive expired_token to prevent token-replay across the
	// approve-poll race window.
	DeviceCodeStatusConsumed
)

// String returns the wire-friendly name of the status, for audit and log
// output. Unknown values surface as "unspecified" so callers cannot
// accidentally print a numeric byte that would later be confused with
// a documented state.
func (s DeviceCodeStatus) String() string {
	switch s {
	case DeviceCodeStatusPending:
		return "pending"
	case DeviceCodeStatusApproved:
		return "approved"
	case DeviceCodeStatusDenied:
		return "denied"
	case DeviceCodeStatusConsumed:
		return "consumed"
	case deviceCodeStatusUnspecified:
		return "unspecified"
	default:
		return "unspecified"
	}
}

// DeviceCode is the persistent record of an RFC 8628 device-authorization
// request. The record is created at /device_authorization, looked up by
// user_code on the verification page, mutated by the
// approve / deny / strike ceremony, polled by FindByDeviceCode, and
// atomically consumed at the token endpoint.
//
// # Hash-on-store contract
//
// [DeviceCode.ID] is the opaque wire device_code (256 bits of crypto/rand,
// base64url-no-pad). It is a bearer secret on the polling channel:
// possession alone authorises the holder to redeem tokens for the device.
// Backends therefore MUST hash [DeviceCode.ID] (SHA-256, ideally HMAC'd
// with a server-side pepper) before persisting it and MUST NOT store the
// raw value, mirroring the discipline established for authorization_code
// and pushed-authorization-request URIs. [DeviceCode.UserCode] is a
// human-read-aloud value gated by the brute-force lockout in the
// device-code package (5 strikes per record), so it is stored as-is —
// hashing would defeat FindByUserCode without adding meaningful defence.
//
// # Lifetime
//
// A record's lifetime is bounded by [DeviceCode.ExpiresAt]. Backends MAY
// garbage-collect rows whose ExpiresAt is in the past; the library
// accepts a missing row as "expired_token" without further inquiry.
type DeviceCode struct {
	// ID is the opaque device_code string returned to the requesting
	// device at /device_authorization. The token endpoint presents it
	// as the device_code parameter at /token.
	ID string

	// UserCode is the human-readable verification code shown on the
	// device's screen. Backends store the canonical normalised form
	// (uppercase, separators stripped) so FindByUserCode can compare
	// without re-normalising.
	UserCode string

	// ClientID identifies the client that initiated the device-
	// authorization request. The token endpoint rejects polls where
	// the authenticated client does not match.
	ClientID string

	// Scope lists the scopes the client requested. The verification
	// page renders the list when prompting for consent; the token
	// endpoint copies the value into the issued credentials.
	Scope []string

	// Resource carries the RFC 8707 §2 normalised audience values the
	// client requested (lowercase scheme + host, trailing-slash
	// stripped). The token endpoint uses them to populate the issued
	// access token's aud claim.
	Resource []string

	// DPoPJKT is the SHA-256 thumbprint of the DPoP proof the device
	// presented at /device_authorization. Empty when the request did
	// not carry a DPoP proof. The token endpoint refuses to mint an
	// access token whose cnf.jkt would not match this value.
	DPoPJKT string

	// MTLSCertS256 is the SHA-256 thumbprint of the mTLS client
	// certificate the device authenticated with at
	// /device_authorization. Empty when the request did not carry
	// mTLS. The token endpoint stamps cnf.x5t#S256 on the issued
	// access token from this value.
	MTLSCertS256 string

	// Interval is the minimum poll interval the device MUST observe.
	// The token endpoint compares LastPolledAt against this value to
	// detect slow_down conditions.
	Interval time.Duration

	// IssuedAt is the wall-clock time the record was created. Supplied
	// by the caller; backends never read the wall clock directly.
	IssuedAt time.Time

	// ExpiresAt is the wall-clock time the record becomes invalid.
	// Backends MAY garbage-collect rows whose ExpiresAt is in the
	// past.
	ExpiresAt time.Time

	// LastPolledAt is the wall-clock time the token endpoint last
	// observed a poll for this record, or nil when the device has not
	// polled yet. The slow_down detector reads this value.
	LastPolledAt *time.Time

	// Status is the current lifecycle state. Backends enforce the
	// transitions documented on [DeviceCodeStatus].
	Status DeviceCodeStatus

	// Subject is the OP-internal stable identifier of the user who
	// approved the request, populated by Approve. Empty when Status
	// is Pending or Denied.
	Subject string

	// AuthTime is the wall-clock time at which the end user
	// completed the verification ceremony. Populated by Approve at
	// the time the record transitions to Approved; zero while the
	// record is Pending or Denied. The token endpoint reads this
	// value when the issued id_token requires the auth_time claim
	// (per OIDC Core 1.0 §2 / store.Client.RequireAuthTime).
	AuthTime time.Time

	// DenyReason names the cause of denial when Status is
	// DeviceCodeStatusDenied. The library populates this with
	// "user_denied", "user_code_lockout", or an embedder-supplied
	// reason; values are opaque to the substore.
	DenyReason string

	// UserCodeStrikes is the count of failed user_code submissions
	// against this record. The verification page increments this
	// counter on every mismatch and triggers the lockout transition
	// at the package-defined cap.
	UserCodeStrikes uint8
}

// DeviceCodeStore is the substore for RFC 8628 device-authorization
// records. It is intentionally outside the transactional cluster: the
// approve→consume CAS embedded in [DeviceCodeStore.Consume] provides the
// single-use guarantee on its own, and pairing the consume with the
// access-token / refresh-token writes inside one transaction would force
// every embedder to either hand the device-code substore the same backend
// as the rest of the transactional cluster or reimplement the CAS in
// their composite layer. The remaining failure mode — Consume succeeds
// and a follow-on token write fails — is observable on the wire as a
// missing token response, after which the device retries the entire
// flow per RFC 8628 §3.5.
//
// Backends that have not yet provisioned the substore MAY fail to
// satisfy [Store.DeviceCodes]; the library detects nil at op.New and
// rejects op.WithDeviceCodeGrant when the substore is missing.
type DeviceCodeStore interface {
	// Save persists a freshly created device-authorization record.
	// Backends MUST hash [DeviceCode.ID] before persisting it (see
	// the type godoc) and MUST return [ErrAlreadyExists] when a
	// hashed-ID collision is detected; the library treats that as a
	// fatal randomness fault. Implementations MAY reject Save when
	// [DeviceCode.UserCode] collides with an existing pending or
	// approved record by returning [ErrAlreadyExists]; the library
	// retries with a fresh user_code in that case.
	Save(ctx context.Context, code *DeviceCode) error

	// FindByDeviceCode returns the record identified by deviceCode.
	// Backends MUST hash the presented value before lookup. The
	// returned record's ID field MUST be set to the original
	// deviceCode the caller supplied (not the digest) so callers can
	// log without re-hashing. Returns [ErrNotFound] when no such
	// record exists; expired records are reported as not found.
	FindByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// FindByUserCode returns the record identified by userCode. The
	// caller is expected to canonicalise the value (uppercase,
	// separators stripped) before invoking this method; backends
	// compare the normalised value byte-for-byte. Returns
	// [ErrNotFound] when no such record exists; expired records are
	// reported as not found.
	FindByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)

	// Approve atomically transitions a Pending record to Approved
	// and stamps the supplied subject and authTime. authTime
	// captures the wall-clock at which the end user completed the
	// verification ceremony; the library reads it back at the
	// token endpoint when the issued id_token requires the
	// auth_time claim. A zero authTime is permitted (clients
	// without RequireAuthTime do not depend on it).
	// Returns [ErrNotFound] when the record does not exist or is
	// already expired, and [ErrConflict] when the record's current
	// status is not Pending (a duplicate approval, a post-deny
	// approval, or a post-consume approval all collapse to
	// ErrConflict so the verification page can surface a single
	// "already decided" message).
	Approve(ctx context.Context, deviceCode, subject string, authTime time.Time) error

	// Deny atomically transitions a Pending record to Denied and
	// stores the supplied reason. The library uses Deny both for
	// explicit user-denied transitions ("user_denied") and for
	// brute-force lockout transitions ("user_code_lockout"); the
	// reason is opaque to the substore. Returns [ErrNotFound] /
	// [ErrConflict] with the same semantics as Approve.
	Deny(ctx context.Context, deviceCode, reason string) error

	// RecordPoll atomically updates [DeviceCode.LastPolledAt] to
	// when AND [DeviceCode.Interval] to nextInterval. The library
	// calls RecordPoll on every poll arrival before deciding the
	// wire response so the next poll's slow_down ladder observes
	// the latest timestamp; on a slow_down decision the library
	// passes the doubled interval per RFC 8628 §3.5 ("If the
	// interval is more than 5 seconds, the client MUST honor the
	// new value") so a misbehaving device cannot keep hammering
	// at the original bar by ignoring the elevated interval.
	// Implementations MUST persist both fields atomically — a
	// concurrent poll observing only the timestamp update would
	// see a stale interval and let the attacker re-arm the gate.
	// A nextInterval value less than or equal to the record's
	// current Interval is taken as "no escalation this poll" and
	// the existing Interval is preserved (the library passes the
	// existing value verbatim on non-slow_down decisions).
	// Returns [ErrNotFound] when the record does not exist; the
	// library treats that as expired_token.
	RecordPoll(ctx context.Context, deviceCode string, when time.Time, nextInterval time.Duration) error

	// IncrementUserCodeStrike increments [DeviceCode.UserCodeStrikes]
	// by one and returns the new value. The verification page calls
	// IncrementUserCodeStrike after a user_code mismatch so the
	// caller can decide whether to trigger Deny with reason
	// "user_code_lockout". Returns [ErrNotFound] when the record
	// does not exist.
	IncrementUserCodeStrike(ctx context.Context, deviceCode string) (uint8, error)

	// Consume atomically transitions an Approved record to
	// Consumed and returns the record. The library calls Consume
	// at the token endpoint before assembling the issued
	// credentials so a duplicate poll cannot mint two token sets
	// for the same approval. Returns [ErrNotFound] for a missing
	// record, [ErrAlreadyConsumed] for a record already in the
	// Consumed state, and [ErrConflict] for any other status
	// (Pending, Denied) so the token endpoint can map the cause
	// onto the matching wire error.
	Consume(ctx context.Context, deviceCode string) (*DeviceCode, error)
}
