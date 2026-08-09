package store

import (
	"context"
	"time"
)

// PasskeyRecord is the persistent representation of a single registered
// passkey (W3C WebAuthn Level 3 §4 "Credential Record"). The library
// reads it on every assertion, mutates the sign-counter / flag fields
// on success, and writes the new state through
// [PasskeyStore.UpdateAssertion].
//
// The struct is a flat carrier so backends do not have to model nested
// objects: every field maps to a single column / document attribute.
// Re-assembling the nested [internal/authn/passkey.CredentialFlags] /
// [internal/authn/passkey.AuthenticatorData] views is the caller's job
// and lives in internal/authn/passkey.
//
// Backends MUST treat the byte fields (CredentialID, PublicKey,
// AAGUID) as opaque. In particular, PublicKey is the COSE_Key encoding
// emitted by the authenticator; the backend MUST NOT inspect, parse,
// or re-encode it.
type PasskeyRecord struct {
	// CredentialID is the authenticator-supplied credential
	// identifier (W3C WebAuthn L3 §4 "id"). It is the primary key
	// of the record and the value the SPA echoes back inside the
	// assertion. Unique within the OP across all subjects.
	CredentialID []byte

	// Subject is the OP-internal stable user identifier (the same
	// value that becomes the "sub" claim of issued tokens) the
	// credential is registered to. It is the secondary lookup key
	// for [PasskeyStore.ListBySubject] and is enforced as a foreign
	// reference to the embedder's user table by convention; the
	// library does not perform that check itself.
	Subject string

	// PublicKey is the COSE_Key encoding of the credential public
	// key as returned by the authenticator. The library uses it to
	// verify assertion signatures; backends MUST treat it as opaque.
	PublicKey []byte

	// AAGUID is the 16-byte authenticator-model identifier
	// (W3C WebAuthn L3 §6.5.4). It is fixed at the device level and
	// identifies the authenticator vendor / model. It is persisted so
	// an allowlist narrowed after registration can be re-applied to
	// existing credentials at assertion time without re-prompting the
	// user; see op.PrimaryPasskey's AAGUIDAllowlist and
	// AAGUIDReCheckOnAssertion.
	AAGUID []byte

	// SignCount is the authenticator-supplied signature counter
	// observed at the most recent ceremony. The library compares
	// every assertion's counter against this value (W3C WebAuthn L3
	// §7.2 step 17) and stamps [CloneWarning] when the new value is
	// not strictly greater. Backends MUST preserve the field
	// monotonically through [PasskeyStore.UpdateAssertion].
	SignCount uint32

	// AttestationType is the attestation format string returned at
	// registration time ("none", "packed", "fido-u2f", ...). v1.0
	// forces the conveyance preference to "none" so the value is
	// almost always "none"; the field is persisted verbatim so a
	// future v1.x that enables direct attestation can read records
	// written today.
	AttestationType string

	// Transports is the list of transport hints the authenticator
	// advertised at registration time, encoded as the strings
	// defined in [protocol.AuthenticatorTransport] ("usb", "nfc",
	// "ble", "smart-card", "hybrid", "internal"). The library
	// echoes them in the assertion AllowedCredentials list so user
	// agents can prefer the registering authenticator.
	Transports []string

	// UserPresent (UP) reports whether the user proved physical
	// presence during the most recent ceremony. The flag is updated
	// on every assertion; backends MUST persist the new value.
	UserPresent bool

	// UserVerified (UV) reports whether the most recent ceremony
	// verified the user via biometric or PIN. Updated per assertion.
	UserVerified bool

	// BackupEligible (BE) reports whether the credential MAY be
	// backed up by the authenticator. The value is fixed at
	// credential creation; the library detects a flip across
	// assertions and rejects the affected ceremony.
	BackupEligible bool

	// BackupState (BS) reports whether the credential has actually
	// been backed up. Unlike BackupEligible this flag may legitimately
	// change over time; updated per assertion.
	BackupState bool

	// CloneWarning is set when a previous assertion observed a
	// non-increasing sign counter — a strong signal that the
	// authenticator has been cloned (W3C WebAuthn L3 §7.2 step 17).
	// The library does not fail the assertion automatically; the
	// orchestrator decides the policy. Persisted so account-management
	// UIs can highlight the affected credential.
	CloneWarning bool

	// Attachment is the [protocol.AuthenticatorAttachment] hint
	// ("platform", "cross-platform", or empty) returned by the user
	// agent at registration time. Informational; surfaced in
	// account-management UIs.
	Attachment string

	// CreatedAt is the wall-clock time the credential was first
	// registered. Backends SHOULD surface it in account-management
	// UIs so users can identify which authenticator is which.
	CreatedAt time.Time
}

// PasskeyAssertionUpdate contains the mutable credential state produced
// by one verified WebAuthn assertion. ExpectedSignCount is the value
// against which the assertion was verified; SignCount is the value
// returned by the authenticator.
//
// A [PasskeyStore] applies this update atomically so concurrent
// assertions cannot rewind security state. Only the fields in this
// struct may change during assertion persistence. Registration-time
// fields such as Subject, PublicKey, AAGUID, BackupEligible, and
// CreatedAt remain untouched.
type PasskeyAssertionUpdate struct {
	ExpectedSignCount uint32
	SignCount         uint32
	UserPresent       bool
	UserVerified      bool
	BackupState       bool
	CloneWarning      bool
}

// PasskeyStore is the substore for registered passkeys. It is a
// transactional substore in spirit. Assertion updates are atomic within
// one credential row but do not need to be atomic with token issuance.
//
// Backends MUST NOT log or audit PublicKey: it is a credential
// identifier in the same threat-model class as a session token, and a
// leak in the log pipeline would let an attacker enumerate registered
// authenticators.
type PasskeyStore interface {
	// Get returns the record identified by credentialID. It MUST
	// return [ErrNotFound] when no record exists; any other non-nil
	// error indicates a backend fault. The library calls Get during
	// assertion to look up the public key for signature verification.
	Get(ctx context.Context, credentialID []byte) (*PasskeyRecord, error)

	// ListBySubject returns every record registered to subject. The
	// result is empty (non-nil, length-zero slice) when the subject
	// has no passkeys; backends MUST NOT return [ErrNotFound] in
	// that case so callers can branch on length without unwrapping
	// errors. The library calls ListBySubject during registration
	// (to populate excludeCredentials) and during assertion (to
	// populate allowCredentials).
	ListBySubject(ctx context.Context, subject string) ([]*PasskeyRecord, error)

	// Put creates or replaces the record identified by
	// r.CredentialID. Backends implement upsert semantics. The
	// library uses Put for registration and account-management
	// writes, never for post-assertion security-state updates.
	//
	// A credential ID belongs to one subject for its lifetime. When a
	// record already exists under r.CredentialID and its Subject
	// differs from r.Subject, the backend MUST leave the stored
	// record untouched and return [ErrAlreadyExists]; overwriting it
	// would move the credential onto the writing subject and unlink
	// the authenticator of whoever held it. The comparison and the
	// write MUST be one atomic backend operation, so a registration
	// racing the check cannot land between them. Re-writing a record
	// under its own subject is the ordinary update path and MUST
	// succeed.
	Put(ctx context.Context, r *PasskeyRecord) error

	// UpdateAssertion atomically applies a verified assertion's
	// mutable fields and returns the resulting record.
	//
	// Backends MUST preserve these monotonicity rules even when two
	// assertions verified against the same ExpectedSignCount arrive
	// in reverse order:
	//   - SignCount never decreases. An update whose SignCount is
	//     greater than the stored value replaces SignCount and the
	//     UserPresent, UserVerified, and BackupState flags. An older
	//     or equal non-zero update leaves those fields unchanged.
	//   - CloneWarning is sticky: the stored value is ORed with the
	//     update value regardless of counter freshness.
	//   - Counterless authenticators are the exception to the equal
	//     rule: when stored, expected, and updated counters are all
	//     zero, the assertion flags are updated.
	//
	// The read, comparison, and write MUST be one atomic backend
	// operation. It MUST return [ErrNotFound] when credentialID does
	// not exist. The returned record MUST be safe for the caller to
	// mutate without changing stored state.
	UpdateAssertion(ctx context.Context, credentialID []byte, update PasskeyAssertionUpdate) (*PasskeyRecord, error)

	// Delete removes the record identified by credentialID. It MUST
	// return [ErrNotFound] if no such record exists so callers can
	// distinguish a no-op delete from a successful one. The library
	// invokes Delete when the user unlinks a passkey from the
	// account-management UI.
	Delete(ctx context.Context, credentialID []byte) error
}
