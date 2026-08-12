package passkeykit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Sentinel errors re-exported from the ceremony the login path shares,
// so embedders can dispatch on them through [errors.Is] without
// importing an internal package. Each keeps the underlying detail
// wrapped, so %v on the returned error still explains what the
// authenticator got wrong.
var (
	// ErrChallengeExpired is returned by [Registrar.Finish] /
	// [Registrar.Register] when the session outlived its TTL. The
	// ceremony cannot be retried from that session — issue a fresh
	// challenge through [Registrar.Begin].
	ErrChallengeExpired = passkey.ErrChallengeExpired

	// ErrAttestationInvalid is returned when the response fails a
	// WebAuthn Level 3 §7.1 check: challenge mismatch, RPID mismatch,
	// signature verification failure, an unsupported algorithm, or an
	// AAGUID outside the configured allowlist.
	ErrAttestationInvalid = passkey.ErrAttestationInvalid

	// ErrCredentialAlreadyExists is returned when the authenticator
	// produced a credential ID that is already registered — to this
	// subject or to another one. For this subject it is the
	// server-side half of the excludeCredentials list
	// [Registrar.Begin] sends: a compliant authenticator declines
	// before it gets this far, and this is what catches the case where
	// it did not. For another subject it is the refusal WebAuthn Level
	// 3 §7.1 step 27 calls for, without which the enrolment would
	// unlink that subject's authenticator.
	//
	// The two cases share one error deliberately. A handler that
	// rendered them apart would tell whoever posted the response
	// whether a credential ID belongs to somebody else.
	ErrCredentialAlreadyExists = passkey.ErrCredentialAlreadyExists

	// ErrInvalidResponse is returned when the posted bytes cannot be
	// parsed as a WebAuthn registration response — a truncated body, a
	// non-JSON payload, or a JSON object missing the credential fields.
	ErrInvalidResponse = passkey.ErrInvalidResponse
)

// Configuration and call-shape sentinels raised by this package.
var (
	// ErrStoreRequired is returned by [New] when the supplied step
	// carries a nil Store. Enrolment reads the subject's existing
	// credentials to build the exclude list, so there is no usable
	// storeless mode.
	ErrStoreRequired = errors.New("passkeykit: PrimaryPasskey.Store is required")

	// ErrSubjectRequired is returned when [User.Subject] is empty. The
	// subject is the WebAuthn user handle and the owner of the stored
	// record; an empty one would register a credential to nobody.
	ErrSubjectRequired = errors.New("passkeykit: user subject is required")

	// ErrSessionRequired is returned by [Registrar.Finish] /
	// [Registrar.Register] when the session argument is nil.
	ErrSessionRequired = errors.New("passkeykit: session is required")

	// ErrSubjectMismatch is returned when the session's user handle
	// disagrees with the [User.Subject] handed to the finish call. It
	// means the two halves of one ceremony came from different places:
	// either a caller bug, or a ferried session an attacker chose. The
	// registration is refused rather than binding the new credential to
	// whichever subject was named last.
	ErrSubjectMismatch = errors.New("passkeykit: session was issued for a different subject")
)

// User identifies the account a passkey is being registered to. The
// three fields play different roles and only the first is
// security-relevant.
type User struct {
	// Subject is the OP-internal stable user identifier — the same
	// value that becomes the "sub" claim of issued tokens, and the
	// owner recorded on [store.PasskeyRecord.Subject]. It is also the
	// WebAuthn user handle, so it is visible to the authenticator and
	// MUST be an opaque identifier the embedder assigns, never a
	// user-typed address. Required.
	Subject string

	// Name is the account label the user agent shows while choosing
	// where to store the credential, typically the e-mail address or
	// preferred username. It has no security effect and is not
	// persisted by the library.
	Name string

	// DisplayName is the human-readable name shown alongside Name
	// ("Alice Example"). Also cosmetic; user agents fall back to Name
	// when it is empty.
	DisplayName string
}

// CreationOptions is the JSON payload the SPA passes to
// navigator.credentials.create(). Serialise it as-is: the field name
// matches the "publicKey" member the call expects, so a handler can
// write the whole value to the response body and the browser-side code
// is one line.
type CreationOptions struct {
	// PublicKey is the W3C PublicKeyCredentialCreationOptions object
	// as JSON. It carries the challenge, the Relying Party identity,
	// the user handle, and the exclude list.
	PublicKey json.RawMessage `json:"publicKey"`
}

// Session is the per-ceremony state [Registrar.Begin] emits and the
// finish call consumes. It is deliberately opaque: the only supported
// operations are JSON round-tripping it to wherever the embedder keeps
// it and reading [Session.ExpiresAt] to size the cookie that holds it.
//
// See the package documentation for what a Session may and may not be
// exposed to.
type Session struct {
	inner passkey.Session
}

// MarshalJSON renders the session for storage. The encoding is the
// library's own and callers MUST treat it as opaque; it is not part of
// any wire protocol and its shape may grow between minor versions.
func (s Session) MarshalJSON() ([]byte, error) {
	return s.inner.MarshalJSON()
}

// UnmarshalJSON rehydrates a session previously produced by
// [Session.MarshalJSON].
func (s *Session) UnmarshalJSON(data []byte) error {
	return s.inner.UnmarshalJSON(data)
}

// ExpiresAt reports the instant after which the finish call rejects
// this session with [ErrChallengeExpired]. Embedders size the cookie or
// server-side row that carries the session from this value so the two
// lifetimes cannot disagree.
func (s Session) ExpiresAt() time.Time { return s.inner.Expires }

// Registrar issues registration ceremonies for the passkeys that one
// [op.PrimaryPasskey] step authenticates. Construct it with [New] and
// share it for the process lifetime.
type Registrar struct {
	verifier *passkey.Verifier
	store    store.PasskeyStore
}

// New builds a [Registrar] for the login step passed in. The step is
// the same value the embedder installs on its [op.LoginFlow]; see the
// package documentation for why enrolment and login are configured from
// one value rather than two.
//
// Validation matches the login step's own: RPID, RPDisplayName, and at
// least one RPOrigin are required, every origin must be a registrable
// suffix of the RPID over https (http being allowed for loopback), and
// a non-empty AAGUIDAllowlist must name canonical UUIDs. A step this
// function accepts is one op.New will accept, so a misconfiguration
// surfaces once, at startup, from whichever call the embedder makes
// first.
func New(step op.PrimaryPasskey) (*Registrar, error) {
	if isNilStore(step.Store) {
		return nil, ErrStoreRequired
	}
	v, err := passkey.New(passkey.Config{
		RPID:                     step.RPID,
		RPDisplayName:            step.RPDisplayName,
		RPOrigins:                step.RPOrigins,
		SessionTTL:               step.SessionTTL,
		AttestationPreference:    attestationPreferenceFor(step),
		AAGUIDAllowlist:          step.AAGUIDAllowlist,
		AAGUIDReCheckOnAssertion: step.AAGUIDReCheckOnAssertion,
	})
	if err != nil {
		return nil, fmt.Errorf("passkeykit: %w", err)
	}
	return &Registrar{verifier: v, store: step.Store}, nil
}

// Begin starts a ceremony for user. It returns the options to hand the
// SPA and the session to keep; the two are separate return values so a
// handler that serialises its result cannot send the session to the
// browser along with the challenge.
//
// The subject's already-registered credentials are read from the store
// and forwarded as excludeCredentials, so an authenticator the account
// already holds declines the ceremony at the device level rather than
// producing a duplicate the finish call would have to reject.
func (r *Registrar) Begin(ctx context.Context, user User) (*CreationOptions, *Session, error) {
	if user.Subject == "" {
		return nil, nil, ErrSubjectRequired
	}
	existing, err := r.existingCredentials(ctx, user.Subject)
	if err != nil {
		return nil, nil, err
	}
	challenge, session, err := r.verifier.BeginRegistration(
		ctx, user.Subject, user.Name, user.DisplayName, existing,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("passkeykit: begin: %w", err)
	}
	return &CreationOptions{PublicKey: challenge.PublicKey}, &Session{inner: *session}, nil
}

// Finish verifies the SPA's registration response and returns the
// record to persist, without persisting it. Use it when the write has
// to happen inside a transaction the caller owns; otherwise prefer
// [Registrar.Register], which cannot leave a user believing they
// enrolled a device the store never accepted.
//
// user MUST be the value Begin was called with. response is the JSON
// the SPA produced from the created credential's toJSON().
//
// Errors: [ErrSessionRequired], [ErrSubjectRequired],
// [ErrSubjectMismatch], [ErrChallengeExpired], [ErrInvalidResponse],
// [ErrAttestationInvalid], [ErrCredentialAlreadyExists], or a store
// failure. The returned record is nil on every one of them, and the
// caller MUST NOT persist anything.
func (r *Registrar) Finish(ctx context.Context, session *Session, user User, response []byte) (*store.PasskeyRecord, error) {
	if session == nil {
		return nil, ErrSessionRequired
	}
	if user.Subject == "" {
		return nil, ErrSubjectRequired
	}
	// The session names the user handle the challenge was minted for.
	// Finishing under a different subject would bind the new credential
	// to whoever the finish call happened to name, using a challenge
	// issued to someone else.
	if !bytes.Equal(session.inner.UserID, []byte(user.Subject)) {
		return nil, ErrSubjectMismatch
	}

	// Read the exclude list again rather than trusting the one Begin
	// saw: a credential registered in between is one this ceremony must
	// still refuse to duplicate. The list is this subject's own; the
	// ceremony additionally asks the store whether the credential the
	// authenticator minted belongs to somebody else.
	existing, err := r.existingCredentials(ctx, user.Subject)
	if err != nil {
		return nil, err
	}

	inner := session.inner
	cred, err := r.verifier.FinishRegistration(
		ctx, r.store, &inner, user.Subject, user.Name, user.DisplayName, existing, response,
	)
	if err != nil {
		return nil, fmt.Errorf("passkeykit: finish: %w", err)
	}
	rec := passkey.RecordFromCredential(user.Subject, *cred)
	return &rec, nil
}

// Register verifies the response and persists the resulting credential
// in one call. The record is returned only after the store accepted it,
// so a storage failure surfaces as a failed enrolment rather than as a
// device the user believes is registered.
//
// Errors are [Registrar.Finish]'s, plus whatever
// [store.PasskeyStore.Put] reports. A backend that refuses the write
// because the credential ID is held by another subject — the
// [store.ErrAlreadyExists] half of the Put contract, which closes the
// window between the ceremony's ownership check and the write — is
// reported as [ErrCredentialAlreadyExists] so callers see one error for
// one condition however it was detected.
func (r *Registrar) Register(ctx context.Context, session *Session, user User, response []byte) (*store.PasskeyRecord, error) {
	rec, err := r.Finish(ctx, session, user, response)
	if err != nil {
		return nil, err
	}
	if err := r.store.Put(ctx, rec); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, fmt.Errorf("passkeykit: persist credential: %w", ErrCredentialAlreadyExists)
		}
		return nil, fmt.Errorf("passkeykit: persist credential: %w", err)
	}
	return rec, nil
}

// attestationPreferenceFor derives the conveyance preference from the
// step, exactly as the login side does. Asking for an
// authenticator-model allowlist is asking for attestation: without one
// the AAGUID is self-asserted by whatever produced the response, so any
// software authenticator could claim a certified model's identifier.
// Deriving the preference rather than exposing it as a second knob is
// what keeps the two settings from being configured inconsistently.
func attestationPreferenceFor(step op.PrimaryPasskey) protocol.ConveyancePreference {
	if len(step.AAGUIDAllowlist) > 0 {
		return protocol.PreferDirectAttestation
	}
	return protocol.PreferNoAttestation
}

// isNilStore reports whether the step's store is unusable, catching the
// typed-nil case a plain `== nil` misses: a nil *myStore assigned to the
// interface field is non-nil as an interface and panics on first call.
func isNilStore(s store.PasskeyStore) bool {
	if s == nil {
		return true
	}
	rv := reflect.ValueOf(s)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}

// existingCredentials reads the subject's registered passkeys and
// projects them onto the ceremony's credential shape.
func (r *Registrar) existingCredentials(ctx context.Context, subject string) ([]passkey.Credential, error) {
	records, err := r.store.ListBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("passkeykit: list credentials: %w", err)
	}
	out := make([]passkey.Credential, 0, len(records))
	for _, rec := range records {
		if rec == nil {
			continue
		}
		out = append(out, passkey.CredentialFromRecord(*rec))
	}
	return out, nil
}
