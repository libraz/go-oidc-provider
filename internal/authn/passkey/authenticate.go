package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
)

// AssertionChallenge wraps the JSON-shaped CredentialRequestOptions
// the SPA hands to navigator.credentials.get(). The wrapper exists for
// the same reason as [RegistrationChallenge]: keeping the upstream
// protocol type out of the public surface.
type AssertionChallenge struct {
	// PublicKey is the JSON encoding of the W3C
	// PublicKeyCredentialRequestOptions object the user agent
	// expects under the "publicKey" key.
	PublicKey json.RawMessage `json:"publicKey"`
}

// Sentinel errors specific to assertion. Callers dispatch via
// [errors.Is]. The registration-side errors ([ErrChallengeExpired],
// [ErrInvalidResponse]) also apply to assertion and live in
// register.go.
var (
	// ErrAssertionInvalid is returned when the upstream library
	// rejects the parsed assertion response — challenge mismatch,
	// signature verification failure, BackupEligible flip, allow-list
	// violation, or any other WebAuthn L3 §7.2 check. The original
	// library error is wrapped via fmt.Errorf %w; the sentinel is
	// what callers branch on.
	ErrAssertionInvalid = errors.New("passkey: assertion invalid")

	// ErrCloneDetected is returned when the authenticator's
	// signature counter did not strictly increase compared to the
	// stored value. WebAuthn L3 §7.2 step 17 treats this as a strong
	// signal that the credential has been cloned. The verifier
	// surfaces it as an error rather than just stamping
	// CloneWarning so callers cannot silently ignore the signal; the
	// orchestrator decides whether to fail the ceremony, force a
	// step-up, or merely raise an audit event.
	ErrCloneDetected = errors.New("passkey: clone warning raised")

	// ErrCredentialNotRegistered is returned when the assertion's
	// rawId does not match any credential in the caller-supplied
	// list. The check is performed inside the verifier so callers
	// cannot forget it; passing an empty list is treated as "no
	// credentials registered" which can never satisfy an assertion.
	ErrCredentialNotRegistered = errors.New("passkey: credential not registered")
)

// BeginLogin starts an assertion ceremony for the user identified by
// subject. The returned [AssertionChallenge] is the JSON the SPA hands
// to navigator.credentials.get(); the returned [Session] MUST be
// ferried back to [Verifier.FinishLogin].
//
// The credentials slice is the list of [Credential]s already
// registered to the same subject — typically the result of
// [PasskeyStore.ListBySubject]. The library forwards their IDs to the
// user agent as allowCredentials so the authenticator surfaces only
// the appropriate keys. An empty list returns an error: a user with no
// passkeys cannot be asserted against.
//
// The ctx parameter is accepted for symmetry with the storage API and
// future cancellation but is not consulted today.
func (v *Verifier) BeginLogin(_ context.Context, subject, name string, credentials []Credential) (*AssertionChallenge, *Session, error) {
	if subject == "" {
		return nil, nil, fmt.Errorf("%w: subject is required", ErrInvalidConfig)
	}
	if len(credentials) == 0 {
		return nil, nil, fmt.Errorf("%w: subject has no registered credentials", ErrCredentialNotRegistered)
	}
	// displayName is unused by BeginLogin (the user agent shows the
	// already-registered credential metadata) so we pass the name in
	// both slots.
	user := newWebauthnUser(subject, name, name, credentials)

	assertion, sd, err := v.wa.BeginLogin(user)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: begin login: %w", err)
	}

	sd.Expires = v.clock().Now().Add(v.SessionTTL).UTC()

	raw, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: marshal request options: %w", err)
	}
	session := encodeSession(*sd)
	return &AssertionChallenge{PublicKey: raw}, &session, nil
}

// FinishLogin verifies the assertion response the SPA produced against
// the previously emitted [Session] and the caller's stored credential
// list. On success it returns the matching [Credential] with the sign
// counter, BackupState, UserVerified, and UserPresent fields updated
// from the assertion; the caller MUST persist the new value (typically
// via [PasskeyStore.Put]).
//
// The function returns:
//   - [ErrChallengeExpired] when the session has expired against the
//     verifier's clock;
//   - [ErrInvalidResponse] when the response payload cannot be parsed;
//   - [ErrCredentialNotRegistered] when the rawId is absent from the
//     caller-supplied credentials slice;
//   - [ErrAssertionInvalid] when the parsed response fails any
//     WebAuthn L3 §7.2 check (challenge mismatch, signature failure,
//     BackupEligible flip, ...);
//   - [ErrCloneDetected] when the sign counter did not strictly
//     increase. The returned [*Credential] is non-nil in this case so
//     the caller can stamp the audit trail with the clone-warning
//     metadata, but the orchestrator MUST NOT advance the
//     authenticator chain on the basis of the assertion.
//
// On any error other than [ErrCloneDetected] the returned
// [*Credential] is nil.
func (v *Verifier) FinishLogin(_ context.Context, session *Session, subject, name string, credentials []Credential, response []byte) (*Credential, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: nil session", ErrInvalidResponse)
	}
	if err := v.checkSessionFresh(session); err != nil {
		return nil, err
	}
	if len(credentials) == 0 {
		return nil, ErrCredentialNotRegistered
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	// Verify the rawId is in the caller-supplied list before we hand
	// the parsed response to the upstream library. The library
	// performs its own check but only against session.AllowedCredentialIDs;
	// we want the error type to be the project's sentinel rather
	// than a generic upstream failure.
	matched := false
	for _, c := range credentials {
		if bytes.Equal(c.ID, parsed.RawID) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, ErrCredentialNotRegistered
	}

	user := newWebauthnUser(subject, name, name, credentials)
	sd := decodeSession(*session)
	sd.Expires = sessionZeroTime()

	wc, err := v.wa.ValidateLogin(user, sd, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAssertionInvalid, err)
	}

	out := fromWebauthnCredential(*wc)
	if wc.Authenticator.CloneWarning {
		// Surface the clone signal as a structured error but still
		// return the updated credential so the orchestrator can
		// stamp the audit trail. The orchestrator owns the policy
		// decision (fail vs. warn vs. step-up).
		return &out, ErrCloneDetected
	}
	return &out, nil
}
