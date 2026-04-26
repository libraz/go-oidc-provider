package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
)

// RegistrationChallenge wraps the JSON-shaped CredentialCreationOptions
// that the SPA hands to navigator.credentials.create(). The library
// emits the upstream [protocol.CredentialCreation] verbatim; the
// wrapper exists so the public surface is a single struct rather than
// a forwarded protocol type.
type RegistrationChallenge struct {
	// PublicKey is the JSON encoding of the W3C
	// PublicKeyCredentialCreationOptions object the user agent
	// expects under the "publicKey" key. Callers MAY decode and
	// re-marshal the value if they need to inject custom extensions
	// before delivering it to the SPA, though v1.0 does not surface
	// any extension hooks.
	PublicKey json.RawMessage `json:"publicKey"`
}

// Sentinel errors emitted by the registration ceremony. Callers
// dispatch via [errors.Is] without inspecting message strings.
var (
	// ErrChallengeExpired is returned when the [Session.Expires]
	// stamp is at or before the verifier's clock reading at
	// FinishRegistration / FinishLogin time. The session is unsafe
	// to retry; the caller MUST start a fresh ceremony.
	ErrChallengeExpired = errors.New("passkey: session challenge expired")

	// ErrAttestationInvalid is returned when the upstream library
	// rejects the parsed registration response — challenge
	// mismatch, RPID mismatch, signature verification failure,
	// unsupported algorithm, or any of the other WebAuthn L3 §7.1
	// checks. The original library error is wrapped via fmt.Errorf
	// %w so debug logs can inspect it; the sentinel is what callers
	// branch on.
	ErrAttestationInvalid = errors.New("passkey: attestation invalid")

	// ErrCredentialAlreadyExists is returned when the credential ID
	// emitted by FinishRegistration matches one already in the
	// caller-supplied "existing" list. The duplicate check happens
	// inside the verifier rather than at the storage layer because
	// the library has no concept of "store" at this point in the
	// flow; doing it here lets callers branch on a structured error
	// instead of a backend-specific unique-constraint violation.
	ErrCredentialAlreadyExists = errors.New("passkey: credential already registered")

	// ErrInvalidResponse is returned when the SPA-supplied response
	// payload cannot be parsed as a CredentialCreationResponse /
	// CredentialAssertionResponse. The wrapped error carries the
	// parser detail; the sentinel is what callers branch on.
	ErrInvalidResponse = errors.New("passkey: invalid response payload")
)

// BeginRegistration starts a registration ceremony for the user
// identified by subject. The returned [RegistrationChallenge] is the
// JSON the SPA hands to navigator.credentials.create(); the returned
// [Session] MUST be ferried back to [Verifier.FinishRegistration]
// (typically through an encrypted cookie).
//
// The "existing" slice is the list of [Credential]s already registered
// to the same subject. It is consulted by [Verifier.FinishRegistration]
// to reject duplicate credential IDs ([ErrCredentialAlreadyExists]).
// v1.0 does NOT forward the list to the authenticator as
// excludeCredentials — the user agent therefore relies on its own
// resident-key store (combined with the WebAuthn user handle) to
// de-duplicate at registration time. v1.x will surface an option to
// emit the exclude list once we have a corresponding configuration
// knob for the orchestrator.
//
// The ctx parameter is accepted for symmetry with the storage API and
// future cancellation but is not consulted today.
func (v *Verifier) BeginRegistration(_ context.Context, subject, name, displayName string, existing []Credential) (*RegistrationChallenge, *Session, error) {
	if subject == "" {
		return nil, nil, fmt.Errorf("%w: subject is required", ErrInvalidConfig)
	}
	user := newWebauthnUser(subject, name, displayName, existing)

	creation, sd, err := v.wa.BeginRegistration(user)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: begin registration: %w", err)
	}

	// Override the upstream-stamped Expires with our clock-driven
	// stamp so tests inject a deterministic value and so the cookie
	// payload reflects the verifier's authoritative clock rather
	// than wall-clock time observed inside the library.
	sd.Expires = v.clock().Now().Add(v.SessionTTL).UTC()

	raw, err := json.Marshal(creation.Response)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: marshal creation options: %w", err)
	}
	session := encodeSession(*sd)
	return &RegistrationChallenge{PublicKey: raw}, &session, nil
}

// FinishRegistration verifies the registration response the SPA
// produced via PublicKeyCredential.toJSON() against the previously
// emitted [Session]. On success it returns the freshly minted
// [Credential] the caller MUST persist via the embedder's
// [github.com/libraz/go-oidc-provider/op/store.PasskeyStore].
//
// The function returns:
//   - [ErrChallengeExpired] when the session has expired against the
//     verifier's clock;
//   - [ErrInvalidResponse] when the response payload cannot be parsed;
//   - [ErrAttestationInvalid] when the parsed response fails any
//     WebAuthn L3 §7.1 check;
//   - [ErrCredentialAlreadyExists] when the credential ID is already
//     present in the caller-supplied "existing" slice (intended to be
//     populated from [PasskeyStore.ListBySubject]).
//
// On any error the returned [*Credential] is nil. Backends MUST NOT
// persist anything in that case.
func (v *Verifier) FinishRegistration(_ context.Context, session *Session, subject, name, displayName string, existing []Credential, response []byte) (*Credential, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: nil session", ErrInvalidResponse)
	}
	if err := v.checkSessionFresh(session); err != nil {
		return nil, err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	user := newWebauthnUser(subject, name, displayName, existing)
	sd := decodeSession(*session)
	// Zero Expires so the upstream library's wall-clock check is
	// skipped; we already verified freshness through our injected
	// clock above.
	sd.Expires = sessionZeroTime()

	wc, err := v.wa.CreateCredential(user, sd, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestationInvalid, err)
	}

	// Reject duplicates against the caller-supplied list. The check
	// is intentionally inside the verifier so callers cannot forget
	// it; pass an empty slice to skip.
	for _, c := range existing {
		if bytes.Equal(c.ID, wc.ID) {
			return nil, ErrCredentialAlreadyExists
		}
	}

	out := fromWebauthnCredential(*wc)
	out.CreatedAt = v.clock().Now().UTC()
	return &out, nil
}
