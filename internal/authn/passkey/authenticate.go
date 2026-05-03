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

	// ErrAAGUIDDisallowed is returned when the matched credential's
	// AAGUID is not in the verifier's allowlist (M-AUTHN-2). The check
	// runs at assertion time when [Verifier.AAGUIDReCheckOnAssertion]
	// is true so an embedder that narrows the allowlist after
	// registration can revoke previously-issued credentials whose
	// authenticator model has fallen out of policy.
	ErrAAGUIDDisallowed = errors.New("passkey: AAGUID not in allowlist")
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

	// AAGUID re-check at the start of the assertion ceremony
	// (M-AUTHN-2). Filter the credential list so the upstream
	// library's allowCredentials projection cannot surface a
	// credential whose authenticator model has fallen out of policy.
	// An empty allowlist short-circuits the filter (every AAGUID is
	// accepted); the toggle defaults off so embedders that have not
	// opted in see no behaviour change.
	if v.aaguidReCheckOnAssertion && len(v.aaguidAllowlist) > 0 {
		filtered := make([]Credential, 0, len(credentials))
		for _, c := range credentials {
			if v.AAGUIDAllowed(c.Authenticator.AAGUID) {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return nil, nil, fmt.Errorf("%w: every registered credential is in a now-disallowed AAGUID", ErrAAGUIDDisallowed)
		}
		credentials = filtered
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
//
//nolint:gocognit // FinishLogin enumerates assertion / clone / AAGUID branches in flat shape; refactor would obscure WebAuthn spec mapping.
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

	// AAGUID re-check at assertion time (M-AUTHN-2). When enabled,
	// reject the assertion if the matched credential's AAGUID is no
	// longer in the configured allowlist. The check uses the AAGUID
	// persisted at registration (carried on the stored Credential),
	// not a value extracted from the assertion: assertions do not
	// reliably carry AAGUID, and even if they did the registration-
	// time value is the trust anchor — an attacker who somehow
	// flipped the assertion's AAGUID still cannot satisfy the
	// allowlist gate.
	if rerr := v.checkAAGUIDOnAssertion(credentials, parsed.RawID); rerr != nil {
		return nil, rerr
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
		// return a credential pointer so the orchestrator can stamp
		// the audit trail. We deliberately DO NOT propagate the new
		// (and possibly attacker-controlled) sign counter here:
		// trusting the assertion's counter would let an attacker
		// raise the persisted SignCount to UINT32_MAX and lock out
		// the legitimate authenticator forever. Recover the prior
		// counter from the caller-supplied credential record so the
		// CloneWarning bit is the only persisted change.
		var stored Credential
		for _, c := range credentials {
			if bytes.Equal(c.ID, parsed.RawID) {
				stored = c
				break
			}
		}
		out.Authenticator.SignCount = stored.Authenticator.SignCount
		out.Authenticator.CloneWarning = true
		return &out, ErrCloneDetected
	}
	return &out, nil
}

// checkAAGUIDOnAssertion enforces the M-AUTHN-2 re-check gate against
// the stored credential whose ID matches rawID. Returns
// [ErrAAGUIDDisallowed] when the verifier's
// [Config.AAGUIDReCheckOnAssertion] is true, the configured allowlist
// is non-empty, and the matched credential's AAGUID is not in it. An
// empty allowlist short-circuits to nil (every AAGUID is accepted),
// mirroring the registration-time behaviour. A nil verifier or empty
// credential list short-circuits to nil so the helper is safe to call
// before the credential-not-registered check has run.
func (v *Verifier) checkAAGUIDOnAssertion(credentials []Credential, rawID []byte) error {
	if v == nil || !v.aaguidReCheckOnAssertion {
		return nil
	}
	if len(v.aaguidAllowlist) == 0 {
		return nil
	}
	for _, c := range credentials {
		if !bytes.Equal(c.ID, rawID) {
			continue
		}
		if !v.AAGUIDAllowed(c.Authenticator.AAGUID) {
			return fmt.Errorf("%w: AAGUID %x not in allowlist", ErrAAGUIDDisallowed, c.Authenticator.AAGUID)
		}
		return nil
	}
	// No matched credential. The caller's earlier match check
	// already rejects this case with [ErrCredentialNotRegistered],
	// so reaching here means a programming bug; surface a generic
	// disallowed-AAGUID rather than panic.
	return ErrAAGUIDDisallowed
}
