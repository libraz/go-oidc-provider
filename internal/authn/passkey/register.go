package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/libraz/go-oidc-provider/op/store"
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
	// emitted by FinishRegistration is already registered — either in
	// the caller-supplied "existing" list (the subject's own
	// credentials) or, per the store lookup FinishRegistration
	// performs, to a different subject. Doing the check in the
	// verifier lets callers branch on a structured error instead of a
	// backend-specific unique-constraint violation.
	//
	// One sentinel covers both cases on purpose: an attacker probing
	// credential IDs must not be able to tell "already yours" from
	// "already someone else's".
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
// to reject duplicate credential IDs ([ErrCredentialAlreadyExists])
// AND forwarded to the user agent as excludeCredentials so a CTAP2
// authenticator already bound to the user refuses to register a
// duplicate at the device level. The defence is layered: the SPA-side
// exclude list short-circuits the round trip on a known-duplicate
// authenticator, while the post-FinishRegistration check below
// catches the residual case where a malicious or buggy SPA omitted
// the exclude entry.
//
// The ctx parameter is accepted for symmetry with the storage API and
// future cancellation but is not consulted today.
func (v *Verifier) BeginRegistration(_ context.Context, subject, name, displayName string, existing []Credential) (*RegistrationChallenge, *Session, error) {
	if subject == "" {
		return nil, nil, fmt.Errorf("%w: subject is required", ErrInvalidConfig)
	}
	user := newWebauthnUser(subject, name, displayName, existing)

	exclusions := buildExclusions(existing)
	creation, sd, err := v.wa.BeginRegistration(user, webauthn.WithExclusions(exclusions))
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
// owners is the credential store the ceremony checks the freshly minted
// credential ID against. It is a required argument rather than an
// optional one because the check it enables is what stops a registration
// from taking a credential ID away from the subject that holds it; a
// caller that could pass it by omission would be able to skip the check
// by forgetting about it.
//
// The function returns:
//   - [ErrStoreRequired] when owners is nil;
//   - [ErrChallengeExpired] when the session has expired against the
//     verifier's clock;
//   - [ErrInvalidResponse] when the response payload cannot be parsed;
//   - [ErrAttestationInvalid] when the parsed response fails any
//     WebAuthn L3 §7.1 check;
//   - [ErrCredentialAlreadyExists] when the credential ID is already
//     present in the caller-supplied "existing" slice (intended to be
//     populated from [PasskeyStore.ListBySubject]) or is held in owners
//     by a different subject.
//
// On any error the returned [*Credential] is nil. Backends MUST NOT
// persist anything in that case.
func (v *Verifier) FinishRegistration(ctx context.Context, owners store.PasskeyStore, session *Session, subject, name, displayName string, existing []Credential, response []byte) (*Credential, error) {
	if owners == nil {
		return nil, ErrStoreRequired
	}
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

	// The list above only covers this subject. A credential ID held by
	// another subject has to be refused too, and only the store can
	// answer that.
	if err := ensureCredentialUnclaimed(ctx, owners, subject, wc.ID); err != nil {
		return nil, err
	}

	// Enforce the AAGUID allowlist. An empty allowlist on the Verifier
	// short-circuits to "any AAGUID allowed" so embedders that did not
	// configure [Config.AAGUIDAllowlist] are unaffected.
	//
	// When an allowlist IS configured the AAGUID must first be shown to
	// be authentic. Requesting "direct" conveyance only asks for an
	// attestation statement; it does not guarantee one that vouches for
	// the authenticator model. A response carrying self attestation
	// ("basic_surrogate") or no attestation at all is signed by the
	// credential's own key, which says nothing about which model
	// produced it — so the AAGUID is a value the caller chose. Checking
	// such a value against the allowlist would let any software
	// authenticator claim the identifier of a certified hardware key,
	// which is the whole thing the allowlist exists to prevent.
	if len(v.aaguidAllowlist) > 0 {
		if err := requireVouchedAttestation(wc.AttestationType); err != nil {
			return nil, err
		}
	}
	if !v.AAGUIDAllowed(wc.Authenticator.AAGUID) {
		return nil, fmt.Errorf("%w: AAGUID %x not in allowlist", ErrAttestationInvalid, wc.Authenticator.AAGUID)
	}

	out := fromWebauthnCredential(*wc)
	out.CreatedAt = v.clock().Now().UTC()
	return &out, nil
}

// ensureCredentialUnclaimed refuses a registration whose credential ID
// is already held by a different subject.
//
// WebAuthn Level 3 §7.1 step 27 requires the Relying Party to detect a
// credential ID that is already registered to another user and either
// fail the ceremony or delete the older registration. Failing is the
// only safe half of that choice here: [store.PasskeyStore.Put] is an
// upsert keyed on the credential ID, so admitting the registration would
// move the existing record onto the registering subject and unlink the
// authenticator of whoever held it — an account takeover no
// account-management screen can undo.
//
// A store fault is reported as a fault rather than swallowed: an
// unreadable owner record means the ceremony cannot establish that the
// credential is free, and admitting it on that basis would make a
// backend outage into the bypass.
func ensureCredentialUnclaimed(ctx context.Context, owners store.PasskeyStore, subject string, credentialID []byte) error {
	rec, err := owners.Get(ctx, credentialID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("passkey: look up credential owner: %w", err)
	case rec == nil:
		return nil
	case rec.Subject != subject:
		return ErrCredentialAlreadyExists
	default:
		return nil
	}
}

// requireVouchedAttestation reports whether an attestation of the given
// FIDO attestation type establishes the authenticator model, and so
// whether the AAGUID it carried may be compared against an allowlist.
//
// The vocabulary is the one the upstream library reports in
// [webauthn.Credential.AttestationType], per the FIDO Metadata
// Statement ATTESTATION_ constants. The distinction that matters is
// whether some party other than the credential itself signed for the
// model:
//
//   - "basic_full", "attca", "anonca", "ecdaa" — an attestation key or
//     CA outside the credential vouches for the authenticator, so the
//     AAGUID in the authenticator data is authenticated.
//   - "basic_surrogate" — self attestation: the attestation statement
//     is signed by the newly created credential key itself, so it
//     proves possession of that key and nothing about the hardware.
//   - "none" — no attestation statement at all.
//
// Anything unrecognised is refused rather than admitted, so a future
// library release that introduces another weak type does not silently
// widen the policy.
func requireVouchedAttestation(attestationType string) error {
	switch metadata.AuthenticatorAttestationType(attestationType) {
	case metadata.BasicFull, metadata.AttCA, metadata.AnonCA, metadata.Ecdaa:
		return nil
	default:
		return fmt.Errorf(
			"%w: attestation type %q does not authenticate the AAGUID, so it cannot satisfy the allowlist",
			ErrAttestationInvalid, attestationType)
	}
}

// buildExclusions projects the caller-supplied credentials onto the
// [protocol.CredentialDescriptor] slice the upstream library hands the
// authenticator as excludeCredentials. The transports list is cloned
// so a later mutation by the caller cannot reach the underlying
// session payload. An empty input returns an empty slice rather than
// nil so the WithExclusions option emits a deterministic empty
// list (matching the upstream API expectation that the option always
// installs a non-nil value).
func buildExclusions(existing []Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
		for i, t := range c.Transports {
			transports[i] = protocol.AuthenticatorTransport(t)
		}
		out = append(out, protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    slices.Clone(c.ID),
			Transport:       transports,
			AttestationType: c.AttestationType,
		})
	}
	return out
}
