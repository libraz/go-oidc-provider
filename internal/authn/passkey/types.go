package passkey

import (
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Credential is the project-shaped view of a registered passkey. It
// mirrors [webauthn.Credential] but carries a [time.Time] CreatedAt
// stamp the upstream type does not (it is bookkeeping the OP needs for
// account-management UIs) and exposes [CredentialFlags] /
// [AuthenticatorData] as flat structs without the unexported "raw"
// field [webauthn.CredentialFlags] keeps for protocol round-tripping.
//
// The struct is the value [Verifier.FinishRegistration] returns and the
// shape callers feed back into BeginLogin / FinishLogin. Registration
// callers translate it to a
// [github.com/libraz/go-oidc-provider/op/store.PasskeyRecord] and use
// [github.com/libraz/go-oidc-provider/op/store.PasskeyStore.Put];
// assertion callers persist only its mutable fields through
// [github.com/libraz/go-oidc-provider/op/store.PasskeyStore.UpdateAssertion].
type Credential struct {
	// ID is the credential ID emitted by the authenticator at
	// registration time. It is the primary key of the stored record
	// and the value the SPA echoes back inside the assertion.
	ID []byte

	// PublicKey is the COSE_Key encoded public key. The library uses
	// it to verify assertions; backends MUST treat it as opaque.
	PublicKey []byte

	// AttestationType is the attestation format string returned by
	// the authenticator (for example "none", "packed", "fido-u2f").
	// In v1.0 the registration ceremony forces AttestationPreference
	// = "none" so the value is almost always "none"; the field is
	// retained verbatim so a future v1.x that enables direct
	// attestation can read back values written today.
	AttestationType string

	// Transports lists the [protocol.AuthenticatorTransport] hints
	// the authenticator advertised. The library round-trips the
	// values through the assertion AllowedCredentials list so user
	// agents can prefer the authenticator that registered the
	// credential.
	Transports []string

	// Flags carries the four authenticator-data flags every
	// registered credential record persists. See [CredentialFlags]
	// for the per-bit semantics.
	Flags CredentialFlags

	// Authenticator holds the AAGUID, sign counter, clone-warning
	// flag, and attachment hint observed at the most recent
	// ceremony. The struct is updated on every successful assertion;
	// callers MUST persist the new value.
	Authenticator AuthenticatorData

	// CreatedAt is the wall-clock time the credential was registered
	// (i.e. the verifier's clock reading at FinishRegistration).
	// Backends SHOULD surface it in account-management UIs so users
	// can identify which authenticator is which. The field is OP
	// bookkeeping; the upstream [webauthn.Credential] does not carry
	// it.
	CreatedAt time.Time

	// expectedSignCount is the persisted counter against which this
	// assertion was verified. It is intentionally package-private:
	// only the verifier-to-store path consumes it, while public
	// callers continue to treat Credential as the ceremony result.
	expectedSignCount uint32
}

// CredentialFlags mirrors the four authenticator-data flag bits that
// matter for risk-scoring, sign-counter handling, and discoverable
// credential lifecycle. See WebAuthn L3 §6.1 "Authenticator Data" for
// the source-of-truth descriptions.
type CredentialFlags struct {
	// UserPresent (UP) reports whether the user proved physical
	// presence (typically by touching the authenticator). All
	// non-conditional ceremonies require UP.
	UserPresent bool

	// UserVerified (UV) reports whether the authenticator verified
	// the user via biometric or PIN. Set the registration policy via
	// [protocol.AuthenticatorSelection.UserVerification]; v1.0 uses
	// "preferred" so the bit may be either value.
	UserVerified bool

	// BackupEligible (BE) is the WebAuthn L3 flag that reports
	// whether the credential MAY be backed up by the authenticator
	// (for example synced to the platform's iCloud / Google account).
	// The value is fixed at credential creation and MUST NOT change
	// across assertions; the library detects a flip and rejects the
	// assertion.
	BackupEligible bool

	// BackupState (BS) reports whether the credential has actually
	// been backed up. Unlike BE this flag may legitimately change
	// over time (a previously local-only credential becomes synced
	// after the user enables sync).
	BackupState bool
}

// AuthenticatorData holds the per-authenticator context the OP needs
// for risk-scoring and clone detection. It mirrors
// [webauthn.Authenticator] but stores [Attachment] as a plain string so
// downstream code does not have to import the protocol package just to
// read the field.
type AuthenticatorData struct {
	// AAGUID is the 16-byte authenticator model identifier. It is
	// fixed at the device level and identifies the authenticator
	// vendor / model. v1.0 does not enforce an AAGUID allow-list; the
	// field is persisted so a future v1.x policy can read it back.
	AAGUID []byte

	// SignCount is the authenticator-supplied signature counter
	// observed at the most recent ceremony. The library checks every
	// assertion against the stored value and stamps [CloneWarning]
	// when the new value is not strictly greater (see WebAuthn L3
	// §7.2 step 17).
	SignCount uint32

	// CloneWarning is set to true when the authenticator returned a
	// sign counter equal to or below the previously stored value.
	// The library does NOT fail the assertion automatically — the
	// risk decision belongs to the orchestrator — but the flag MUST
	// be persisted so an account-management UI can highlight the
	// affected credential.
	CloneWarning bool

	// Attachment is the [protocol.AuthenticatorAttachment] hint
	// ("platform" or "cross-platform") returned by the user agent.
	// It is informational and reflected back to the user in
	// account-management UIs; an empty string means the user agent
	// did not report an attachment.
	Attachment string
}

// toWebauthnCredential translates a project-shaped [Credential] to the
// upstream [webauthn.Credential] consumed by the library's assertion
// validator. The mapping is field-for-field:
//
//   - ID, PublicKey, AttestationType: copied verbatim.
//   - Transports: each string is wrapped in a
//     [protocol.AuthenticatorTransport].
//   - Flags.{UserPresent, UserVerified, BackupEligible, BackupState}:
//     copied to the matching bit in [webauthn.CredentialFlags]. The
//     upstream type also keeps a private "raw" field that we cannot
//     populate from outside the package; the library does not consult
//     it during assertion validation so the omission is safe.
//   - Authenticator.{AAGUID, SignCount, CloneWarning}: copied
//     verbatim. Attachment is wrapped in
//     [protocol.AuthenticatorAttachment].
//   - CreatedAt: discarded — the upstream type has no equivalent.
func toWebauthnCredential(c Credential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID:              slices.Clone(c.ID),
		PublicKey:       slices.Clone(c.PublicKey),
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    c.Flags.UserPresent,
			UserVerified:   c.Flags.UserVerified,
			BackupEligible: c.Flags.BackupEligible,
			BackupState:    c.Flags.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       slices.Clone(c.Authenticator.AAGUID),
			SignCount:    c.Authenticator.SignCount,
			CloneWarning: c.Authenticator.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(c.Authenticator.Attachment),
		},
	}
}

// fromWebauthnCredential is the inverse of [toWebauthnCredential]. The
// CreatedAt field is left zero — callers stamp it from their clock
// before persisting the value. Field mapping mirrors
// [toWebauthnCredential]; see that comment for the per-field rationale.
func fromWebauthnCredential(wc webauthn.Credential) Credential {
	transports := make([]string, len(wc.Transport))
	for i, t := range wc.Transport {
		transports[i] = string(t)
	}
	return Credential{
		ID:              slices.Clone(wc.ID),
		PublicKey:       slices.Clone(wc.PublicKey),
		AttestationType: wc.AttestationType,
		Transports:      transports,
		Flags: CredentialFlags{
			UserPresent:    wc.Flags.UserPresent,
			UserVerified:   wc.Flags.UserVerified,
			BackupEligible: wc.Flags.BackupEligible,
			BackupState:    wc.Flags.BackupState,
		},
		Authenticator: AuthenticatorData{
			AAGUID:       slices.Clone(wc.Authenticator.AAGUID),
			SignCount:    wc.Authenticator.SignCount,
			CloneWarning: wc.Authenticator.CloneWarning,
			Attachment:   string(wc.Authenticator.Attachment),
		},
	}
}
