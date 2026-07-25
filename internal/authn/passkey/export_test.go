package passkey

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// WebauthnForTest exposes the underlying [webauthn.WebAuthn] so tests
// can read the upstream configuration directly (e.g., the H-E6 freeze
// on Timeouts.Enforce=false) without re-deriving the value through
// the public surface.
func (v *Verifier) WebauthnForTest() *webauthn.WebAuthn {
	if v == nil {
		return nil
	}
	return v.wa
}

// ForceCloneDetectedForTest drives the clone-detection branch of the
// adapter's continueResult helper with a deterministic credential. It
// is the test seam for [CloneDetectionHandler] coverage: a real
// round-trip would require a soft authenticator minting a valid
// assertion signature with a non-incrementing counter, which the
// orchestrator integration suite stands up but the package-level
// tests do not.
//
// The function returns the error continueResult would have surfaced
// (always [ErrCloneDetected] when cred.Authenticator.CloneWarning is
// true). It deliberately bypasses persistCredential because the
// fake store used in clone-detection tests does not pre-populate the
// row — the contract under test is the handler invocation, not the
// store interaction.
func (a *Authenticator) ForceCloneDetectedForTest(ctx context.Context, subject string, cred *Credential) error {
	if a.driver != nil {
		_ = a.driver.HandleCloneDetected(ctx, subject, cred)
	}
	return ErrCloneDetected
}

// ContinueResultForTest invokes continueResult with the supplied
// credential as if FinishLogin returned (cred, nil). The seam exists
// so tests can assert the adapter's request-scoped UV propagation
// (H-E4) without standing up a soft authenticator. The wrapped
// helper persists the credential through the configured store; tests
// that want to skip the persist must inject a no-op store via
// fakePasskeyStore.
func (a *Authenticator) ContinueResultForTest(ctx context.Context, subject string, authTime time.Time, cred *Credential) interaction.Step {
	step, _ := a.continueResult(ctx, subject, authTime, cred, nil)
	return step
}

// SetExpectedSignCountForTest stamps the persistence snapshot normally
// carried from FinishLogin to persistCredential. It lets concurrency
// tests build verifier results without minting a WebAuthn signature.
func SetExpectedSignCountForTest(cred *Credential, signCount uint32) {
	if cred != nil {
		cred.expectedSignCount = signCount
	}
}

// ToWebauthnCredentialForTest exposes the package-private translation
// helper so tests in the _test package can drive the round-trip without
// reaching into unexported APIs.
func ToWebauthnCredentialForTest(c Credential) webauthn.Credential {
	return toWebauthnCredential(c)
}

// FromWebauthnCredentialForTest is the inverse of
// [ToWebauthnCredentialForTest].
func FromWebauthnCredentialForTest(wc webauthn.Credential) Credential {
	return fromWebauthnCredential(wc)
}

// EncodeSessionForTest exposes the package-private session projection
// so the session_test.go round-trip exercises the same code path as
// the BeginRegistration / BeginLogin entry points.
func EncodeSessionForTest(sd webauthn.SessionData) Session {
	return encodeSession(sd)
}

// DecodeSessionForTest is the inverse of [EncodeSessionForTest].
func DecodeSessionForTest(s Session) webauthn.SessionData {
	return decodeSession(s)
}

// DefaultSessionTTLForTest exposes [defaultSessionTTL] so tests can
// assert the default without duplicating the constant.
const DefaultSessionTTLForTest = defaultSessionTTL

// RequireVouchedAttestationForTest exposes the gate
// [Verifier.FinishRegistration] applies before an AAGUID is compared
// against the allowlist. The seam exists because the alternative —
// minting a self-attested CBOR attestation object — would exercise the
// upstream library's parser rather than this package's policy, and the
// policy is a single decision over the attestation type the library
// reports.
func RequireVouchedAttestationForTest(attestationType string) error {
	return requireVouchedAttestation(attestationType)
}

// CheckAAGUIDOnAssertionForTest exposes the M-AUTHN-2 helper so
// tests can drive the AAGUID re-check without standing up a soft
// authenticator. The seam invokes the same helper [Verifier.FinishLogin]
// calls before [webauthn.ValidateLogin], so a green test here means
// production callers see the same verdict.
func (v *Verifier) CheckAAGUIDOnAssertionForTest(credentials []Credential, rawID []byte) error {
	return v.checkAAGUIDOnAssertion(credentials, rawID)
}
