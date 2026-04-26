package passkey

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// webauthnUser implements the [webauthn.User] interface required by the
// library's BeginRegistration / BeginLogin entry points. It is a
// throw-away view assembled from the project's
// [github.com/libraz/go-oidc-provider/op/store.User] record plus the
// caller-supplied list of already-registered [Credential]s.
//
// # User-handle choice
//
// W3C WebAuthn Level 3 §5.4.3 recommends a 64-byte random user handle
// to "ensure secure operation [...] not the displayName nor name
// members". The recommendation is targeted at deployments where the
// account identifier is itself the email address or the human-typed
// username, both of which an attacker can enumerate cheaply.
//
// We intentionally diverge: the user handle is the OP-internal
// **subject** (the same value that becomes the "sub" claim of issued
// tokens). The trade-off is acceptable for this library because:
//
//  1. The OP controls the issuer namespace; subjects are opaque
//     identifiers picked by the embedder, not user-typed strings, so
//     the privacy concern that motivates the random handle ("don't
//     leak the email") does not apply.
//  2. The credential is bound to RPID, so even if the handle leaks
//     across other RPs it cannot be replayed against them.
//  3. Subject linkage is required for the AMR / ACR audit trail; a
//     random handle would force a separate index from handle to
//     subject, which is operational overhead with no security gain
//     given the previous two points.
//
// The handle is the UTF-8 byte sequence of the subject string. The
// underlying [webauthn.Config] keeps the library default
// (EncodeUserIDAsString = false) so the value round-trips through the
// CredentialCreationOptions JSON as a base64url-encoded string per the
// W3C WebAuthn convention for BufferSource fields. SPAs decode it back
// to a buffer through the standard PublicKeyCredential.parseCreationOptionsFromJSON
// helpers.
type webauthnUser struct {
	subject     []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

// newWebauthnUser assembles a [webauthnUser] from the OP-internal
// subject string, the (typically email or preferred_username) name, the
// human-displayable name shown by the user agent, and the list of
// already-registered credentials.
//
// The credentials list is used by the library at assertion time to
// populate allowCredentials in the CredentialRequestOptions emitted by
// BeginLogin. At registration time the library reads the same list
// only to compute the user-handle equality check inside
// CreateCredential; v1.0 does not project it into excludeCredentials
// (see [Verifier.BeginRegistration] for the rationale). Pass an empty
// slice when no credentials are yet registered; passing nil is
// equivalent.
func newWebauthnUser(subject, name, displayName string, creds []Credential) webauthnUser {
	wcs := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		wcs[i] = toWebauthnCredential(c)
	}
	return webauthnUser{
		subject:     []byte(subject),
		name:        name,
		displayName: displayName,
		credentials: wcs,
	}
}

// WebAuthnID implements [webauthn.User]. See the type-level comment for
// the rationale behind using the subject string as the handle.
func (u webauthnUser) WebAuthnID() []byte { return u.subject }

// WebAuthnName implements [webauthn.User].
func (u webauthnUser) WebAuthnName() string { return u.name }

// WebAuthnDisplayName implements [webauthn.User].
func (u webauthnUser) WebAuthnDisplayName() string { return u.displayName }

// WebAuthnCredentials implements [webauthn.User].
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
