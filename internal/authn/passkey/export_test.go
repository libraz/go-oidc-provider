package passkey

import "github.com/go-webauthn/webauthn/webauthn"

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
