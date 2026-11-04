package authn

import "strings"

// FactorType is the typed identifier for an [Authenticator] method. The
// string values double as identifiers in audit logs, [op/interaction]
// JSON, and the RFC 8176 amr derivation, so they MUST stay stable: the
// constants are the wire form and not just symbolic names. New built-in
// values ship with the library; embedders extend the namespace through
// dotted user identifiers (see [FactorType.IsUserDefined]).
type FactorType string

// Built-in [FactorType] values. The string content is the canonical
// identifier; renaming any of these breaks audit log continuity and
// orchestrator routing tables and is therefore a v1.0 freeze surface.
// User extensions: any FactorType whose string value contains a "." is
// treated as user-defined (e.g., "myorg.sms_otp"). Reserved bare names
// are exhausted by the constants below; pick a prefix.
const (
	// FactorPassword is a knowledge factor (RFC 8176 amr "pwd").
	FactorPassword FactorType = "password"

	// FactorTOTP is RFC 6238 time-based one-time password (amr "otp").
	FactorTOTP FactorType = "totp"

	// FactorPasskey is a WebAuthn assertion. RFC 8176 amr value
	// depends on the user-verification bit: "hwk" with UV, "swk"
	// without (see Factor.AMRValue).
	FactorPasskey FactorType = "passkey"

	// FactorRecoveryCode is a single-use pre-issued numeric code
	// stored at enrolment (amr "otp").
	FactorRecoveryCode FactorType = "recovery_code"

	// FactorEmailOTP is a code delivered through email. The factor
	// emits two prompts (send / verify) and is amr "otp".
	FactorEmailOTP FactorType = "email_otp"
)

// IsBuiltin reports whether t is one of the [FactorType] constants
// declared by the library. Built-in identifiers are reserved: a user
// extension MUST NOT match any of them, and the orchestrator rejects
// duplicates at construction time.
func (t FactorType) IsBuiltin() bool {
	switch t {
	case FactorPassword, FactorTOTP, FactorPasskey, FactorRecoveryCode, FactorEmailOTP:
		return true
	default:
		return false
	}
}

// IsUserDefined reports whether t is a non-empty user extension. The
// rule is intentionally simple — a dotted prefix segregates user
// extensions from the bare built-in identifiers — so that Authenticator
// authors do not need to consult a separate registry to verify their
// chosen name is safe.
func (t FactorType) IsUserDefined() bool {
	if t == "" || t.IsBuiltin() {
		return false
	}
	return strings.Contains(string(t), ".")
}

// String returns the underlying identifier. Provided for symmetry with
// the other typed-string identifiers in this package.
func (t FactorType) String() string { return string(t) }
