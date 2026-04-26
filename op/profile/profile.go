package profile

// Profile is the typed enumeration of industry security profiles supported
// by the library. The zero value is invalid; callers MUST use one of the
// exported constants.
type Profile uint8

const (
	// profileUnspecified is the zero value used to detect an uninitialised
	// [Profile]. Switch statements should surface it via the default arm
	// so accidentally-zero callers fail loudly.
	profileUnspecified Profile = iota

	// FAPI2Baseline selects the OpenID Foundation FAPI 2.0 Baseline OP
	// profile. It mandates PAR, PKCE, sender-constrained tokens (DPoP or
	// mTLS), and ES256 signing.
	FAPI2Baseline

	// FAPI2MessageSigning selects the FAPI 2.0 Message Signing OP
	// profile. It builds on Baseline by additionally requiring JAR and
	// JARM for non-repudiation of authorization request and response.
	FAPI2MessageSigning

	// FAPICIBA selects the FAPI Client-Initiated Backchannel
	// Authentication profile. v1.x.
	FAPICIBA

	// IGovHigh selects the OpenID iGov High profile. v2+.
	IGovHigh
)

// String returns the canonical lower-case identifier used in discovery
// metadata and audit events. The values match the conformance suite test
// plan slugs.
func (p Profile) String() string {
	switch p {
	case FAPI2Baseline:
		return "fapi2-baseline"
	case FAPI2MessageSigning:
		return "fapi2-message-signing"
	case FAPICIBA:
		return "fapi-ciba"
	case IGovHigh:
		return "igov-high"
	case profileUnspecified:
		return ""
	default:
		return ""
	}
}

// IsValid reports whether p is one of the recognised exported constants.
func (p Profile) IsValid() bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning, FAPICIBA, IGovHigh:
		return true
	case profileUnspecified:
		return false
	default:
		return false
	}
}
