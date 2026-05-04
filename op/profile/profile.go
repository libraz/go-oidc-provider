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
	// Authentication profile (FAPI-CIBA-ID1). It enforces:
	//   - signed authentication request on /bc-authorize
	//     (FAPI-CIBA-ID1 §5.2.2);
	//   - sender-constrained access tokens via DPoP or mTLS
	//     (inherited from FAPI 2.0 §3.1.4);
	//   - 10-minute access-token TTL cap (FAPI 2.0 §3.1.9);
	//   - private_key_jwt / tls_client_auth /
	//     self_signed_tls_client_auth client authentication
	//     (FAPI 2.0 §3.1.3);
	//   - server-side access-token revocation
	//     (FAPI 2.0 §5.3.2.2).
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

// RequiresAccessTokenRevocation reports whether p mandates server-side
// JWT access-token revocation (ADR 0025). FAPI 2.0 Security Profile
// §5.3.2.2 imposes the requirement on the FAPI 2.0 family (Baseline,
// Message Signing); FAPI-CIBA inherits the same posture by reference
// (FAPI-CIBA-ID1 §5). The future iGov High profile is still a
// placeholder and will land here when its constraint table graduates.
// Non-FAPI profiles return false so embedders deploying plain
// OAuth 2.0 / OIDC can opt into [op.RevocationStrategyNone] without
// tripping the gate.
//
// The op.New validator consults this predicate to reject the
// combination of a FAPI profile with [op.RevocationStrategyNone]: the
// misconfiguration is caught at construction time so an operator never
// serves a single token before the gate fires.
func RequiresAccessTokenRevocation(p Profile) bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning, FAPICIBA:
		return true
	case IGovHigh, profileUnspecified:
		// IGovHigh is a placeholder today; it will land here when
		// its constraint table graduates.
		return false
	}
	return false
}
