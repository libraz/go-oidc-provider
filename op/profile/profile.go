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
	//   - private_key_jwt client authentication (FAPI 2.0 §3.1.3;
	//     the profile also permits the two RFC 8705 §2 mTLS methods,
	//     which this library does not implement — see
	//     [AllowedClientAuthMethods]);
	//   - server-side access-token revocation
	//     (FAPI 2.0 §5.3.2.2).
	FAPICIBA

	// Baseline selects the OAuth 2.1 / RFC 9700 posture on top of
	// OpenID Connect Core 1.0. Its single MUST beyond the library
	// default is PKCE on every authorization-code request
	// (see [RequiresPKCE]).
	//
	// Baseline deliberately imposes nothing else: no access-token TTL
	// cap, no client-authentication restriction, no PAR mandate, no
	// sender-constrained tokens. Those are FAPI requirements, and
	// folding them in here would leave a profile no deployment could
	// adopt without also being financial-grade.
	//
	// The distinction Baseline draws is against the *unspecified*
	// configuration, not against FAPI. With no profile configured the
	// OP accepts an authorization-code request without a
	// code_challenge — the spec-compliant OIDC Core 1.0 shape the
	// OpenID Connect Basic certification suite drives. That default
	// cannot tell "we admit legacy relying parties on purpose" apart
	// from "we never considered it"; Baseline is how a deployment
	// says the former in the type system.
	//
	// Declared last so the numeric values of the FAPI constants stay
	// put; the wire form is [Profile.String], never the ordinal.
	Baseline
)

// String returns the canonical lower-case identifier used in discovery
// metadata and audit events. The values match the conformance suite test
// plan slugs.
func (p Profile) String() string {
	switch p {
	case Baseline:
		return "baseline"
	case FAPI2Baseline:
		return "fapi2-baseline"
	case FAPI2MessageSigning:
		return "fapi2-message-signing"
	case FAPICIBA:
		return "fapi-ciba"
	case profileUnspecified:
		return ""
	default:
		return ""
	}
}

// IsValid reports whether p is one of the recognised exported constants.
func (p Profile) IsValid() bool {
	switch p {
	case Baseline, FAPI2Baseline, FAPI2MessageSigning, FAPICIBA:
		return true
	case profileUnspecified:
		return false
	default:
		return false
	}
}

// RequiresAccessTokenRevocation reports whether p mandates
// server-side JWT access-token revocation. FAPI 2.0 Security Profile
// §5.3.2.2 imposes the requirement on the FAPI 2.0 family
// ([FAPI2Baseline], [FAPI2MessageSigning]); FAPI-CIBA inherits the
// same posture by reference (FAPI-CIBA-ID1 §5). Non-FAPI profiles —
// including [Baseline] — return false so embedders deploying plain
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
	case Baseline, profileUnspecified:
		return false
	}
	return false
}
