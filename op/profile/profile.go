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

	// FAPI2Baseline selects the OpenID Foundation FAPI 2.0 Security
	// Profile (Final) Baseline OP profile. It enforces:
	//   - pushed authorization requests (PAR) on every authorization
	//     request, with a request_uri lifetime below 600 seconds;
	//   - PKCE and either state or nonce on every authorization request;
	//   - sender-constrained access tokens via DPoP or mTLS;
	//   - private_key_jwt, tls_client_auth or self_signed_tls_client_auth
	//     client authentication, with a client assertion "aud" equal to
	//     the issuer identifier as a single string;
	//   - no refresh-token rotation;
	//   - a 10-minute access-token TTL cap and no RS256 issuing.
	//
	// JAR processing is switched on, but a signed request object is NOT
	// required: plain PAR and form requests remain acceptable.
	FAPI2Baseline

	// FAPI2MessageSigning selects the FAPI 2.0 Message Signing OP
	// profile. It builds on [FAPI2Baseline] by additionally requiring:
	//   - a signed request object (JAR) on every /authorize and /par
	//     request;
	//   - JARM-signed authorization responses;
	//   - signed (RFC 9701 JWT) introspection responses;
	//   - a DPoP nonce source whenever DPoP is in use.
	FAPI2MessageSigning

	// FAPICIBA selects the FAPI Client-Initiated Backchannel
	// Authentication profile (FAPI-CIBA-ID1). It enforces:
	//   - signed authentication request on /bc-authorize
	//     (FAPI-CIBA-ID1 §5.2.2);
	//   - sender-constrained access tokens via DPoP or mTLS
	//     (inherited from FAPI 2.0 §3.1.4);
	//   - 10-minute access-token TTL cap (FAPI 2.0 §3.1.9);
	//   - private_key_jwt, tls_client_auth or self_signed_tls_client_auth
	//     client authentication (FAPI 2.0 §3.1.3; the two RFC 8705 §2
	//     methods need feature.MTLS — see [AllowedClientAuthMethods]);
	//   - server-side access-token revocation
	//     (FAPI 2.0 §5.3.2.2).
	FAPICIBA

	// OAuth21 selects the OAuth 2.1 / RFC 9700 posture on top of
	// OpenID Connect Core 1.0. Its single MUST beyond OpenID
	// Connect Core 1.0 is PKCE on every authorization-code request
	// (see [RequiresPKCE]). It is unrelated to FAPI 2.0 Baseline, which
	// is [FAPI2Baseline].
	//
	// OAuth21 deliberately imposes nothing else: no access-token TTL
	// cap, no client-authentication restriction, no PAR mandate, no
	// sender-constrained tokens. Those are FAPI requirements, and
	// folding them in here would leave a profile no deployment could
	// adopt without also being financial-grade.
	//
	// OAuth21 is the default: an OP built without [op.WithProfile]
	// behaves as if it were declared. A deployment that must admit
	// confidential clients without PKCE (legacy relying parties, the
	// OpenID Connect Basic certification suite) opts out with
	// [OIDCCore].
	//
	// Declared after the FAPI constants so their numeric values stay
	// put; the wire form is [Profile.String] ("oauth21"), never the
	// ordinal.
	//
	// Stable since v1.5.
	OAuth21

	// OIDCCore selects the OpenID Connect Core 1.0 shape explicitly:
	// PKCE stays optional for confidential clients and no other
	// requirement is added. It is for legacy relying parties and the
	// OpenID Connect Basic certification suite.
	//
	// It cannot be combined with any other profile; [op.New] rejects
	// the combination. String returns "oidc-core".
	//
	// Stable since v1.5.
	OIDCCore
)

// String returns the canonical lower-case identifier used in discovery
// metadata and audit events. The values match the conformance suite test
// plan slugs.
func (p Profile) String() string {
	switch p {
	case OAuth21:
		return "oauth21"
	case OIDCCore:
		return "oidc-core"
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
	case OAuth21, OIDCCore, FAPI2Baseline, FAPI2MessageSigning, FAPICIBA:
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
// including [OAuth21] — return false so embedders deploying plain
// OAuth 2.0 / OIDC can opt into [op.RevocationStrategyNone] without
// tripping the gate.
//
// The op.New validator consults this predicate to reject the
// combination of a FAPI profile with [op.RevocationStrategyNone]: the
// misconfiguration is caught at construction time so an operator never
// serves a single token before the gate fires.
func RequiresAccessTokenRevocation(p Profile) bool {
	return IsFAPI(p)
}

// IsFAPI reports whether p belongs to the FAPI family: [FAPI2Baseline],
// [FAPI2MessageSigning] or [FAPICIBA]. [OAuth21] and an unrecognised
// value return false.
func IsFAPI(p Profile) bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning, FAPICIBA:
		return true
	case OAuth21, OIDCCore, profileUnspecified:
		return false
	}
	return false
}

// RequiresSenderConstrainedTokens reports whether p forbids bearer access
// tokens. FAPI 2.0 §3.1.4 imposes the mandate on the FAPI 2.0 family and
// FAPI-CIBA inherits it (FAPI-CIBA-ID1 §5); [OAuth21] keeps bearer tokens
// legal.
func RequiresSenderConstrainedTokens(p Profile) bool {
	return IsFAPI(p)
}

// RequiresSignedRequestObject reports whether p mandates a signed JAR
// request object on every /authorize and /par request (FAPI 2.0 Message
// Signing §5.6). FAPI-CIBA's signed-request mandate applies to
// /bc-authorize only; see [RequiresSignedBackchannelRequest].
func RequiresSignedRequestObject(p Profile) bool {
	return p == FAPI2MessageSigning
}

// RequiresSignedBackchannelRequest reports whether p mandates a signed JAR
// request object on every /bc-authorize request (FAPI-CIBA-ID1 §5.2.2).
func RequiresSignedBackchannelRequest(p Profile) bool {
	return p == FAPICIBA
}

// RequiresJARMResponseMode reports whether p mandates that every
// /authorize response be JARM-wrapped (FAPI 2.0 Message Signing §5.5).
func RequiresJARMResponseMode(p Profile) bool {
	return p == FAPI2MessageSigning
}

// RequiresSignedIntrospection reports whether p forces every successful
// /introspect response onto the RFC 9701 JWT envelope (FAPI 2.0 Message
// Signing §5).
func RequiresSignedIntrospection(p Profile) bool {
	return p == FAPI2MessageSigning
}
