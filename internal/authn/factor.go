package authn

// Factor records one successful authentication step contributed by a
// per-method verifier (password adapter, [totp.Verifier],
// [recovery.Consumer], [passkey.Asserter], ...). The orchestrator
// collects one Factor per verified step during a chain run and feeds
// the slice to [Aggregate] when the chain terminates.
//
// Factor is deliberately a flat data carrier: the per-method packages
// own their own state machines, and Factor is the narrow handoff back
// to the orchestrator. Adding fields here SHOULD NOT couple the
// aggregator to per-method internals; if a method needs richer context
// it MUST persist that context through its own store.
type Factor struct {
	// Type names the authenticator method that produced the factor.
	// Use one of the [FactorType] constants exported by the public
	// API (or a user-defined dotted identifier per
	// [FactorType.IsUserDefined]); foreign strings are preserved
	// across [Aggregate] but contribute no amr value.
	//
	// The constant strings are the same identifiers that flow through
	// [op/interaction.Result.AMR], so a Driver that round-trips a
	// custom authenticator name does not need a translation table.
	Type FactorType

	// AssuranceLevel is the [AAL] this factor independently
	// satisfies. The aggregator takes the maximum across the slice;
	// a single AAL3 factor therefore lifts the whole session, while
	// adding a weaker factor next to a stronger one does not weaken
	// it.
	AssuranceLevel AAL

	// UserVerified is true when the authenticator confirmed the user
	// (WebAuthn UV bit, biometric gesture, PIN). The aggregator only
	// reads it for [FactorPasskey], where UV distinguishes the
	// "swk" and "hwk" RFC 8176 tokens; other methods MAY leave it
	// false.
	UserVerified bool
}

// AMRValue returns the RFC 8176 §2 token corresponding to f.Type.
// Unknown types return the empty string; [Aggregate] filters those
// out so a foreign factor cannot pollute the amr claim. The receiver
// is a value; AMRValue does not mutate the factor.
//
// Mapping rationale:
//
//   - "pwd" — knowledge factor (password). RFC 8176 §2.
//   - "otp" — one-time password, used for TOTP, recovery codes, and
//     email OTP. Recovery codes are pre-issued numeric codes the user
//     stored out-of-band; they meet the RFC 8176 definition of
//     "one-time password" (a single-use code derived from a shared
//     secret) more cleanly than any of the possession-token values.
//     Email OTP shares the same rationale: a one-shot numeric code
//     derived from a server secret and delivered out-of-band.
//     Encoding them as "otp" keeps the amr claim semantically
//     accurate without inventing a non-IANA token.
//   - "swk" — software-keyed credential. Selected for a passkey
//     assertion that did not carry the UV bit: the user demonstrated
//     possession of the private key but no user-verification gesture
//     was performed. RFC 8176 §2 defines "swk" as proof of possession
//     of a software-secured key.
//   - "hwk" — hardware-keyed credential. Selected for a UV-verified
//     passkey assertion. RFC 8176 §2 defines "hwk" as proof of
//     possession of a hardware-secured key. WebAuthn does not let
//     the relying party distinguish a hardware authenticator from a
//     UV-protected platform credential at assertion time, so "hwk"
//     is the closest registered token; the embedder accepts the
//     well-known imprecision in exchange for a value RFC 8176
//     consumers already know how to render.
func (f Factor) AMRValue() string {
	switch f.Type {
	case FactorPassword:
		return "pwd"
	case FactorTOTP, FactorRecoveryCode, FactorEmailOTP:
		return "otp"
	case FactorPasskey:
		if f.UserVerified {
			return "hwk"
		}
		return "swk"
	default:
		return ""
	}
}
