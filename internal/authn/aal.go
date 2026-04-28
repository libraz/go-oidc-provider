package authn

// AAL enumerates the Authenticator Assurance Levels the library tracks for a
// completed authentication. The model is the four-level ladder familiar from
// NIST SP 800-63B (no-auth / single-factor / multi-factor / hardware-backed),
// not the two-level "AAL1 / AAL2 / AAL3" taxonomy of the same document
// verbatim: the zero value of [AAL0] is reserved so that uninitialised
// authentication state is structurally distinguishable from a successful
// AAL1 login. Callers that need the literal NIST mapping use [AAL.ACRURI].
// The level is computed by the orchestrator from the per-factor
// [internal/authn.Factor] records emitted during a chain run; it is never
// read from the RP's authorization request. See
// 02-product-design.md §E.6.1 ("acr/amr の信頼源は session の
// amr_history のみ") for the rationale.
// Stable since v0.1.
type AAL int

// AAL constants. The naming follows the package convention of upper-case
// abbreviations; [AAL.String] returns the upper-case form ("AAL0",
// "AAL1"...) so log lines and audit records read consistently. RFC 8485
// uses lower-case ("aal0"...) inside acr_values strings; that wire form
// is intentionally not surfaced here because the library does not negotiate
// acr through 8485-style tokens in v1.0.
const (
	// AAL0 is the zero value: no successful authenticator step has run.
	// The orchestrator returns it for empty factor sets and for chains
	// that aborted before any factor verified.
	AAL0 AAL = iota

	// AAL1 is single-factor authentication (knowledge OR possession).
	// A password-only login is the canonical example.
	AAL1

	// AAL2 is two-factor authentication, OR a single factor strong
	// enough to stand in for two on its own (TOTP, WebAuthn passkey
	// with user-verification). NIST SP 800-63B §4.2 treats the latter
	// as AAL2-eligible because the cryptographic possession proof and
	// the UV gesture together cover both knowledge and possession.
	AAL2

	// AAL3 is hardware-backed authentication: the proof of possession
	// is bound to a tamper-resistant authenticator (FIDO2 cross-
	// platform key with attestation, smart card, hardware security
	// module). The library only reaches this level when a factor
	// explicitly carries AssuranceLevel == AAL3; passkeys default to
	// AAL2 even when UV is set, mirroring the conservative reading of
	// SP 800-63B §5.1.7.
	AAL3
)

// String returns the canonical text form of the level. The values are
// stable across versions: callers MAY persist them in audit logs.
func (l AAL) String() string {
	switch l {
	case AAL0:
		return "AAL0"
	case AAL1:
		return "AAL1"
	case AAL2:
		return "AAL2"
	case AAL3:
		return "AAL3"
	default:
		return "AAL?"
	}
}

// ACRURI returns the canonical Authentication Context Class Reference URI
// the library writes into the id_token "acr" claim for a session that
// closed at this level. The mapping is the InCommon / US-Federal
// equivalence table commonly used in the wild for NIST SP 800-63B AAL:
//   - AAL0 -> "" (no claim emitted; OIDC Core 1.0 §2 makes "acr"
//     optional, and an empty string lets the JSON encoder drop it).
//   - AAL1 -> "urn:mace:incommon:iap:bronze". The InCommon Identity
//     Assurance Profile bronze level corresponds to AAL1-equivalent
//     proofing; documented at https://spaces.at.internet2.edu/display/
//     InCAssurance/Bronze+Profile (InCommon Assurance Programs).
//   - AAL2 -> "urn:mace:incommon:iap:silver". Silver corresponds to
//     AAL2-equivalent proofing; same source as bronze above.
//   - AAL3 -> "http://idmanagement.gov/ns/assurance/loa/4". The US
//     federal Identity, Credential, and Access Management (ICAM)
//     Level of Assurance 4 (RFC 6711 registry) is the closest legacy
//     URI for hardware-backed authentication; modern deployments
//     often use vector-of-trust strings instead, which are out of
//     scope for v1.0.
//
// The mapping is deliberately not configurable. Embedders that need a
// different acr URI vocabulary will get a v1.x extension point; baking
// per-deployment URIs into v1.0 would let an embedder ship a configuration
// in which acr means nothing comparable across deployments.
func (l AAL) ACRURI() string {
	switch l {
	case AAL1:
		return "urn:mace:incommon:iap:bronze"
	case AAL2:
		return "urn:mace:incommon:iap:silver"
	case AAL3:
		return "http://idmanagement.gov/ns/assurance/loa/4"
	default:
		// AAL0 and any out-of-range value collapse to the empty
		// string so the id_token encoder drops the "acr" claim.
		return ""
	}
}

// Valid reports whether l is one of the defined AAL constants. The check
// is used by storage layers and tests that round-trip the value through
// an int column; callers that build an [AAL] from a literal constant in
// the same package do not need it.
func (l AAL) Valid() bool {
	return l >= AAL0 && l <= AAL3
}
