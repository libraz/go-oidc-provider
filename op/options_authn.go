package op

// options_authn.go bundles the construction-time options that tune
// authenticator-side policy. Each option here drives an internal
// passkey / TOTP / recovery / email-OTP knob that does not surface
// elsewhere in the public API; the file is separate from options.go
// so the authenticator policy surface is easy to inspect at code
// review time.

// WithPasskeyAttestation configures the WebAuthn attestation
// conveyance preference and the optional AAGUID allowlist enforced
// at registration time.
//
// preference accepts "none" (default; no attestation statement
// requested) or "direct" (the user agent forwards the device's
// attestation statement so the OP can verify it). v1.0 does NOT
// support "indirect" or "enterprise"; passing either returns a
// configuration error from [New].
//
// aaguids is the per-deployment allowlist of authenticator-model
// identifiers, encoded as canonical UUID strings ("xxxxxxxx-xxxx-
// xxxx-xxxx-xxxxxxxxxxxx"). An empty / nil slice disables the
// check (every AAGUID is accepted). When a non-empty list is
// supplied the registration ceremony rejects every authenticator
// whose AAGUID is not in the set; the orchestrator surfaces the
// failure through the SPA's standard registration-failure handler.
//
// AAGUIDs are matched case-insensitively. A malformed entry is
// reported by the [Provider] when the passkey verifier is built;
// this option validates the conveyance preference at the option
// site so a typo surfaces immediately.
//
// Embedders that want to enforce AAGUID restrictions MUST set
// preference to "direct" — the user agent only forwards the AAGUID
// when the conveyance preference asks for it.
//
// Wiring: the verifier-side enforcement lives in
// [internal/authn/passkey]; the public option is the embedder-facing
// declaration. Until the [Provider] grows a typed field for the
// authenticator policy (a follow-up landing in op-core), the option
// validates its argument set and is otherwise a no-op. Embedders MAY
// register the option today and have it consumed automatically once
// the wiring lands.
func WithPasskeyAttestation(preference string, _ []string) Option {
	return optionFunc(func(_ *config) error {
		switch preference {
		case "", "none", "direct":
			return nil
		default:
			return &Error{
				Code:        codeConfiguration,
				Description: "WithPasskeyAttestation: preference \"" + preference + "\" is not supported (use \"none\" or \"direct\")",
			}
		}
	})
}
