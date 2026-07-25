package passkey_test

import (
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
)

// TestAAGUIDAllowlistOnlyDecidesOnAVouchedAAGUID pins that an
// authenticator-model allowlist is never evaluated against an AAGUID
// the caller could have chosen.
//
// An AAGUID is not a credential: it travels in the authenticator data
// as a plain 16-byte field, and nothing about a registration response
// makes it true. What makes it true is an attestation statement signed
// by a key outside the credential — a batch attestation key, or a CA
// that vouches for the model. Without one, "this is a certified
// hardware key" is a claim the submitter typed, and an allowlist
// checking it reports that only approved models may register while
// admitting a software authenticator that named an approved model.
//
// The property has two halves, and both are needed because either one
// alone leaves the policy inert. A deployment must actually ask for
// attestation, and the response it gets back must actually carry one
// that identifies the model — asking is only a preference, and a
// self-attested or unattested response is a legal answer to it.
//
// Tracks: CVE-2026-6856 (Keycloak) — direct attestation was requested,
// but a response bearing packed self-attestation (no x5c chain) was
// accepted and its unverified AAGUID was matched against the
// acceptable-AAGUID policy, bypassing the allowlist.
func TestAAGUIDAllowlistOnlyDecidesOnAVouchedAAGUID(t *testing.T) {
	t.Parallel()

	const aaguid = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"

	t.Run("an allowlist cannot be configured without asking for attestation", func(t *testing.T) {
		t.Parallel()

		// Every conveyance other than "direct" leaves the AAGUID
		// self-asserted, so pairing one with an allowlist describes a
		// policy the ceremony cannot enforce. Refusing at construction
		// is what keeps that from being a silent runtime posture.
		for _, pref := range []protocol.ConveyancePreference{
			"",
			protocol.PreferNoAttestation,
		} {
			_, err := passkey.New(passkey.Config{
				RPID:            "op.test.invalid",
				RPDisplayName:   "OP",
				RPOrigins:       []string{"https://op.test.invalid"},
				AAGUIDAllowlist: []string{aaguid},

				AttestationPreference: pref,
			})
			if !errors.Is(err, passkey.ErrInvalidConfig) {
				t.Errorf("AttestationPreference %q with an allowlist: err=%v, want ErrInvalidConfig", pref, err)
			}
		}
	})

	t.Run("asking for attestation makes the allowlist configurable", func(t *testing.T) {
		t.Parallel()

		// The control. Without this the subtest above would also pass
		// against a build that rejects every allowlist outright.
		v, err := passkey.New(passkey.Config{
			RPID:                  "op.test.invalid",
			RPDisplayName:         "OP",
			RPOrigins:             []string{"https://op.test.invalid"},
			AAGUIDAllowlist:       []string{aaguid},
			AttestationPreference: protocol.PreferDirectAttestation,
		})
		if err != nil {
			t.Fatalf("direct attestation with an allowlist: %v", err)
		}
		if got := v.WebauthnForTest().Config.AttestationPreference; got != protocol.PreferDirectAttestation {
			t.Errorf("conveyance requested of the user agent = %q, want %q", got, protocol.PreferDirectAttestation)
		}
	})

	t.Run("a response whose attestation does not identify the model is refused", func(t *testing.T) {
		t.Parallel()

		// The attestation types the upstream library reports, split by
		// whether anything outside the credential signed for the
		// authenticator model. Only the vouched half may reach the
		// allowlist comparison; the rest must be refused before it,
		// however agreeable the AAGUID they carry looks.
		cases := []struct {
			attestationType metadata.AuthenticatorAttestationType
			vouched         bool
		}{
			{metadata.BasicFull, true},
			{metadata.AttCA, true},
			{metadata.AnonCA, true},
			{metadata.Ecdaa, true},

			// Self attestation: the statement is signed by the very
			// key being registered, so it proves possession of that
			// key and says nothing about the hardware around it.
			{metadata.BasicSurrogate, false},
			{metadata.None, false},

			// Anything the library might report in a future release
			// is refused rather than admitted, so a new weak type
			// cannot widen the policy by default.
			{"", false},
			{"some_future_type", false},
		}

		for _, tc := range cases {
			err := passkey.RequireVouchedAttestationForTest(string(tc.attestationType))
			switch {
			case tc.vouched && err != nil:
				t.Errorf("attestation type %q: err=%v, want accepted (an attestation key outside the credential signed for the model)",
					tc.attestationType, err)
			case !tc.vouched && err == nil:
				t.Errorf("attestation type %q: accepted, but nothing outside the credential vouched for the AAGUID, so the allowlist would be matching a caller-chosen value",
					tc.attestationType)
			case !tc.vouched && !errors.Is(err, passkey.ErrAttestationInvalid):
				t.Errorf("attestation type %q: err=%v, want ErrAttestationInvalid", tc.attestationType, err)
			}
		}
	})
}
