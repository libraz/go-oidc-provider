package passkey_test

// One step value configures both ceremonies, so the user-verification
// requirement has to reach both. A deployment that demands UV but only
// enforces it at assertion time enrols the PIN-less roaming
// authenticator happily and then refuses every login it produces — the
// user is registered with a credential that cannot sign in, and no
// error at enrolment time said so.

import (
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// uvVerifier builds the verifier both ceremonies run on, from the same
// shared derivation the login step and the enrolment facade use.
func uvVerifier(t *testing.T, requireUV bool, now time.Time) *passkey.Verifier {
	t.Helper()

	v, err := passkey.New(passkey.ConfigFrom(passkey.StepPolicy{
		RPID:                    roundTripRPID,
		RPDisplayName:           "Example Identity",
		RPOrigins:               []string{roundTripOrigin},
		SessionTTL:              5 * time.Minute,
		RequireUserVerification: requireUV,
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.Clock = timex.ClockFunc(func() time.Time { return now })
	return v
}

// TestUserVerificationAppliesToBothCeremonies drives registration and
// assertion from one policy and asserts they agree on the gesture they
// demand: under RequireUserVerification an authenticator that only
// proves presence is refused by both, and one that verifies the user is
// accepted by both. The combination the invariant rules out — enrolment
// succeeding where login would fail — is what the first subtest would
// catch.
func TestUserVerificationAppliesToBothCeremonies(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	t.Run("required-refuses-a-presence-only-authenticator", func(t *testing.T) {
		t.Parallel()

		v := uvVerifier(t, true, now)
		key, err := softkey.New()
		if err != nil {
			t.Fatalf("softkey.New: %v", err)
		}
		// The authenticator performs no PIN / biometric gesture.
		key.UserVerified = false

		if _, err := registerAs(t, v, newEmptyPasskeyStore(t), key, roundTripSubject, nil); !errors.Is(err, passkey.ErrAttestationInvalid) {
			t.Fatalf("registration err=%v, want ErrAttestationInvalid: a credential enrolled without the gesture "+
				"this policy demands is one that can never be asserted with it", err)
		}

		// The credential the login side would have to work with, had the
		// enrolment gone through: registered while the policy was still
		// permissive, then asserted under the strict one.
		permissive := uvVerifier(t, false, now)
		registered, err := registerAs(t, permissive, newEmptyPasskeyStore(t), key, roundTripSubject, nil)
		if err != nil {
			t.Fatalf("registration under the permissive policy: %v", err)
		}
		if _, err := assertRoundTrip(t, v, key, []passkey.Credential{*registered}); !errors.Is(err, passkey.ErrAssertionInvalid) {
			t.Fatalf("assertion err=%v, want ErrAssertionInvalid", err)
		}
	})

	t.Run("required-accepts-a-verifying-authenticator", func(t *testing.T) {
		t.Parallel()

		v := uvVerifier(t, true, now)
		key, err := softkey.New()
		if err != nil {
			t.Fatalf("softkey.New: %v", err)
		}
		key.UserVerified = true

		registered, err := registerAs(t, v, newEmptyPasskeyStore(t), key, roundTripSubject, nil)
		if err != nil {
			t.Fatalf("registration: %v", err)
		}
		if !registered.Flags.UserVerified {
			t.Error("registered credential does not carry the UV flag")
		}
		asserted, err := assertRoundTrip(t, v, key, []passkey.Credential{*registered})
		if err != nil {
			t.Fatalf("assertion: %v", err)
		}
		if !asserted.Flags.UserVerified {
			t.Error("asserted credential does not carry the UV flag")
		}
	})

	t.Run("preferred-accepts-a-presence-only-authenticator", func(t *testing.T) {
		t.Parallel()

		v := uvVerifier(t, false, now)
		key, err := softkey.New()
		if err != nil {
			t.Fatalf("softkey.New: %v", err)
		}
		key.UserVerified = false

		registered, err := registerAs(t, v, newEmptyPasskeyStore(t), key, roundTripSubject, nil)
		if err != nil {
			t.Fatalf("registration: %v", err)
		}
		if _, err := assertRoundTrip(t, v, key, []passkey.Credential{*registered}); err != nil {
			t.Fatalf("assertion: %v", err)
		}
	})
}

// TestConfigFromDerivesBothPolicyAxes pins the derivation itself, since
// both call sites now depend on it rather than on their own copy.
func TestConfigFromDerivesBothPolicyAxes(t *testing.T) {
	t.Parallel()

	strict := passkey.ConfigFrom(passkey.StepPolicy{RequireUserVerification: true})
	if strict.UserVerification != "required" {
		t.Errorf("UserVerification = %q, want required", strict.UserVerification)
	}
	if strict.AttestationPreference != "none" {
		t.Errorf("AttestationPreference = %q, want none without an allowlist", strict.AttestationPreference)
	}

	relaxed := passkey.ConfigFrom(passkey.StepPolicy{AAGUIDAllowlist: []string{"fbfc3007-154e-4ecc-8c0b-6e020557d7bd"}})
	if relaxed.UserVerification != "preferred" {
		t.Errorf("UserVerification = %q, want preferred", relaxed.UserVerification)
	}
	// An allowlist is only enforceable against an attestation that vouches
	// for the AAGUID, so asking for one implies direct conveyance.
	if relaxed.AttestationPreference != "direct" {
		t.Errorf("AttestationPreference = %q, want direct alongside an allowlist", relaxed.AttestationPreference)
	}
}
