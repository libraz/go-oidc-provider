package authn_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

// TestFactorEffectiveAALPasskeyUV isolates the rule that decides how
// much a passkey assertion is worth. The adapter declares AAL2 because
// that is the ceiling a user-verified assertion reaches, but the UV bit
// is only known once the authenticator answers: a presence-only
// assertion proved possession of the key and nothing else, which is one
// factor, so it settles at AAL1.
func TestFactorEffectiveAALPasskeyUV(t *testing.T) {
	t.Parallel()

	noUV := authn.Factor{Type: op.FactorPasskey, AssuranceLevel: op.AAL2, UserVerified: false}
	withUV := authn.Factor{Type: op.FactorPasskey, AssuranceLevel: op.AAL2, UserVerified: true}

	if got := noUV.EffectiveAAL(); got != op.AAL1 {
		t.Errorf("presence-only passkey EffectiveAAL() = %v, want %v", got, op.AAL1)
	}
	if got := withUV.EffectiveAAL(); got != op.AAL2 {
		t.Errorf("user-verified passkey EffectiveAAL() = %v, want %v", got, op.AAL2)
	}
}

// TestFactorEffectiveAALNonPasskeyUnaffected confirms the cap is scoped
// to the WebAuthn factor. UserVerified is documented as passkey-specific
// and other methods MAY leave it false, so reading it for them would
// demote every password / TOTP login.
func TestFactorEffectiveAALNonPasskeyUnaffected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   authn.Factor
		want op.AAL
	}{
		{
			name: "password",
			in:   authn.Factor{Type: op.FactorPassword, AssuranceLevel: op.AAL1},
			want: op.AAL1,
		},
		{
			name: "totp",
			in:   authn.Factor{Type: op.FactorTOTP, AssuranceLevel: op.AAL2},
			want: op.AAL2,
		},
		{
			name: "email_otp",
			in:   authn.Factor{Type: op.FactorEmailOTP, AssuranceLevel: op.AAL2},
			want: op.AAL2,
		},
		{
			name: "custom",
			in:   authn.Factor{Type: "custom.sso", AssuranceLevel: op.AAL2},
			want: op.AAL2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.EffectiveAAL(); got != tc.want {
				t.Errorf("EffectiveAAL() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAggregatePasskeyWithoutUVIsSingleFactor is the observable half of
// the rule: the acr the session records for a presence-only passkey
// login is the AAL1 URI, not the AAL2 one. Reporting silver here would
// let a login that never performed a user-verification gesture satisfy
// a step-up that asked for two factors.
func TestAggregatePasskeyWithoutUVIsSingleFactor(t *testing.T) {
	t.Parallel()

	acr, amr, level := authn.Aggregate([]authn.Factor{
		{Type: op.FactorPasskey, AssuranceLevel: op.AAL2, UserVerified: false},
	})
	if level != op.AAL1 {
		t.Errorf("level = %v, want %v", level, op.AAL1)
	}
	if want := "urn:mace:incommon:iap:bronze"; acr != want {
		t.Errorf("acr = %q, want %q", acr, want)
	}
	if !equalSlices(amr, []string{"swk"}) {
		t.Errorf("amr = %v, want [swk]", amr)
	}
}

// TestAggregatePasskeyWithUVIsTwoFactor is the symmetric case: the same
// adapter with the UV bit set reaches AAL2 and reports the silver acr.
func TestAggregatePasskeyWithUVIsTwoFactor(t *testing.T) {
	t.Parallel()

	acr, amr, level := authn.Aggregate([]authn.Factor{
		{Type: op.FactorPasskey, AssuranceLevel: op.AAL2, UserVerified: true},
	})
	if level != op.AAL2 {
		t.Errorf("level = %v, want %v", level, op.AAL2)
	}
	if want := "urn:mace:incommon:iap:silver"; acr != want {
		t.Errorf("acr = %q, want %q", acr, want)
	}
	if !equalSlices(amr, []string{"hwk"}) {
		t.Errorf("amr = %v, want [hwk]", amr)
	}
}

// TestAggregatePasswordPlusPresenceOnlyPasskey covers the combination a
// deployment running passkey as a second step actually produces: the
// pair is two distinct methods, so amr carries "mfa" — but neither
// factor reached AAL2 on its own, so the session settles at AAL1 and
// the "mfa" tag (which Aggregate gates on AAL2) is withheld.
func TestAggregatePasswordPlusPresenceOnlyPasskey(t *testing.T) {
	t.Parallel()

	acr, amr, level := authn.Aggregate([]authn.Factor{
		{Type: op.FactorPassword, AssuranceLevel: op.AAL1},
		{Type: op.FactorPasskey, AssuranceLevel: op.AAL2, UserVerified: false},
	})
	if level != op.AAL1 {
		t.Errorf("level = %v, want %v", level, op.AAL1)
	}
	if want := "urn:mace:incommon:iap:bronze"; acr != want {
		t.Errorf("acr = %q, want %q", acr, want)
	}
	if !equalSlices(amr, []string{"pwd", "swk"}) {
		t.Errorf("amr = %v, want [pwd swk]", amr)
	}
}
