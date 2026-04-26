package authn_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

func TestFactorAMRValueKnownTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   authn.Factor
		want string
	}{
		{
			name: "password",
			in:   authn.Factor{Type: authn.FactorTypePassword, AssuranceLevel: op.AAL1},
			want: "pwd",
		},
		{
			name: "totp",
			in:   authn.Factor{Type: authn.FactorTypeTOTP, AssuranceLevel: op.AAL2},
			want: "otp",
		},
		{
			name: "recovery_code",
			in:   authn.Factor{Type: authn.FactorTypeRecoveryCode, AssuranceLevel: op.AAL2},
			want: "otp",
		},
		{
			name: "passkey_no_uv",
			in:   authn.Factor{Type: authn.FactorTypePasskey, AssuranceLevel: op.AAL2, UserVerified: false},
			want: "swk",
		},
		{
			name: "passkey_uv",
			in:   authn.Factor{Type: authn.FactorTypePasskey, AssuranceLevel: op.AAL2, UserVerified: true},
			want: "hwk",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.AMRValue(); got != tc.want {
				t.Errorf("AMRValue() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFactorAMRValuePasskeyUVSwitch isolates the WebAuthn UV branch:
// the same factor type produces different RFC 8176 tokens depending on
// whether the authenticator verified the user. The aggregation rules
// downstream rely on this distinction (a UV passkey alone is AAL2 and
// reads as "hwk"; a non-UV passkey is "swk" and would not on its own
// satisfy a step-up requirement).
func TestFactorAMRValuePasskeyUVSwitch(t *testing.T) {
	t.Parallel()

	noUV := authn.Factor{Type: authn.FactorTypePasskey, UserVerified: false}
	withUV := authn.Factor{Type: authn.FactorTypePasskey, UserVerified: true}

	if got := noUV.AMRValue(); got != "swk" {
		t.Errorf("non-UV passkey AMRValue() = %q, want %q", got, "swk")
	}
	if got := withUV.AMRValue(); got != "hwk" {
		t.Errorf("UV passkey AMRValue() = %q, want %q", got, "hwk")
	}
}

// TestFactorAMRValueUnknownType locks in the contract that a foreign
// factor type contributes the empty string, which Aggregate then filters
// out so custom authenticators cannot pollute the amr claim.
func TestFactorAMRValueUnknownType(t *testing.T) {
	t.Parallel()

	cases := []string{"", "custom", "webauthn", "PASSWORD" /* case-sensitive */}
	for _, typ := range cases {
		f := authn.Factor{Type: typ, AssuranceLevel: op.AAL1}
		if got := f.AMRValue(); got != "" {
			t.Errorf("AMRValue() for type=%q = %q, want %q", typ, got, "")
		}
	}
}
