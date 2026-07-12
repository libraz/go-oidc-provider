package authn_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
)

func TestAALStringAndACRURIStableWireValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		level   authn.AAL
		str     string
		acrURI  string
		isValid bool
	}{
		{
			name:    "zero value no auth",
			level:   authn.AAL0,
			str:     "AAL0",
			acrURI:  "",
			isValid: true,
		},
		{
			name:    "single factor",
			level:   authn.AAL1,
			str:     "AAL1",
			acrURI:  "urn:mace:incommon:iap:bronze",
			isValid: true,
		},
		{
			name:    "multi factor",
			level:   authn.AAL2,
			str:     "AAL2",
			acrURI:  "urn:mace:incommon:iap:silver",
			isValid: true,
		},
		{
			name:    "hardware backed",
			level:   authn.AAL3,
			str:     "AAL3",
			acrURI:  "http://idmanagement.gov/ns/assurance/loa/4",
			isValid: true,
		},
		{
			name:    "below range",
			level:   authn.AAL(-1),
			str:     "AAL?",
			acrURI:  "",
			isValid: false,
		},
		{
			name:    "above range",
			level:   authn.AAL(4),
			str:     "AAL?",
			acrURI:  "",
			isValid: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.level.String(); got != tc.str {
				t.Fatalf("String() = %q, want %q", got, tc.str)
			}
			if got := tc.level.ACRURI(); got != tc.acrURI {
				t.Fatalf("ACRURI() = %q, want %q", got, tc.acrURI)
			}
			if got := tc.level.Valid(); got != tc.isValid {
				t.Fatalf("Valid() = %v, want %v", got, tc.isValid)
			}
		})
	}
}

func TestFactorTypeNamespaceClassification(t *testing.T) {
	t.Parallel()

	for _, typ := range []authn.FactorType{
		authn.FactorPassword,
		authn.FactorTOTP,
		authn.FactorPasskey,
		authn.FactorRecoveryCode,
		authn.FactorEmailOTP,
	} {
		typ := typ
		t.Run(typ.String(), func(t *testing.T) {
			t.Parallel()

			if !typ.IsBuiltin() {
				t.Fatalf("%q IsBuiltin() = false, want true", typ)
			}
			if typ.IsUserDefined() {
				t.Fatalf("%q IsUserDefined() = true, want false for reserved built-in", typ)
			}
			if got := typ.String(); got != string(typ) {
				t.Fatalf("String() = %q, want %q", got, string(typ))
			}
		})
	}

	cases := []struct {
		name            string
		typ             authn.FactorType
		wantBuiltin     bool
		wantUserDefined bool
	}{
		{name: "empty", typ: "", wantBuiltin: false, wantUserDefined: false},
		{name: "bare unknown reserved namespace", typ: "sms", wantBuiltin: false, wantUserDefined: false},
		{name: "case sensitive builtin", typ: "PASSWORD", wantBuiltin: false, wantUserDefined: false},
		{name: "dotted user extension", typ: "example.sms", wantBuiltin: false, wantUserDefined: true},
		{name: "dotted prefix is enough", typ: "vendor.", wantBuiltin: false, wantUserDefined: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.typ.IsBuiltin(); got != tc.wantBuiltin {
				t.Fatalf("IsBuiltin() = %v, want %v", got, tc.wantBuiltin)
			}
			if got := tc.typ.IsUserDefined(); got != tc.wantUserDefined {
				t.Fatalf("IsUserDefined() = %v, want %v", got, tc.wantUserDefined)
			}
		})
	}
}
