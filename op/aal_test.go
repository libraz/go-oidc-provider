package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func TestAALString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   op.AAL
		want string
	}{
		{op.AAL0, "AAL0"},
		{op.AAL1, "AAL1"},
		{op.AAL2, "AAL2"},
		{op.AAL3, "AAL3"},
		{op.AAL(99), "AAL?"},
		{op.AAL(-1), "AAL?"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("AAL(%d).String() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
}

func TestAALACRURI(t *testing.T) {
	t.Parallel()

	// The exact strings are part of the public surface: persisted
	// id_tokens carry them, so a regression here would silently
	// break downstream relying parties that match on the literal.
	cases := []struct {
		in   op.AAL
		want string
	}{
		{op.AAL0, ""},
		{op.AAL1, "urn:mace:incommon:iap:bronze"},
		{op.AAL2, "urn:mace:incommon:iap:silver"},
		{op.AAL3, "http://idmanagement.gov/ns/assurance/loa/4"},
		{op.AAL(99), ""},
		{op.AAL(-1), ""},
	}
	for _, tc := range cases {
		if got := tc.in.ACRURI(); got != tc.want {
			t.Errorf("AAL(%d).ACRURI() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
}

func TestAALValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   op.AAL
		want bool
	}{
		{op.AAL0, true},
		{op.AAL1, true},
		{op.AAL2, true},
		{op.AAL3, true},
		{op.AAL(4), false},
		{op.AAL(99), false},
		{op.AAL(-1), false},
	}
	for _, tc := range cases {
		if got := tc.in.Valid(); got != tc.want {
			t.Errorf("AAL(%d).Valid() = %v, want %v", int(tc.in), got, tc.want)
		}
	}
}

// TestAALRoundTrip locks in the (String, ACRURI) pairing for every
// defined level. It is a single regression guard so a future refactor
// that renumbers the constants cannot silently shift the acr URIs.
func TestAALRoundTrip(t *testing.T) {
	t.Parallel()

	type pair struct {
		level  op.AAL
		str    string
		acrURI string
	}
	all := []pair{
		{op.AAL0, "AAL0", ""},
		{op.AAL1, "AAL1", "urn:mace:incommon:iap:bronze"},
		{op.AAL2, "AAL2", "urn:mace:incommon:iap:silver"},
		{op.AAL3, "AAL3", "http://idmanagement.gov/ns/assurance/loa/4"},
	}
	for _, p := range all {
		if !p.level.Valid() {
			t.Errorf("%s: Valid() = false, want true", p.str)
		}
		if got := p.level.String(); got != p.str {
			t.Errorf("%s: String() = %q", p.str, got)
		}
		if got := p.level.ACRURI(); got != p.acrURI {
			t.Errorf("%s: ACRURI() = %q, want %q", p.str, got, p.acrURI)
		}
	}
}
