package authn_test

import (
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

// equalSlices is a helper for the aggregator's slice-valued result.
// reflect.DeepEqual treats a nil slice and an empty slice as different,
// which matters here: the aggregator uses nil to mean "no amr claim".
func equalSlices(a, b []string) bool {
	return reflect.DeepEqual(a, b)
}

func TestAggregateEmpty(t *testing.T) {
	t.Parallel()

	acr, amr, level := authn.Aggregate(nil)
	if acr != "" {
		t.Errorf("acr = %q, want empty", acr)
	}
	if amr != nil {
		t.Errorf("amr = %v, want nil", amr)
	}
	if level != op.AAL0 {
		t.Errorf("level = %v, want AAL0", level)
	}

	// An empty slice MUST behave the same as a nil slice.
	acr2, amr2, level2 := authn.Aggregate([]authn.Factor{})
	if acr2 != "" || amr2 != nil || level2 != op.AAL0 {
		t.Errorf("empty slice: acr=%q amr=%v level=%v", acr2, amr2, level2)
	}
}

func TestAggregateSingleFactor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		factor    authn.Factor
		wantACR   string
		wantAMR   []string
		wantLevel op.AAL
	}{
		{
			name:      "password",
			factor:    authn.Factor{Type: authn.FactorTypePassword, AssuranceLevel: op.AAL1},
			wantACR:   "urn:mace:incommon:iap:bronze",
			wantAMR:   []string{"pwd"},
			wantLevel: op.AAL1,
		},
		{
			name:      "totp",
			factor:    authn.Factor{Type: authn.FactorTypeTOTP, AssuranceLevel: op.AAL2},
			wantACR:   "urn:mace:incommon:iap:silver",
			wantAMR:   []string{"otp"},
			wantLevel: op.AAL2,
		},
		{
			name:      "passkey_uv",
			factor:    authn.Factor{Type: authn.FactorTypePasskey, AssuranceLevel: op.AAL2, UserVerified: true},
			wantACR:   "urn:mace:incommon:iap:silver",
			wantAMR:   []string{"hwk"},
			wantLevel: op.AAL2,
		},
		{
			name:      "passkey_hardware",
			factor:    authn.Factor{Type: authn.FactorTypePasskey, AssuranceLevel: op.AAL3, UserVerified: true},
			wantACR:   "http://idmanagement.gov/ns/assurance/loa/4",
			wantAMR:   []string{"hwk"},
			wantLevel: op.AAL3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			acr, amr, level := authn.Aggregate([]authn.Factor{tc.factor})
			if acr != tc.wantACR {
				t.Errorf("acr = %q, want %q", acr, tc.wantACR)
			}
			if !equalSlices(amr, tc.wantAMR) {
				t.Errorf("amr = %v, want %v", amr, tc.wantAMR)
			}
			if level != tc.wantLevel {
				t.Errorf("level = %v, want %v", level, tc.wantLevel)
			}
		})
	}
}

// TestAggregatePasswordPlusTOTP exercises the canonical MFA path: two
// distinct factors at AAL1 + AAL2 -> level AAL2, amr contains "mfa".
func TestAggregatePasswordPlusTOTP(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: authn.FactorTypePassword, AssuranceLevel: op.AAL1},
		{Type: authn.FactorTypeTOTP, AssuranceLevel: op.AAL2},
	}
	acr, amr, level := authn.Aggregate(factors)

	if acr != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr = %q, want silver", acr)
	}
	if level != op.AAL2 {
		t.Errorf("level = %v, want AAL2", level)
	}
	want := []string{"mfa", "otp", "pwd"}
	if !equalSlices(amr, want) {
		t.Errorf("amr = %v, want %v", amr, want)
	}

	// Explicit assertion: "mfa" MUST be present so a regression that
	// drops the multi-factor signal fails loudly.
	found := false
	for _, v := range amr {
		if v == "mfa" {
			found = true
			break
		}
	}
	if !found {
		t.Error("amr does not contain \"mfa\"")
	}
}

// TestAggregatePasswordPlusRecoveryCode confirms that a recovery code
// counts as a distinct factor (its AMRValue is "otp", different from
// the password's "pwd"), so the pair earns an "mfa" tag too.
func TestAggregatePasswordPlusRecoveryCode(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: authn.FactorTypePassword, AssuranceLevel: op.AAL1},
		{Type: authn.FactorTypeRecoveryCode, AssuranceLevel: op.AAL2},
	}
	acr, amr, level := authn.Aggregate(factors)

	if acr != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr = %q, want silver", acr)
	}
	if level != op.AAL2 {
		t.Errorf("level = %v, want AAL2", level)
	}
	want := []string{"mfa", "otp", "pwd"}
	if !equalSlices(amr, want) {
		t.Errorf("amr = %v, want %v", amr, want)
	}
}

// TestAggregateTOTPTwiceNoMFA documents the "distinct values" rule:
// stepping up TOTP after an initial TOTP login produces two factors
// that both report "otp", so the deduplicated set has one entry and
// "mfa" is NOT appended. The user authenticated with one method twice,
// not with two methods.
func TestAggregateTOTPTwiceNoMFA(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: authn.FactorTypeTOTP, AssuranceLevel: op.AAL2},
		{Type: authn.FactorTypeTOTP, AssuranceLevel: op.AAL2},
	}
	acr, amr, level := authn.Aggregate(factors)

	if acr != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr = %q, want silver", acr)
	}
	if level != op.AAL2 {
		t.Errorf("level = %v, want AAL2", level)
	}
	want := []string{"otp"}
	if !equalSlices(amr, want) {
		t.Errorf("amr = %v, want %v (no \"mfa\" because the values are identical)", amr, want)
	}
}

// TestAggregatePasskeyUVPlusTOTP combines two distinct strong factors.
// Both contribute AAL2; the level stays at AAL2; and the distinct AMR
// set {"hwk", "otp"} earns the "mfa" tag. The result is sorted.
func TestAggregatePasskeyUVPlusTOTP(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: authn.FactorTypePasskey, AssuranceLevel: op.AAL2, UserVerified: true},
		{Type: authn.FactorTypeTOTP, AssuranceLevel: op.AAL2},
	}
	acr, amr, level := authn.Aggregate(factors)

	if acr != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr = %q, want silver", acr)
	}
	if level != op.AAL2 {
		t.Errorf("level = %v, want AAL2", level)
	}
	want := []string{"hwk", "mfa", "otp"}
	if !equalSlices(amr, want) {
		t.Errorf("amr = %v, want %v", amr, want)
	}
}

// TestAggregateUnknownFactorContributesLevelOnly confirms that a
// foreign factor type still lifts the assurance level (so a custom
// authenticator can satisfy a step-up policy) but does not insert
// anything into amr.
func TestAggregateUnknownFactorContributesLevelOnly(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: "custom", AssuranceLevel: op.AAL1},
	}
	acr, amr, level := authn.Aggregate(factors)

	if acr != "urn:mace:incommon:iap:bronze" {
		t.Errorf("acr = %q, want bronze", acr)
	}
	if amr != nil {
		t.Errorf("amr = %v, want nil (foreign factor must not pollute the claim)", amr)
	}
	if level != op.AAL1 {
		t.Errorf("level = %v, want AAL1", level)
	}
}

// TestAggregateAllAAL0 exercises the all-factors-zero edge: the chain
// runner reports unknown / no-assurance steps only. Foreign types
// contribute no amr entries and the level stays at AAL0, so the result
// matches the empty-input case (acr empty, amr nil).
func TestAggregateAllAAL0(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: "custom", AssuranceLevel: op.AAL0},
		{Type: "other", AssuranceLevel: op.AAL0},
	}
	acr, amr, level := authn.Aggregate(factors)

	if acr != "" {
		t.Errorf("acr = %q, want empty", acr)
	}
	if amr != nil {
		t.Errorf("amr = %v, want nil", amr)
	}
	if level != op.AAL0 {
		t.Errorf("level = %v, want AAL0", level)
	}
}

// TestAggregatePasswordAtAAL0 documents that the aggregator does not
// override the caller's claim about a factor's assurance: if a chain
// reports a password step but tags it AAL0 (perhaps because the
// password store is in a degraded mode), the amr entry "pwd" still
// appears but the level stays at AAL0 and acr is empty. This is a
// corner the chain runner is responsible for not producing in steady
// state; the test exists to lock in that the aggregator does not
// auto-promote the level on its behalf.
func TestAggregatePasswordAtAAL0(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: authn.FactorTypePassword, AssuranceLevel: op.AAL0},
	}
	acr, amr, level := authn.Aggregate(factors)

	if acr != "" {
		t.Errorf("acr = %q, want empty", acr)
	}
	if !equalSlices(amr, []string{"pwd"}) {
		t.Errorf("amr = %v, want [\"pwd\"]", amr)
	}
	if level != op.AAL0 {
		t.Errorf("level = %v, want AAL0", level)
	}
}

// TestAggregateMFAGuardBelowAAL2 exercises the "level >= AAL2" guard
// on the mfa tag: two distinct factors at AAL1 each are still
// suspicious from an assurance perspective, so we do NOT mint an "mfa"
// claim that would exaggerate the strength of the authentication.
func TestAggregateMFAGuardBelowAAL2(t *testing.T) {
	t.Parallel()

	factors := []authn.Factor{
		{Type: authn.FactorTypePassword, AssuranceLevel: op.AAL1},
		// A second knowledge-equivalent factor at AAL1.
		{Type: "custom", AssuranceLevel: op.AAL1},
	}
	acr, amr, level := authn.Aggregate(factors)

	if level != op.AAL1 {
		t.Errorf("level = %v, want AAL1", level)
	}
	if acr != "urn:mace:incommon:iap:bronze" {
		t.Errorf("acr = %q, want bronze", acr)
	}
	// The custom factor contributes no amr entry, so even though
	// the chain saw two factors, only "pwd" appears and the mfa
	// tag is absent.
	if !equalSlices(amr, []string{"pwd"}) {
		t.Errorf("amr = %v, want [\"pwd\"]", amr)
	}
}

// TestAggregateDoesNotMutateInput is a safety net: callers reuse the
// factor slice elsewhere (audit log, telemetry), and the aggregator
// must not surprise them by reordering or rewriting it.
func TestAggregateDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	in := []authn.Factor{
		{Type: authn.FactorTypeTOTP, AssuranceLevel: op.AAL2},
		{Type: authn.FactorTypePassword, AssuranceLevel: op.AAL1},
	}
	snapshot := make([]authn.Factor, len(in))
	copy(snapshot, in)

	_, amr, _ := authn.Aggregate(in)

	// Mutating the result MUST NOT echo into the input.
	if len(amr) > 0 {
		amr[0] = "tampered"
	}

	if !reflect.DeepEqual(in, snapshot) {
		t.Errorf("input mutated: in = %#v, snapshot = %#v", in, snapshot)
	}
}
