package op_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestDefaultACRPolicyResolveBackCompat confirms that a request without
// acr_values gets the AAL-derived InCommon URI, preserving the legacy
// wire shape so deployments that never asked for acr_values see no
// change in their id_token wire form.
func TestDefaultACRPolicyResolveBackCompat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name    string
		level   op.AAL
		wantACR string
		wantOK  bool
	}{
		{name: "AAL0 → omitted", level: op.AAL0, wantACR: "", wantOK: false},
		{name: "AAL1 → bronze", level: op.AAL1, wantACR: "urn:mace:incommon:iap:bronze", wantOK: true},
		{name: "AAL2 → silver", level: op.AAL2, wantACR: "urn:mace:incommon:iap:silver", wantOK: true},
		{name: "AAL3 → loa4", level: op.AAL3, wantACR: "http://idmanagement.gov/ns/assurance/loa/4", wantOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotACR, gotAMR, gotOK := op.DefaultACRPolicy{}.Resolve(ctx, op.LoginContext{}, tc.level)
			if gotACR != tc.wantACR {
				t.Errorf("acr = %q, want %q", gotACR, tc.wantACR)
			}
			if gotOK != tc.wantOK {
				t.Errorf("ok = %v, want %v", gotOK, tc.wantOK)
			}
			if gotAMR != nil {
				t.Errorf("amr = %v, want nil (caller-default flag)", gotAMR)
			}
		})
	}
}

// TestDefaultACRPolicyResolveEcho confirms the default policy returns
// the first requested entry the ceremony satisfied, and only a canonical
// URI can be satisfied: an unknown value is never echoed.
func TestDefaultACRPolicyResolveEcho(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const bronze = "urn:mace:incommon:iap:bronze"
	const silver = "urn:mace:incommon:iap:silver"
	tests := []struct {
		name      string
		level     op.AAL
		acrValues []string
		wantACR   string
		wantOK    bool
	}{
		{
			name:      "OFCS: acr_values=1 2 → unknown values are not echoed",
			level:     op.AAL1,
			acrValues: []string{"1", "2"},
			wantACR:   "",
			wantOK:    false,
		},
		{
			name:      "first satisfied canonical entry wins",
			level:     op.AAL2,
			acrValues: []string{silver, bronze},
			wantACR:   silver,
			wantOK:    true,
		},
		{
			name:      "unmet entry is skipped for a later satisfied one",
			level:     op.AAL1,
			acrValues: []string{silver, bronze},
			wantACR:   bronze,
			wantOK:    true,
		},
		{
			name:      "AAL0 → no entry satisfied → not ok",
			level:     op.AAL0,
			acrValues: []string{bronze},
			wantACR:   "",
			wantOK:    false,
		},
		{
			name:      "empty string entries are skipped",
			level:     op.AAL2,
			acrValues: []string{"", silver},
			wantACR:   silver,
			wantOK:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotACR, _, gotOK := op.DefaultACRPolicy{}.Resolve(ctx, op.LoginContext{ACRValues: tc.acrValues}, tc.level)
			if gotACR != tc.wantACR {
				t.Errorf("acr = %q, want %q", gotACR, tc.wantACR)
			}
			if gotOK != tc.wantOK {
				t.Errorf("ok = %v, want %v", gotOK, tc.wantOK)
			}
		})
	}
}

// TestDefaultACRPolicySatisfies covers the default predicate: a
// requested string is satisfied only when it is a canonical URI whose
// level the ceremony reached. Unknown strings and the empty string are
// never satisfied.
func TestDefaultACRPolicySatisfies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name      string
		requested string
		level     op.AAL
		want      bool
	}{
		{name: "empty requested → false", requested: "", level: op.AAL2, want: false},
		{name: "AAL0 → false", requested: op.AAL1.ACRURI(), level: op.AAL0, want: false},
		{name: "unknown value → false", requested: "1", level: op.AAL3, want: false},
		{name: "bronze at AAL1 → true", requested: op.AAL1.ACRURI(), level: op.AAL1, want: true},
		{name: "silver at AAL1 → false", requested: op.AAL2.ACRURI(), level: op.AAL1, want: false},
		{name: "silver at AAL3 → true", requested: op.AAL2.ACRURI(), level: op.AAL3, want: true},
		{name: "loa4 at AAL3 → true", requested: op.AAL3.ACRURI(), level: op.AAL3, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := op.DefaultACRPolicy{}.Satisfies(ctx, tc.requested, tc.level, nil)
			if got != tc.want {
				t.Errorf("Satisfies(%q, %v) = %v, want %v", tc.requested, tc.level, got, tc.want)
			}
		})
	}
}

// stubACRPolicy is the strict-deployment override used by
// TestACRPolicyOverride to confirm the seam works. The policy refuses
// to mark "urn:strict" as satisfied unless the chain reached AAL3 and
// completed the recovery_code step, mirroring a NIST SP 800-63 binding.
type stubACRPolicy struct {
	calls *int
}

func (p stubACRPolicy) Resolve(ctx context.Context, lc op.LoginContext, internal op.AAL) (string, []string, bool) {
	if p.calls != nil {
		*p.calls++
	}
	for _, want := range lc.ACRValues {
		if p.Satisfies(ctx, want, internal, lc.CompletedSteps) {
			return want, []string{"hwk", "mfa"}, true
		}
	}
	return "", nil, false
}

func (stubACRPolicy) Satisfies(_ context.Context, requested string, internal op.AAL, completed []op.StepKind) bool {
	if requested != "urn:strict" {
		return false
	}
	if internal < op.AAL3 {
		return false
	}
	for _, k := range completed {
		if k == op.StepKindRecoveryCode {
			return true
		}
	}
	return false
}

// TestACRPolicyOverrideShape confirms that a custom ACRPolicy is invoked
// and that its non-nil amr return replaces the per-factor aggregated
// amr. The test exercises the policy interface directly (the wiring
// adapter is covered by integration tests).
func TestACRPolicyOverrideShape(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	calls := 0
	policy := stubACRPolicy{calls: &calls}
	lc := op.LoginContext{
		ACRValues:      []string{"urn:strict"},
		CompletedSteps: []op.StepKind{op.StepKindPassword, op.StepKindRecoveryCode},
	}
	acr, amr, ok := policy.Resolve(ctx, lc, op.AAL3)
	if !ok || acr != "urn:strict" {
		t.Fatalf("Resolve = (%q, %v, %v), want (urn:strict, [hwk mfa], true)", acr, amr, ok)
	}
	if !reflect.DeepEqual(amr, []string{"hwk", "mfa"}) {
		t.Errorf("amr = %v, want [hwk mfa]", amr)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (Resolve invoked exactly once)", calls)
	}
	// Same policy must refuse to satisfy at AAL2 even with the right
	// completed step, locking in the strict predicate.
	_, _, ok = policy.Resolve(ctx, lc, op.AAL2)
	if ok {
		t.Errorf("AAL2 with strict policy: ok = true, want false")
	}
}

// TestACRLevels_Satisfies covers the lookup order (map entry, then
// canonical URI) and the failure shapes: unknown, empty and out-of-range
// entries are never satisfied.
func TestACRLevels_Satisfies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	levels := op.ACRLevels{
		"urn:x":    op.AAL2,
		"urn:zero": op.AAL0,
		"urn:wide": op.AAL(9),
	}
	tests := []struct {
		name      string
		levels    op.ACRLevels
		requested string
		internal  op.AAL
		want      bool
	}{
		{name: "map entry met", levels: levels, requested: "urn:x", internal: op.AAL2, want: true},
		{name: "map entry exceeded", levels: levels, requested: "urn:x", internal: op.AAL3, want: true},
		{name: "map entry unmet", levels: levels, requested: "urn:x", internal: op.AAL1, want: false},
		{name: "canonical via map-less lookup", levels: levels, requested: op.AAL1.ACRURI(), internal: op.AAL1, want: true},
		{name: "canonical unmet", levels: levels, requested: op.AAL3.ACRURI(), internal: op.AAL2, want: false},
		{name: "unknown", levels: levels, requested: "urn:other", internal: op.AAL3, want: false},
		{name: "empty requested", levels: levels, requested: "", internal: op.AAL3, want: false},
		{name: "AAL0 internal never satisfies", levels: levels, requested: "urn:x", internal: op.AAL0, want: false},
		{name: "entry mapped to AAL0 is unsatisfiable", levels: levels, requested: "urn:zero", internal: op.AAL3, want: false},
		{name: "entry mapped out of range is unsatisfiable", levels: levels, requested: "urn:wide", internal: op.AAL3, want: false},
		{name: "nil map handles canonical URIs", levels: nil, requested: op.AAL2.ACRURI(), internal: op.AAL2, want: true},
		{name: "empty map rejects unknown", levels: op.ACRLevels{}, requested: "urn:x", internal: op.AAL3, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.levels.Satisfies(ctx, tc.requested, tc.internal, nil); got != tc.want {
				t.Errorf("Satisfies(%q, %v) = %v, want %v", tc.requested, tc.internal, got, tc.want)
			}
		})
	}
}

// TestACRLevels_Resolve covers Resolve over a pairwise-generated model:
//
//	request kind: none | canonical (silver) | map value (urn:x) | unknown
//	achieved:     AAL1 | AAL2
//	policy:       DefaultACRPolicy | ACRLevels{"urn:x": AAL2}
//
// The request kind (voluntary / essential) and a custom ACRPolicy act
// on the wire layer, not on Resolve, and are covered end to end. The
// first eight rows cover every pair of the model; the remaining rows
// pin ordering and empty-entry handling.
func TestACRLevels_Resolve(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const silver = "urn:mace:incommon:iap:silver"
	const bronze = "urn:mace:incommon:iap:bronze"
	levels := op.ACRLevels{"urn:x": op.AAL2}
	var def op.ACRPolicy = op.DefaultACRPolicy{}
	tests := []struct {
		name      string
		policy    op.ACRPolicy
		level     op.AAL
		acrValues []string
		wantACR   string
		wantOK    bool
	}{
		{name: "none/AAL1/default", policy: def, level: op.AAL1, wantACR: bronze, wantOK: true},
		{name: "none/AAL2/levels", policy: levels, level: op.AAL2, wantACR: silver, wantOK: true},
		{name: "canonical/AAL1/levels", policy: levels, level: op.AAL1, acrValues: []string{silver}, wantOK: false},
		{name: "canonical/AAL2/default", policy: def, level: op.AAL2, acrValues: []string{silver}, wantACR: silver, wantOK: true},
		{name: "map/AAL1/default", policy: def, level: op.AAL1, acrValues: []string{"urn:x"}, wantOK: false},
		{name: "map/AAL2/levels", policy: levels, level: op.AAL2, acrValues: []string{"urn:x"}, wantACR: "urn:x", wantOK: true},
		{name: "unknown/AAL1/levels", policy: levels, level: op.AAL1, acrValues: []string{"urn:nope"}, wantOK: false},
		{name: "unknown/AAL2/default", policy: def, level: op.AAL2, acrValues: []string{"urn:nope"}, wantOK: false},
		{name: "no request at AAL0 → not ok", policy: levels, level: op.AAL0, wantOK: false},
		{name: "unmet entry skipped for a later met one", policy: levels, level: op.AAL1, acrValues: []string{"urn:x", bronze}, wantACR: bronze, wantOK: true},
		{name: "request order wins among met entries", policy: levels, level: op.AAL2, acrValues: []string{"urn:x", silver}, wantACR: "urn:x", wantOK: true},
		{name: "empty entry skipped", policy: levels, level: op.AAL2, acrValues: []string{"", "urn:x"}, wantACR: "urn:x", wantOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotACR, gotAMR, gotOK := tc.policy.Resolve(ctx, op.LoginContext{ACRValues: tc.acrValues}, tc.level)
			if gotACR != tc.wantACR || gotOK != tc.wantOK {
				t.Errorf("Resolve = (%q, %v), want (%q, %v)", gotACR, gotOK, tc.wantACR, tc.wantOK)
			}
			if gotAMR != nil {
				t.Errorf("amr = %v, want nil", gotAMR)
			}
		})
	}
}

// TestDefaultACRPolicy_DelegatesToACRLevels pins DefaultACRPolicy to an
// empty ACRLevels across a spread of inputs, so the two cannot drift.
func TestDefaultACRPolicy_DelegatesToACRLevels(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	requests := [][]string{
		nil,
		{op.AAL1.ACRURI()},
		{op.AAL3.ACRURI(), op.AAL2.ACRURI()},
		{"urn:unknown", op.AAL1.ACRURI()},
		{""},
	}
	for _, level := range []op.AAL{op.AAL0, op.AAL1, op.AAL2, op.AAL3} {
		for _, acrValues := range requests {
			lc := op.LoginContext{ACRValues: acrValues}
			wantACR, wantAMR, wantOK := op.ACRLevels(nil).Resolve(ctx, lc, level)
			gotACR, gotAMR, gotOK := op.DefaultACRPolicy{}.Resolve(ctx, lc, level)
			if gotACR != wantACR || gotOK != wantOK || !reflect.DeepEqual(gotAMR, wantAMR) {
				t.Errorf("Resolve(%v, %v) = (%q, %v, %v), want (%q, %v, %v)",
					acrValues, level, gotACR, gotAMR, gotOK, wantACR, wantAMR, wantOK)
			}
			for _, requested := range append([]string{"urn:unknown"}, acrValues...) {
				want := op.ACRLevels(nil).Satisfies(ctx, requested, level, nil)
				if got := (op.DefaultACRPolicy{}).Satisfies(ctx, requested, level, nil); got != want {
					t.Errorf("Satisfies(%q, %v) = %v, want %v", requested, level, got, want)
				}
			}
		}
	}
}
