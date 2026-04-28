package op_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestDefaultACRPolicyResolveBackCompat confirms that a request without
// acr_values gets the AAL-derived InCommon URI, preserving the
// pre-ADR-0012 wire shape so deployments that never asked for acr_values
// see no change in their id_token wire form.
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

// TestDefaultACRPolicyResolveEcho confirms the OFCS-passing path: when
// the RP supplies acr_values the policy returns the first satisfied
// entry verbatim. The "first satisfied" rule lets a strict deployment
// override Satisfies and have the policy skip unsupported entries
// without touching Resolve.
func TestDefaultACRPolicyResolveEcho(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name      string
		level     op.AAL
		acrValues []string
		wantACR   string
		wantOK    bool
	}{
		{
			name:      "OFCS: acr_values=1 2 → echo 1",
			level:     op.AAL1,
			acrValues: []string{"1", "2"},
			wantACR:   "1",
			wantOK:    true,
		},
		{
			name:      "first preferred wins",
			level:     op.AAL2,
			acrValues: []string{"urn:mfa", "urn:loa1"},
			wantACR:   "urn:mfa",
			wantOK:    true,
		},
		{
			name:      "AAL0 → no entry satisfied → omit",
			level:     op.AAL0,
			acrValues: []string{"1"},
			wantACR:   "",
			wantOK:    false,
		},
		{
			name:      "empty string entries are skipped",
			level:     op.AAL2,
			acrValues: []string{"", "urn:mfa"},
			wantACR:   "urn:mfa",
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

// TestDefaultACRPolicySatisfies covers the lax-by-default predicate
// the policy exposes for strict-deployment overrides. The default rule
// is "any non-empty requested string is satisfied iff internal >= AAL1";
// the empty string is never satisfied so a misconfigured table cannot
// silently mark every login as satisfied.
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
		{name: "AAL0 → false", requested: "urn:mfa", level: op.AAL0, want: false},
		{name: "AAL1 → true", requested: "1", level: op.AAL1, want: true},
		{name: "AAL2 → true", requested: "urn:mfa", level: op.AAL2, want: true},
		{name: "AAL3 → true", requested: "urn:strict", level: op.AAL3, want: true},
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
