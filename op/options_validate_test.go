package op_test

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestFeatureFlag_RejectedWithoutItsConfiguringOption pins the
// construction-time rejection of a feature flag that carries no
// behaviour of its own. Each of the three flags below is documented as
// being activated implicitly by a companion option that supplies the
// configuration the feature runs on; passing the flag alone leaves the
// OP mounting no endpoint and advertising nothing, and an embedder who
// declared the feature has no observable signal that it did not take
// effect. The three MUST fail the same way, and the diagnostic MUST
// name the option that is missing.
func TestFeatureFlag_RejectedWithoutItsConfiguringOption(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		flag       feature.Flag
		wantOption string
	}{
		{"dynamic_registration", feature.DynamicRegistration, "WithDynamicRegistration"},
		{"rar", feature.RAR, "WithAuthorizationDetailTypes"},
		{"grant_management", feature.GrantManagement, "WithGrantManagement"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOpts(t), op.WithFeature(tc.flag))...)
			if err == nil {
				t.Fatalf("op.New accepted feature.%s without %s", tc.flag, tc.wantOption)
			}
			if !op.IsServerError(err) {
				t.Errorf("an unconfigured feature flag must surface as a server configuration error: %v", err)
			}
			desc := configurationDescription(t, err)
			if !strings.Contains(desc, tc.wantOption) {
				t.Errorf("description=%q must name the missing %s", desc, tc.wantOption)
			}
		})
	}
}

// TestFeatureFlag_AcceptedWithItsConfiguringOption is the contrapositive:
// the companion option alone is the supported way to switch these
// features on, so the rejection above must not fire for a deployment
// that wired the feature properly.
func TestFeatureFlag_AcceptedWithItsConfiguringOption(t *testing.T) {
	t.Parallel()

	t.Run("rar", func(t *testing.T) {
		t.Parallel()

		if _, err := op.New(append(validBaseOpts(t),
			op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
				Type:     "payment_initiation",
				Validate: func(context.Context, map[string]any, *store.Client) error { return nil },
			}),
		)...); err != nil {
			t.Fatalf("op.New with WithAuthorizationDetailTypes: %v", err)
		}
	})

	t.Run("grant_management", func(t *testing.T) {
		t.Parallel()

		if _, err := op.New(append(validBaseOpts(t),
			op.WithGrantManagement([]op.GrantManagementAction{op.GrantActionQuery, op.GrantActionRevoke}, false),
		)...); err != nil {
			t.Fatalf("op.New with WithGrantManagement: %v", err)
		}
	})
}
