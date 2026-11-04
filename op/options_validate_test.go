package op_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestNew_ReportsEveryMissingRequiredOption pins the existence stage: with
// no options at all, the default authorization_code grant owes cookie keys
// and a login flow on top of issuer, store and keyset, and one op.New call
// reports all five.
func TestNew_ReportsEveryMissingRequiredOption(t *testing.T) {
	t.Parallel()

	_, err := op.New()
	if err == nil {
		t.Fatal("op.New() with no options returned nil")
	}
	for name, want := range map[string]error{
		"issuer":      op.ErrIssuerRequired,
		"store":       op.ErrStoreRequired,
		"keyset":      op.ErrKeysetRequired,
		"cookie keys": op.ErrCookieKeysRequired,
		"login flow":  op.ErrLoginFlowRequired,
	} {
		if !errors.Is(err, want) {
			t.Errorf("err does not report the missing %s: %v", name, err)
		}
	}
}

// TestNew_SingleMissingReturnsBareSentinel pins that one missing item is
// returned as itself rather than wrapped in a join, so a direct comparison
// keeps working and the message stays a single line.
func TestNew_SingleMissingReturnsBareSentinel(t *testing.T) {
	t.Parallel()

	_, err := op.New(op.WithDefaults(
		op.WithStore(stubStore{}),
		op.WithUserStore(stubUserStore{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
	), fixtureAuthenticator())
	if err != op.ErrIssuerRequired { //nolint:errorlint // asserting the bare sentinel is the point
		t.Fatalf("err = %v, want the bare ErrIssuerRequired", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("single missing option produced a multi-line message: %q", err.Error())
	}
}

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
			op.WithGrantManagement(op.GrantManagement{Actions: []op.GrantManagementAction{op.GrantActionQuery, op.GrantActionRevoke}}),
		)...); err != nil {
			t.Fatalf("op.New with WithGrantManagement: %v", err)
		}
	})
}

// TestWithGrantManagement_RejectsDouble pins the once-only contract the
// sibling WithGrants / WithProfile options share: a second call must not
// silently replace the first action set and actionRequired flag.
func TestWithGrantManagement_RejectsDouble(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrantManagement(op.GrantManagement{Actions: []op.GrantManagementAction{op.GrantActionQuery}, ActionRequired: true}),
		op.WithGrantManagement(op.GrantManagement{Actions: []op.GrantManagementAction{op.GrantActionRevoke}}),
	)...)
	if err == nil {
		t.Fatal("expected error for two WithGrantManagement calls, got nil")
	}
	if !strings.Contains(err.Error(), "at most once") {
		t.Errorf("err = %v, want at-most-once diagnostic", err)
	}
}
