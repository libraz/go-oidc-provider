package op

// The tests in this file live in package op (not op_test) so they can
// inspect unexported [config] fields the H1-E option layer touches.
// External-package tests in op/options_test.go cover the same surface
// from the embedder's perspective; this file pins the structural
// invariants that would otherwise require routing requests through
// the assembled handler to observe.

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestApplyDefaults_HTMLDriverDefault confirms the plan 005 §3.4
// promise: with neither [WithInteraction] nor [WithSPAUI] supplied
// the OP boots with [interaction.HTMLDriver] as its default driver,
// so an embedder who calls only the four required options
// (WithIssuer / WithStore / WithKeyset / WithCookieKey) still gets a
// working HTML login surface.
func TestApplyDefaults_HTMLDriverDefault(t *testing.T) {
	t.Parallel()

	c := &config{}
	c.applyDefaults()
	if _, ok := c.interactionD.(interaction.HTMLDriver); !ok {
		t.Fatalf("default interactionD = %T, want interaction.HTMLDriver", c.interactionD)
	}
}

// TestApplyDefaults_HonoursWithInteraction confirms the explicit
// [WithInteraction] driver wins over the HTMLDriver default. The
// default substitution short-circuits when [config.interactionD] is
// already set so an embedder's custom driver is preserved verbatim.
func TestApplyDefaults_HonoursWithInteraction(t *testing.T) {
	t.Parallel()

	custom := interaction.JSONDriver{}
	c := &config{interactionD: custom}
	c.applyDefaults()
	if _, ok := c.interactionD.(interaction.JSONDriver); !ok {
		t.Fatalf("explicit driver replaced by default: %T", c.interactionD)
	}
}

// TestApplyDefaults_SPAUISuppressesDefaultDriver pins the §3.4
// boundary: when [WithSPAUI] is configured the default-driver
// fallback short-circuits because the embedder's SPA owns rendering
// and the OP only needs to serve JSON state endpoints. The handler's
// own nil-driver fallback (in internal/authorizeendpoint) takes over
// at request time.
func TestApplyDefaults_SPAUISuppressesDefaultDriver(t *testing.T) {
	t.Parallel()

	c := &config{spaUISet: true}
	c.applyDefaults()
	if c.interactionD != nil {
		t.Fatalf("with WithSPAUI active, default driver was set to %T; want nil", c.interactionD)
	}
}

// TestWithStaticClients_StoresSeededClients pins the H1-E aggregate
// behaviour: every seed projected through [ClientSeed.seed] is
// appended to [config.staticClients] in the order seeds appear. The
// orchestrator wiring that consumes the slice is staged for H1-D;
// this test guards the option-side contract so the H1-D commit can
// rely on the slice shape without re-deriving it.
func TestWithStaticClients_StoresSeededClients(t *testing.T) {
	t.Parallel()

	opt := WithStaticClients(
		PublicClient{
			ID:           "spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		},
		PublicClient{
			ID:           "spa-2",
			RedirectURIs: []string{"https://app2.example.com/cb"},
			Scopes:       []string{"openid"},
		},
	)
	c := &config{}
	if err := opt.apply(c); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(c.staticClients) != 2 {
		t.Fatalf("staticClients length = %d, want 2", len(c.staticClients))
	}
	if c.staticClients[0].ID != "spa" || c.staticClients[1].ID != "spa-2" {
		t.Errorf("staticClients order corrupted: %+v", c.staticClients)
	}
}

// TestWithProfile_AutoEnableIdempotent verifies the §3.6 contract
// from the unexported side: layered [WithFeature] + [WithProfile]
// combinations never produce a duplicate flag in [config.features].
func TestWithProfile_AutoEnableIdempotent(t *testing.T) {
	t.Parallel()

	c := &config{}
	if err := WithFeature(feature.PAR).apply(c); err != nil {
		t.Fatalf("WithFeature(PAR): %v", err)
	}
	if err := WithProfile(profile.FAPI2Baseline).apply(c); err != nil {
		t.Fatalf("WithProfile(FAPI2Baseline): %v", err)
	}
	count := 0
	for _, f := range c.features {
		if f == feature.PAR {
			count++
		}
	}
	if count != 1 {
		t.Errorf("PAR flag count = %d, want 1 (auto-enable must be idempotent)", count)
	}
}

// TestWithProfile_AutoEnablePopulatesRequiredFeatures pins the
// post-condition: after a single [WithProfile] call every flag in
// [profile.RequiredFeatures] for the active profile appears in
// [config.features]. This guards the auto-enable side of the §3.6
// contract independently of the idempotence test above.
func TestWithProfile_AutoEnablePopulatesRequiredFeatures(t *testing.T) {
	t.Parallel()

	c := &config{}
	if err := WithProfile(profile.FAPI2Baseline).apply(c); err != nil {
		t.Fatalf("WithProfile: %v", err)
	}
	for _, want := range profile.RequiredFeatures(profile.FAPI2Baseline) {
		if !featureEnabled(c.features, want) {
			t.Errorf("required feature %s not auto-enabled", want)
		}
	}
}
