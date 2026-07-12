package op

// The tests in this file live in package op (not op_test) so they can
// inspect unexported [config] fields the H1-E option layer touches.
// External-package tests in op/options_test.go cover the same surface
// from the embedder's perspective; this file pins the structural
// invariants that would otherwise require routing requests through
// the assembled handler to observe.

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestApplyDefaults_HTMLDriverDefault confirms the plan 005 §3.4
// promise: with neither [WithInteractionDriver] nor [WithSPAUI] supplied
// the OP boots with [interaction.HTMLDriver] as its default driver,
// so an embedder using the default authorization-code grant set with
// the required constructor options (WithIssuer / WithStore / WithKeyset
// / WithCookieKeys) still gets a working HTML login surface.
func TestApplyDefaults_HTMLDriverDefault(t *testing.T) {
	t.Parallel()

	c := &config{}
	c.applyDefaults()
	if _, ok := c.interactionD.(interaction.HTMLDriver); !ok {
		t.Fatalf("default interactionD = %T, want interaction.HTMLDriver", c.interactionD)
	}
}

// TestApplyDefaults_HonoursWithInteractionDriver confirms the explicit
// [WithInteractionDriver] driver wins over the HTMLDriver default. The
// default substitution short-circuits when [config.interactionD] is
// already set so an embedder's custom driver is preserved verbatim.
func TestApplyDefaults_HonoursWithInteractionDriver(t *testing.T) {
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

// TestApplyDefaults_WrapsOverlayWhenConsentOrChooserSet pins the
// overlay wiring contract from plan 016 §3.2.2: when WithConsentUI
// or WithChooserUI is configured (and SPA is not), applyDefaults
// wraps the resolved interaction.Driver with TemplateOverlayDriver
// composed against the HTMLDriver default. With WithSPAUI the
// overlay is NOT composed — SPA mode owns the consent / chooser
// surface via the JSON envelope per ADR 0015 §SPA mode and ADR 0008
// §3.5.
func TestApplyDefaults_WrapsOverlayWhenConsentOrChooserSet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		seed     func(*config)
		wantWrap bool
	}{
		{
			name:     "WithConsentUI only wraps overlay",
			seed:     func(c *config) { c.consentUISet = true; c.consentUI = ConsentUI{} },
			wantWrap: true,
		},
		{
			name:     "WithChooserUI only wraps overlay",
			seed:     func(c *config) { c.chooserUISet = true; c.chooserUI = ChooserUI{} },
			wantWrap: true,
		},
		{
			name:     "WithSPAUI suppresses overlay even when chooser is set",
			seed:     func(c *config) { c.spaUISet = true; c.chooserUISet = true; c.chooserUI = ChooserUI{} },
			wantWrap: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &config{}
			tc.seed(c)
			c.applyDefaults()
			overlay, ok := c.interactionD.(interaction.TemplateOverlayDriver)
			if tc.wantWrap {
				if !ok {
					t.Fatalf("interactionD = %T, want interaction.TemplateOverlayDriver", c.interactionD)
				}
				if _, isHTML := overlay.Inner.(interaction.HTMLDriver); !isHTML {
					t.Errorf("overlay.Inner = %T, want interaction.HTMLDriver", overlay.Inner)
				}
				return
			}
			if ok {
				t.Fatalf("unexpected overlay wrap under SPA mode: %T", c.interactionD)
			}
		})
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

// TestProfileAllowedAuthMethodNames_ExcludesMTLS pins that the helper's
// documented contract — the wire list excludes the RFC 8705 mTLS methods
// the runtime cannot enforce — matches its behaviour. A FAPI 2.0 profile
// allows private_key_jwt plus the two mTLS methods; the helper must keep
// private_key_jwt and drop both mTLS names so every consumer (discovery
// advertisement and the static-client auth-method gate) inherits the
// exclusion.
func TestProfileAllowedAuthMethodNames_ExcludesMTLS(t *testing.T) {
	t.Parallel()

	c := &config{profiles: []profile.Profile{profile.FAPI2Baseline}}
	got := c.profileAllowedAuthMethodNames()

	for _, name := range got {
		if m := AuthMethod(name); m == AuthTLSClientAuth || m == AuthSelfSignedTLSClientAuth {
			t.Fatalf("profileAllowedAuthMethodNames returned mTLS method %q; doc promises exclusion", name)
		}
	}
	if !containsString(got, string(AuthPrivateKeyJWT)) {
		t.Fatalf("profileAllowedAuthMethodNames=%v, want it to retain private_key_jwt", got)
	}
}

// TestEffectiveDeviceCodeExpiry_DefaultsAndOverride pins the H1
// resolution contract for the device_code TTL knob: a zero-value
// [config.deviceCodeExpiry] resolves to [devicecode.DefaultExpiresIn]
// and an embedder-supplied value via [WithDeviceCodeExpiry] wins.
// The knob is deliberately independent of [config.accessTokenTTL].
func TestEffectiveDeviceCodeExpiry_DefaultsAndOverride(t *testing.T) {
	t.Parallel()

	c := &config{}
	if got, want := c.effectiveDeviceCodeExpiry(), devicecode.DefaultExpiresIn; got != want {
		t.Fatalf("effectiveDeviceCodeExpiry() = %v, want default %v", got, want)
	}

	c.deviceCodeExpiry = 20 * time.Minute
	if got, want := c.effectiveDeviceCodeExpiry(), 20*time.Minute; got != want {
		t.Fatalf("effectiveDeviceCodeExpiry() = %v, want override %v", got, want)
	}
}

// TestEffectiveDeviceCodePollInterval_DefaultsAndOverride mirrors
// [TestEffectiveDeviceCodeExpiry_DefaultsAndOverride] for the
// advertised poll `interval`.
func TestEffectiveDeviceCodePollInterval_DefaultsAndOverride(t *testing.T) {
	t.Parallel()

	c := &config{}
	if got, want := c.effectiveDeviceCodePollInterval(), devicecode.DefaultInterval; got != want {
		t.Fatalf("effectiveDeviceCodePollInterval() = %v, want default %v", got, want)
	}

	c.deviceCodePollInterval = 15 * time.Second
	if got, want := c.effectiveDeviceCodePollInterval(), 15*time.Second; got != want {
		t.Fatalf("effectiveDeviceCodePollInterval() = %v, want override %v", got, want)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
