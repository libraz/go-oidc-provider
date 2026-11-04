package op

// The tests in this file live in package op (not op_test) so they can
// inspect unexported [config] fields the option layer touches.
// External-package tests in op/options_test.go cover the same surface
// from the embedder's perspective; this file pins the structural
// invariants that would otherwise require routing requests through
// the assembled handler to observe.

import (
	"html/template"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestApplyDefaults_HTMLDriverDefault confirms the default-driver
// contract: without [WithUI] the OP boots with [interaction.HTMLDriver]
// as its default driver, so an embedder using the default
// authorization-code grant set with the required constructor options
// (WithIssuer / WithStore / WithKeyset / WithCookieKeys) still gets a
// working HTML login surface.
func TestApplyDefaults_HTMLDriverDefault(t *testing.T) {
	t.Parallel()

	c := &config{}
	c.applyDefaults()
	if _, ok := c.interactionD.(interaction.HTMLDriver); !ok {
		t.Fatalf("default interactionD = %T, want interaction.HTMLDriver", c.interactionD)
	}
}

// TestApplyDefaults_HonoursWithUIDriver confirms an explicit
// [DriverUI] driver wins over the HTMLDriver default and is preserved
// verbatim.
func TestApplyDefaults_HonoursWithUIDriver(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{WithUI(DriverUI{Driver: interaction.JSONDriver{}})})
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if _, ok := c.interactionD.(interaction.JSONDriver); !ok {
		t.Fatalf("explicit driver replaced by default: %T", c.interactionD)
	}
}

// TestApplyDefaults_SPAUISuppressesDefaultDriver pins the §3.4
// boundary: when [SPAUI] is configured the resolved driver stays nil
// because the embedder's SPA owns rendering and the OP only needs to
// serve JSON state endpoints. The handler's own nil-driver fallback (in
// internal/authorizeendpoint) takes over at request time.
func TestApplyDefaults_SPAUISuppressesDefaultDriver(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{WithUI(SPAUI{LoginMount: "/login"})})
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if c.interactionD != nil {
		t.Fatalf("with SPAUI active, default driver was set to %T; want nil", c.interactionD)
	}
}

// TestApplyDefaults_WrapsOverlayWhenAPageTemplateIsSet pins the overlay
// wiring contract: an [HTMLUI] with at least one templated page resolves
// to a TemplateOverlayDriver composed over the HTMLDriver; an HTMLUI with
// no template keeps the bare HTMLDriver.
func TestApplyDefaults_WrapsOverlayWhenAPageTemplateIsSet(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("p").Parse("ok"))
	cases := []struct {
		name     string
		ui       UI
		wantWrap bool
	}{
		{"consent template wraps overlay", HTMLUI{Consent: PageTemplate{Template: tmpl}}, true},
		{"chooser template wraps overlay", HTMLUI{Chooser: PageTemplate{Template: tmpl}}, true},
		{"login template wraps overlay", HTMLUI{Login: PageTemplate{Template: tmpl}}, true},
		{"no template keeps the bare driver", HTMLUI{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := newConfig([]Option{WithUI(tc.ui)})
			if err != nil {
				t.Fatalf("newConfig: %v", err)
			}
			overlay, ok := c.interactionD.(interaction.TemplateOverlayDriver)
			if !tc.wantWrap {
				if ok {
					t.Fatalf("unexpected overlay wrap: %T", c.interactionD)
				}
				return
			}
			if !ok {
				t.Fatalf("interactionD = %T, want interaction.TemplateOverlayDriver", c.interactionD)
			}
			if _, isHTML := overlay.Inner.(interaction.HTMLDriver); !isHTML {
				t.Errorf("overlay.Inner = %T, want interaction.HTMLDriver", overlay.Inner)
			}
		})
	}
}

// TestApplyDefaults_ComposedDriverKeepsErrorRenderer pins the property
// that survives the composition: the driver applyDefaults installs must
// still be able to render a terminal authorization error. The wrapping
// happens because of a branding template, and the error path is the one
// nothing exercises during a successful login, so a wrapper that lost
// the capability would ship as "the consent page looks right" while
// every pre-redirect failure fell back to a raw JSON envelope in the
// user's browser.
func TestApplyDefaults_ComposedDriverKeepsErrorRenderer(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("p").Parse("ok"))
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"default driver", nil},
		{"with consent template", []Option{WithUI(HTMLUI{Consent: PageTemplate{Template: tmpl}})}},
		{"with chooser template", []Option{WithUI(HTMLUI{Chooser: PageTemplate{Template: tmpl}})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := newConfig(tc.opts)
			if err != nil {
				t.Fatalf("newConfig: %v", err)
			}
			if _, ok := c.interactionD.(interaction.ErrorRenderer); !ok {
				t.Fatalf("composed driver %T does not satisfy interaction.ErrorRenderer", c.interactionD)
			}
		})
	}
}

// The per-template Content-Security-Policy is validated at the option
// site and consumed by the overlay driver, so the resolved mode is the
// only place the two halves meet. A policy that stops here renders the
// option inert: the page still loads, the browser still drops the
// assets, and nothing reports it.
func TestApplyDefaults_CarriesTemplatePoliciesIntoTheOverlay(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("p").Parse("ok"))
	const consentCSP = "default-src 'none'; img-src https://consent.example"
	const chooserCSP = "default-src 'none'; img-src https://chooser.example"
	c, err := newConfig([]Option{WithUI(HTMLUI{
		Consent: PageTemplate{Template: tmpl, ContentSecurityPolicy: consentCSP},
		Chooser: PageTemplate{Template: tmpl, ContentSecurityPolicy: chooserCSP},
	})})
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	overlay, ok := c.interactionD.(interaction.TemplateOverlayDriver)
	if !ok {
		t.Fatalf("interactionD = %T, want interaction.TemplateOverlayDriver", c.interactionD)
	}
	// WithUI stores the normalized policy, as the per-page options did.
	for _, tc := range []struct{ name, got, declared string }{
		{"ConsentCSP", overlay.ConsentCSP, consentCSP},
		{"ChooserCSP", overlay.ChooserCSP, chooserCSP},
	} {
		want, err := interaction.NormalizeCSP(tc.declared)
		if err != nil {
			t.Fatalf("NormalizeCSP(%q): %v", tc.declared, err)
		}
		if tc.got != want {
			t.Errorf("overlay.%s = %q, want %q", tc.name, tc.got, want)
		}
	}
}

// TestWithStaticClients_StoresSeededClients pins the aggregate
// behaviour: every seed projected through [ClientSeed.seed] is
// appended to [config.staticClients] in the order seeds appear. The
// test guards the option-side contract on its own, so the wiring that
// consumes the slice can rely on its shape without re-deriving it.
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

// TestProfileAllowedAuthMethodNames_MTLSFollowsTheFeature pins that a
// FAPI 2.0 profile's mTLS methods reach every consumer of the list
// (discovery and the static-client gate) only with feature.MTLS, and that
// private_key_jwt is kept either way.
func TestProfileAllowedAuthMethodNames_MTLSFollowsTheFeature(t *testing.T) {
	t.Parallel()

	for _, mtlsOn := range []bool{false, true} {
		c := &config{profiles: []profile.Profile{profile.FAPI2Baseline}}
		if mtlsOn {
			c.features = []feature.Flag{feature.MTLS}
		}
		got := c.profileAllowedAuthMethodNames()
		for _, m := range []AuthMethod{AuthTLSClientAuth, AuthSelfSignedTLSClientAuth} {
			if containsString(got, string(m)) != mtlsOn {
				t.Fatalf("mTLS=%v: profileAllowedAuthMethodNames=%v, %q present=%v", mtlsOn, got, m, !mtlsOn)
			}
		}
		if !containsString(got, string(AuthPrivateKeyJWT)) {
			t.Fatalf("mTLS=%v: profileAllowedAuthMethodNames=%v, want it to retain private_key_jwt", mtlsOn, got)
		}
	}
}

// TestEffectiveDeviceCodeExpiry_DefaultsAndOverride pins the H1
// resolution contract for the device_code TTL knob: a zero-value
// [config.deviceCodeExpiry] resolves to [devicecode.DefaultExpiresIn]
// and an embedder-supplied value via [DeviceCodeGrant.TTL] wins.
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

// TestEffectiveCIBADefaultExpiresIn_ClampedByMax pins that a configured cap
// also bounds the lifetime applied when the client omits requested_expiry.
// Without the clamp an operator who lowers only the cap still hands out
// library-default auth_req_ids that outlive the maximum they advertised.
func TestEffectiveCIBADefaultExpiresIn_ClampedByMax(t *testing.T) {
	t.Parallel()

	c := &config{}
	if got, want := c.effectiveCIBADefaultExpiresIn(), ciba.DefaultExpiresIn; got != want {
		t.Fatalf("effectiveCIBADefaultExpiresIn() = %v, want default %v", got, want)
	}

	c.cibaMaxExpiresIn = 90 * time.Second
	if got, want := c.effectiveCIBADefaultExpiresIn(), 90*time.Second; got != want {
		t.Fatalf("effectiveCIBADefaultExpiresIn() = %v, want clamped %v", got, want)
	}

	c.cibaDefaultExpiresIn = 30 * time.Second
	if got, want := c.effectiveCIBADefaultExpiresIn(), 30*time.Second; got != want {
		t.Fatalf("effectiveCIBADefaultExpiresIn() = %v, want override %v", got, want)
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
