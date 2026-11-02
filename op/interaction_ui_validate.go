package op

import "github.com/libraz/go-oidc-provider/op/interaction"

// validateSPAUIDriver rejects [WithSPAUI] combined with a bundled HTML
// driver. Under WithSPAUI the configured driver renders every prompt the
// SPA fetches from <LoginMount>/state/{uid}, so an HTML driver would hand
// the SPA markup instead of the JSON prompt envelope.
func (c *config) validateSPAUIDriver() error {
	if !c.spaUISet || !isBundledHTMLDriver(c.interactionD) {
		return nil
	}
	return newConfigurationError(
		"WithSPAUI is combined with a bundled HTML interaction driver "+
			"(interaction.HTMLDriver or interaction.TemplateOverlayDriver), so the SPA "+
			"would receive HTML instead of the JSON prompt envelope; drop "+
			"WithInteractionDriver, or use a driver that emits the JSON prompt envelope",
		nil,
	)
}

// isBundledHTMLDriver reports whether d is [interaction.HTMLDriver] or
// [interaction.TemplateOverlayDriver], by value or pointer.
func isBundledHTMLDriver(d interaction.Driver) bool {
	switch v := d.(type) {
	case interaction.HTMLDriver, interaction.TemplateOverlayDriver:
		return true
	case *interaction.HTMLDriver:
		return v != nil
	case *interaction.TemplateOverlayDriver:
		return v != nil
	default:
		return false
	}
}

// validateInteractionUICapabilities rejects a login flow whose factors
// the configured interaction driver cannot render.
//
// A passkey step carries the assertion the browser's WebAuthn call
// produces. That call is script and the built-in HTML driver ships none,
// so no user could ever complete the step. A driver the library did not
// write is assumed capable; see [rendersWithoutScript].
func (c *config) validateInteractionUICapabilities() error {
	if c.passkeyScheduled() && rendersWithoutScript(c.interactionD) {
		return newConfigurationError(
			"a passkey step is configured but the interaction UI is the "+
				"built-in HTML driver, which renders no client-side script and "+
				"cannot run a WebAuthn ceremony; configure WithSPAUI or "+
				"WithInteractionDriver with a UI that runs the ceremony",
			nil,
		)
	}
	return nil
}
