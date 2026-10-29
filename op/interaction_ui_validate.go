package op

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
