package op

import "github.com/libraz/go-oidc-provider/internal/authn"

// CaptchaInput is an alias for [authn.CaptchaInput].
type CaptchaInput = authn.CaptchaInput

// CaptchaVerifier is an alias for [authn.CaptchaVerifier].
type CaptchaVerifier = authn.CaptchaVerifier

// CaptchaWidgetDescriber is an alias for
// [authn.CaptchaWidgetDescriber]. A [CaptchaVerifier] that also
// implements it populates [interaction.CaptchaPromptData] on every
// captcha prompt the OP emits, which is what lets an SPA bootstrap the
// upstream provider's challenge widget. Implementing it is optional:
// a verifier that does not describe a widget emits a prompt with the
// provider and site key empty.
type CaptchaWidgetDescriber = authn.CaptchaWidgetDescriber
