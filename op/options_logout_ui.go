package op

import (
	"bytes"
	"html/template"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// LogoutUI declares the templates the [Provider] uses to render the two
// pages of RP-Initiated Logout: the confirmation page shown when a
// request arrives without proof of the user's intent, and the signed-out
// page shown when the request carried no post_logout_redirect_uri. Both
// are rendered by the server whichever [UI] [WithUI] selects, [SPAUI]
// included.
//
// The confirmation template is executed with
// [interaction.LogoutConfirmTemplateData] and MUST render every entry of
// its Fields as a hidden input in a form that submits to SubmitAction with
// SubmitMethod; [WithLogoutUI] rejects a template that does not. The
// signed-out template is executed with
// [interaction.LogoutSignedOutTemplateData]. The error page is not
// templated.
//
// Stable since v1.5.
type LogoutUI struct {
	// ConfirmTemplate renders the confirmation page. MUST be non-nil.
	ConfirmTemplate *template.Template

	// SignedOutTemplate renders the signed-out page. MUST be non-nil;
	// both pages are templated together so a sign-out never changes
	// appearance halfway through.
	SignedOutTemplate *template.Template

	// ContentSecurityPolicy is the policy sent with both pages. Empty
	// keeps the library default, which forbids every subresource:
	//
	//	default-src 'none'; frame-ancestors 'none'; base-uri 'none'; sandbox allow-forms allow-same-origin
	//
	// A declared policy replaces the whole header, the default's sandbox
	// directive included. Keeping `sandbox allow-forms allow-same-origin`
	// (or dropping it) is the declaring side's decision; without
	// allow-forms the confirmation form cannot submit. Declare the
	// origins the templates load from, e.g.
	// "default-src 'none'; style-src 'self'; img-src 'self' data:; sandbox allow-forms allow-same-origin".
	//
	// [interaction.NormalizeCSP] validates the value at [New] and
	// documents which directives are not the embedder's to relax.
	ContentSecurityPolicy string
}

// WithLogoutUI registers the [LogoutUI] templates for the
// RP-Initiated Logout pages. Applies whichever [UI] [WithUI] selects.
// Validation:
//   - ConfirmTemplate and SignedOutTemplate MUST be non-nil.
//   - ContentSecurityPolicy, when set, MUST pass
//     [interaction.NormalizeCSP].
//   - ConfirmTemplate is executed once against sample data and MUST emit
//     every [interaction.LogoutConfirmTemplateData.Fields] value; a
//     template that omits {{range .Fields}} would otherwise fail every
//     confirmation at request time.
//   - Repeated [WithLogoutUI] calls are rejected.
//
// The Referrer-Policy of these pages stays same-origin and is not
// configurable: the confirmation POST depends on a same-origin Origin.
//
// Stable since v1.5.
func WithLogoutUI(ui LogoutUI) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithLogoutUI"); err != nil {
			return err
		}
		if ui.ConfirmTemplate == nil {
			return newConfigurationError("WithLogoutUI: ConfirmTemplate must not be nil", nil)
		}
		if ui.SignedOutTemplate == nil {
			return newConfigurationError("WithLogoutUI: SignedOutTemplate must not be nil", nil)
		}
		// Empty stays empty: the end-session pages then keep their own
		// default policy, which differs from the interaction default.
		policy := ui.ContentSecurityPolicy
		if policy != "" {
			normalized, err := normalizeUICSP("WithLogoutUI", policy)
			if err != nil {
				return err
			}
			policy = normalized
		}
		if err := checkLogoutConfirmFields(ui.ConfirmTemplate); err != nil {
			return err
		}
		c.logoutUI = ui
		c.logoutUI.ContentSecurityPolicy = policy
		return nil
	})
}

// checkLogoutConfirmFields executes tpl against sentinel hidden-field
// values and reports a configuration error unless every sentinel appears
// in the output.
func checkLogoutConfirmFields(tpl *template.Template) error {
	const count = 3
	fields := make([]interaction.HiddenField, count)
	for i := range fields {
		n := strconv.Itoa(i)
		fields[i] = interaction.HiddenField{
			Name:  "sentinel_field_" + n,
			Value: "logout-ui-sentinel-value-" + n,
		}
	}
	var out bytes.Buffer
	err := tpl.Execute(&out, interaction.LogoutConfirmTemplateData{
		Locale:       "en",
		Title:        "Title",
		Body:         "Body",
		Button:       "Button",
		SubmitMethod: "POST",
		SubmitAction: "./end_session",
		ClientName:   "Client",
		Fields:       fields,
	})
	if err != nil {
		return newConfigurationError("WithLogoutUI: ConfirmTemplate failed to execute", err)
	}
	for _, f := range fields {
		if !strings.Contains(out.String(), f.Value) {
			return newConfigurationError("WithLogoutUI: ConfirmTemplate must render every entry of Fields as a hidden input", nil)
		}
	}
	return nil
}
