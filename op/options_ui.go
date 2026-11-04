package op

import (
	"html/template"
	"os"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// WithUI selects how the OP renders the interaction prompts — sign-in,
// consent and the account chooser. Pass one of [HTMLUI], [SPAUI] or
// [DriverUI]; exactly one mode is active, so there is no combination of
// UI options to reconcile. Without WithUI the OP renders its built-in
// HTML pages, exactly as HTMLUI{} does.
//
// The RP-Initiated Logout pages are not part of the mode: they are
// server-rendered in every mode and restyled through [WithLogoutUI].
// Non-factor prompts registered through [WithInteractions] render
// through whichever mode is selected.
//
// Validation runs at the option site, so a misconfigured value fails
// [New]; each variant documents its own rules. A second WithUI fails
// [New], unless one of the two is wrapped in [WithDefaults], in which
// case the explicit one wins and the default is not validated. Setting
// WithUI outside [WithDefaults] while [WithGrants] leaves out
// authorization_code fails [New] with [ErrAuthorizationCodeGrantRequired].
//
// Stable since v1.5.
func WithUI(ui UI) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithUI"); err != nil {
			return err
		}
		if nilcheck.IsNil(ui) {
			return newConfigurationError("WithUI received nil UI", nil)
		}
		mode, err := ui.ui()
		if err != nil {
			return err
		}
		c.ui = mode
		c.uiSet = true
		c.recordBrowserSurface("WithUI")
		return nil
	})
}

// UI selects how the OP renders the interaction prompts — sign-in,
// consent and the account chooser. Exactly one is active; without
// [WithUI] the OP renders its built-in HTML pages, as [HTMLUI]{} does.
//
// The implementations are [HTMLUI], [SPAUI] and [DriverUI]. The single
// method is unexported, so the set is closed; a type that embeds one of
// the three resolves as the embedded variant.
//
// Stable since v1.5.
type UI interface {
	ui() (uiMode, error)
}

// HTMLUI renders the built-in HTML pages. A page whose [PageTemplate]
// has a nil Template keeps the built-in markup, so one page can be
// replaced alone and HTMLUI{} is the built-in surface unchanged.
//
// A page template is meaningful only over the built-in HTML driver. To
// lay templates over a driver of your own, or over an
// [interaction.HTMLDriver] carrying its own translator, pass an
// [interaction.TemplateOverlayDriver] with that driver as Inner to
// [DriverUI].
//
// Validation:
//   - A PageTemplate that sets ContentSecurityPolicy without a Template
//     fails [New].
//   - A ContentSecurityPolicy on a templated page MUST pass
//     [interaction.NormalizeCSP].
//
// Embedders SHOULD construct HTMLUI with named field initialisation so
// pages added in a minor release remain source-compatible.
//
// Stable since v1.5.
type HTMLUI struct {
	// Login replaces every sign-in prompt except consent, the account
	// chooser and passkey: password, TOTP, email OTP, recovery code,
	// factor choice, captcha, custom [Step] prompts and [WithInteractions]
	// prompts. One template serves all of them; branch on the prompt type.
	//
	// The template receives [interaction.LoginTemplateData] and MUST:
	//   - (a) echo StateRef and CSRFToken as hidden fields named
	//     [interaction.StateRefField] and [interaction.CSRFTokenField]; a form
	//     that drops either is refused on submission (fail-closed);
	//   - (b) guard Data with {{with .Data}} or a branch on .Type: Data is nil
	//     for a custom Step and for [WithInteractions] prompts;
	//   - (c) for the factor-choice prompt, submit the chosen option's Kind
	//     under .FactorField, listing .Data.Options.
	//
	// Also note:
	//   - (d) the CSP applies to every login prompt. Loosening script-src for a
	//     captcha widget loosens the password and TOTP pages too: name hosts
	//     only, never 'unsafe-inline'.
	//   - (e) the template is laid over the built-in HTML driver. To lay it
	//     over a driver of your own, pass an [interaction.TemplateOverlayDriver]
	//     with that driver as Inner to [DriverUI].
	//   - (f) passkey prompts and error pages are not templated and stay with
	//     the underlying driver.
	Login PageTemplate

	// Consent replaces the consent screen. The template receives
	// [interaction.ConsentTemplateData]: the client metadata, the scope
	// list and the CSRF token.
	Consent PageTemplate

	// Chooser replaces the account chooser shown when prompt=select_account
	// fires for a session that already has a chooser group. The template
	// receives [interaction.ChooserTemplateData]: the accounts, the
	// add-account URL and the CSRF token.
	Chooser PageTemplate
}

// PageTemplate replaces one built-in page with an embedder template. It
// is a field of [HTMLUI]; a nil Template keeps the built-in page.
//
// Stable since v1.5.
type PageTemplate struct {
	// Template is the [html/template.Template] the page renders. Nil
	// keeps the built-in markup for that page.
	Template *template.Template

	// ContentSecurityPolicy is the policy sent with the rendered page.
	// Empty keeps the library default, which forbids every subresource:
	// correct for the markup the built-in driver emits, but it silently
	// drops the stylesheet, logo or webfont a branded template loads —
	// the browser blocks them and the OP never sees a failure. Declare
	// the origins the template uses, e.g.
	// "default-src 'none'; style-src 'self'; img-src 'self' data:".
	// Each page declares its own policy because the pages are independent
	// templates that need not load from the same origins.
	//
	// [interaction.NormalizeCSP] validates the value at [New] and
	// documents which directives are not the embedder's to relax. Setting
	// it without a Template fails [New].
	ContentSecurityPolicy string
}

// SPAUI hands the prompts to a single-page application through the JSON
// state endpoint. It declares the SPA-shell mount point and optional
// asset root the [Provider] should expose so the embedder's React (or
// framework-neutral SPA) frontend can drive the login / consent flows.
// [WithUI] translates LoginMount into the shell, JSON state, and asset
// routes; no HTML driver is installed, and every prompt is served as
// [interaction.JSONDriver] renders it. The scope is deliberately limited to
// login / consent: the RP-Initiated Logout pages are rendered by the
// server (restyle them with [WithLogoutUI]), and front-channel logout
// and session management iframes are out of scope, so [SPAUI] does not
// carry mounts for those surfaces.
// Embedders SHOULD construct [SPAUI] with named field initialisation so optional fields
// added in a minor release remain source-compatible.
//
// The front end is fully replaceable, so the wire contract it has to
// implement is part of this type's surface rather than a property of
// the bundle shipped with the examples: the prompt envelope, the two
// terminal envelopes the front end delivers to the client itself, and
// the rule that a non-200 body may not be JSON at all are documented
// under "State-route contract" below.
//
// Validation:
//   - LoginMount MUST be non-empty and MUST start with "/".
//   - StaticDir MAY be empty; when set the directory MUST exist at
//     construction time (an [os.Stat] check) so a typo fails [New]
//     rather than the first request.
//   - ContentSecurityPolicy, when set, MUST pass [interaction.NormalizeCSP].
//
// Stable since v1.5.
//
// # State-route contract
//
// The front end drives the ceremony against LoginMount/state/{uid} —
// GET to read the current prompt, POST to submit a reply, DELETE to
// cancel — and MUST branch on the HTTP status before it parses a body:
//
//   - 200: a JSON object, either the next prompt or a terminal
//     envelope. Its "type" member tells the two apart.
//   - 204: the interaction was cancelled and the request carried no
//     redirect_uri, so there is nothing to deliver to the client.
//   - anything else: the ceremony cannot continue. The body is
//     normally the JSON error envelope ({"error", "error_description"}),
//     but it is not guaranteed to be JSON: a response the OP cannot
//     produce safely — a JARM envelope it failed to sign, say — fails
//     closed as text/plain carrying no protocol fields at all, because
//     the alternative is emitting a weaker response shape than the
//     client contracted for. A front end that parses before it checks
//     the status raises on those instead of reporting them.
//
// A 200 whose "type" is one of the two terminal values below is the
// authorization response itself, and the front end is what delivers it
// to the client: both arrive on the state route precisely because a
// fetch() can neither follow a cross-origin redirect nor execute an
// HTML document, so the OP cannot deliver either one through its own
// response.
//
//	{"type":"redirect","location":"<url>"}
//
// Navigate the document to location (window.location.href). This is the
// terminal for response_mode=query and for the JARM query.jwt /
// fragment.jwt modes.
//
//	{"type":"form_post","action":"<redirect_uri>","fields":{"<name>":"<value>"}}
//
// Build a form with method="post" and the given action, add one hidden
// input per fields entry, and submit it at document level. This is the
// terminal for response_mode=form_post — fields carries code / state /
// iss on success and error / error_description / state on failure — and
// for the JARM form_post.jwt mode, where fields carries a single
// "response" JWT. Submitting it is exactly what the page the OP renders
// on the non-SPA surface auto-submits; a front end that skips it strands
// the flow with the client never receiving a response.
//
// Any other "type" is the next prompt ([interaction.Prompt]): render it
// and POST the reply. "redirect" and "form_post" are reserved for the
// terminals, so a custom prompt MUST NOT take either name — the
// [interaction.Prompt] namespace rule, which requires an org-prefixed
// dotted name, already keeps them apart.
type SPAUI struct {
	// LoginMount is the URL path the SPA's login entry HTML lives
	// under (typically "/login"). MUST be non-empty and MUST start
	// with "/"; an empty value rejects [WithUI] at the option
	// site so the misconfiguration surfaces at construction time.
	LoginMount string

	// StaticDir is the on-disk directory the [Provider] serves
	// the SPA's static assets from. Empty means the embedder
	// hosts the assets behind a reverse proxy; when set the path
	// MUST exist at construction time so a typo surfaces at
	// [New] rather than the first request.
	StaticDir string

	// ContentSecurityPolicy is the policy sent with the SPA shell
	// (LoginMount/{uid}); asset responses carry none. Empty means the
	// default policy:
	//
	//	default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
	//
	// A bundle that needs inline scripts, external origins or a <base>
	// element MUST supply its own value. A non-empty value replaces the
	// default and is validated with [interaction.NormalizeCSP], the same
	// rules as [PageTemplate.ContentSecurityPolicy]; a rejected value fails
	// [New].
	ContentSecurityPolicy string
}

// DriverUI renders the prompts through an embedder [interaction.Driver]:
// a server-side renderer, a framework-specific driver, or a JSON driver
// behind an external front end.
//
// The bundled drivers are accepted too. Pass an
// [interaction.TemplateOverlayDriver] to lay [HTMLUI]-style page templates
// over a driver of your own, or over an [interaction.HTMLDriver] that
// carries its own translator; [WithUI] then checks the overlay exactly as
// it checks [HTMLUI].
//
// Validation:
//   - Driver MUST be non-nil, including a typed nil.
//   - A [interaction.TemplateOverlayDriver] (value or pointer) MUST have a
//     non-nil Inner, and its ConsentCSP, ChooserCSP and LoginCSP MUST pass
//     [interaction.NormalizeCSP].
//
// Stable since v1.5.
type DriverUI struct {
	// Driver renders every prompt and parses every submission.
	Driver interaction.Driver
}

// spaDefaultCSP is the shell policy applied when
// [SPAUI.ContentSecurityPolicy] is empty.
const spaDefaultCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

// uiMode is the resolved [UI]: the driver the authorize endpoint renders
// through, and the SPA wiring when the mode is [SPAUI].
type uiMode struct {
	// driver is nil only for SPAUI; the authorize endpoint then falls
	// back to [interaction.JSONDriver].
	driver interaction.Driver

	// spa is non-nil only for SPAUI.
	spa *spaWiring
}

// spaWiring carries the validated [SPAUI] fields; csp is already
// normalized or defaulted to spaDefaultCSP.
type spaWiring struct {
	loginMount string
	staticDir  string
	csp        string
}

// ui resolves the built-in HTML driver, wrapped in an
// [interaction.TemplateOverlayDriver] when any page carries a template.
func (h HTMLUI) ui() (uiMode, error) {
	loginCSP, err := h.Login.policy("Login")
	if err != nil {
		return uiMode{}, err
	}
	consentCSP, err := h.Consent.policy("Consent")
	if err != nil {
		return uiMode{}, err
	}
	chooserCSP, err := h.Chooser.policy("Chooser")
	if err != nil {
		return uiMode{}, err
	}
	if h.Login.Template == nil && h.Consent.Template == nil && h.Chooser.Template == nil {
		return uiMode{driver: interaction.HTMLDriver{}}, nil
	}
	return uiMode{driver: interaction.TemplateOverlayDriver{
		Inner:           interaction.HTMLDriver{},
		ConsentTemplate: h.Consent.Template,
		ChooserTemplate: h.Chooser.Template,
		LoginTemplate:   h.Login.Template,
		ConsentCSP:      consentCSP,
		ChooserCSP:      chooserCSP,
		LoginCSP:        loginCSP,
	}}, nil
}

// policy validates p as the named [HTMLUI] page and returns the policy
// the overlay sends with it; an untemplated page yields "", which the
// overlay reads as "keep the default policy".
func (p PageTemplate) policy(page string) (string, error) {
	if p.Template == nil {
		if p.ContentSecurityPolicy != "" {
			return "", newConfigurationError("WithUI: HTMLUI."+page+" sets ContentSecurityPolicy without a Template", nil)
		}
		return "", nil
	}
	return normalizeCSPField("WithUI: HTMLUI."+page+".ContentSecurityPolicy", p.ContentSecurityPolicy)
}

// ui resolves the SPA wiring; the driver stays nil.
func (s SPAUI) ui() (uiMode, error) {
	if s.LoginMount == "" {
		return uiMode{}, newConfigurationError("WithUI: SPAUI.LoginMount must not be empty", nil)
	}
	if !strings.HasPrefix(s.LoginMount, "/") {
		return uiMode{}, newConfigurationError("WithUI: SPAUI.LoginMount must start with \"/\"", nil)
	}
	if err := validateSPAUIStaticDir(s.StaticDir); err != nil {
		return uiMode{}, err
	}
	policy := spaDefaultCSP
	if s.ContentSecurityPolicy != "" {
		normalized, err := normalizeCSPField("WithUI: SPAUI.ContentSecurityPolicy", s.ContentSecurityPolicy)
		if err != nil {
			return uiMode{}, err
		}
		policy = normalized
	}
	return uiMode{spa: &spaWiring{loginMount: s.LoginMount, staticDir: s.StaticDir, csp: policy}}, nil
}

// validateSPAUIStaticDir checks that a non-empty StaticDir refers to
// an accessible directory at construction time. An empty value means
// "let the embedder serve the SPA bundle through their own reverse
// proxy" and is allowed.
func validateSPAUIStaticDir(dir string) error {
	if dir == "" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return newConfigurationError("WithUI: SPAUI.StaticDir "+dir+" not accessible", err)
	}
	if !info.IsDir() {
		return newConfigurationError("WithUI: SPAUI.StaticDir "+dir+" is not a directory", nil)
	}
	return nil
}

// ui resolves the embedder driver as given, after checking a template
// overlay the way [HTMLUI] would have built it.
func (d DriverUI) ui() (uiMode, error) {
	if nilcheck.IsNil(d.Driver) {
		return uiMode{}, newConfigurationError("WithUI: DriverUI.Driver must not be nil", nil)
	}
	var overlay *interaction.TemplateOverlayDriver
	switch v := d.Driver.(type) {
	case interaction.TemplateOverlayDriver:
		overlay = &v
	case *interaction.TemplateOverlayDriver:
		overlay = v
	}
	if overlay != nil {
		if nilcheck.IsNil(overlay.Inner) {
			return uiMode{}, newConfigurationError("WithUI: DriverUI.Driver is a TemplateOverlayDriver with a nil Inner", nil)
		}
		for _, f := range []struct{ name, policy string }{
			{"ConsentCSP", overlay.ConsentCSP},
			{"ChooserCSP", overlay.ChooserCSP},
			{"LoginCSP", overlay.LoginCSP},
		} {
			if _, err := normalizeCSPField("WithUI: DriverUI.Driver "+f.name, f.policy); err != nil {
				return uiMode{}, err
			}
		}
	}
	return uiMode{driver: d.Driver}, nil
}

// normalizeUICSP validates policy through [interaction.NormalizeCSP]
// and returns the normalized value (the default policy for an empty
// input), or a configuration error naming option.
func normalizeUICSP(option, policy string) (string, error) {
	return normalizeCSPField(option+": ContentSecurityPolicy", policy)
}

// normalizeCSPField is [normalizeUICSP] with the full field label, so the
// error reads "<field> rejected".
func normalizeCSPField(field, policy string) (string, error) {
	normalized, err := interaction.NormalizeCSP(policy)
	if err != nil {
		return "", newConfigurationError(field+" rejected", err)
	}
	return normalized, nil
}
