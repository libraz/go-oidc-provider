package interaction

import (
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// htmlSubmissionContentType is the only request Content-Type the
// [HTMLDriver.ParseSubmission] method accepts. The check is performed
// case-insensitively against the type/subtype portion only; charset
// and other parameters are ignored.
const htmlSubmissionContentType = "application/x-www-form-urlencoded"

// HTMLDriver is a default [Driver] implementation that renders prompts
// as a minimal, self-contained HTML form and parses
// application/x-www-form-urlencoded submissions back into a
// [FormSubmission]. It is intended as the zero-configuration fallback
// for embedders that supply neither a [Driver] of their own nor a SPA
// shell: the rendered page boots a working login surface with no
// styling, no client-side JavaScript, and no third-party assets.
//
// Output discipline:
//
//   - The document contains no <script>, <style>, <img>, or inline
//     event handler attributes (on*=, style=). The page therefore
//     loads cleanly under a "script-src 'none'; style-src 'none';
//     img-src 'none'" Content-Security-Policy.
//   - Every byte derived from prompt data — labels, placeholders,
//     prefilled values, scope names, scope descriptions — is run
//     through [html.EscapeString] before reaching the response writer.
//     A hostile [PromptData] payload cannot inject markup.
//   - The output is deterministic: no random identifiers, no
//     timestamps, no map iteration. Keys derived from maps are sorted
//     before emission so golden tests can pin the byte-for-byte form.
//
// # Required hidden fields become text inputs
//
// A [FieldSpec] of kind [FieldHidden] normally carries a value the
// client-side layer computes — a captcha provider's widget token, a
// WebAuthn assertion. This driver runs no script, so nothing on the page
// can put a value there, while the orchestrator rejects a submission
// that omits a field the prompt declared [FieldSpec.Required]. Rendered
// as a hidden input, such a field makes the step unanswerable from this
// surface, and for the captcha step every unanswerable attempt is
// counted: the chain aborts once they run out, locking out every user
// who reaches the challenge.
//
// Required hidden fields are therefore emitted as labelled text inputs,
// so the ceremony always has a way forward. Whether the typed value is
// accepted stays the step's own decision — a captcha whose token can
// only come from a browser widget will still refuse it, but the refusal
// is the verifier's and is visible, rather than a form the user was
// never able to fill in.
//
// Embedders that want branding or CSS either override the two
// templated screens via [op.WithConsentUI] / [op.WithChooserUI] — which
// carry a per-page [NormalizeCSP] policy so the assets are not blocked
// — or replace the driver outright via [op.WithInteractionDriver]; the
// canonical examples for the latter path live under
// examples/16-custom-interaction/ and 10-react-login/.
//
// HTMLDriver is safe for concurrent use. When Translator is non-nil, the
// function it references MUST also be safe for concurrent use.
type HTMLDriver struct {
	// Translator resolves a plain-text message for locale and key. Returning
	// false asks HTMLDriver to use its built-in English fallback. Translator
	// output and placeholder data are always escaped by HTMLDriver at the
	// final HTML emission site; Translator implementations MUST return text,
	// not trusted markup.
	//
	// op.New injects the Provider's locale resolver when this field is nil,
	// including for an explicitly supplied HTMLDriver. A non-nil embedder
	// translator is preserved.
	Translator MessageTranslator
}

// MessageTranslator resolves a plain-text localized message. locale is the
// registered BCP 47 tag already selected for [Prompt.Locale]. data supplies
// deterministic "{name}" placeholder values. Returning ("", false) selects
// HTMLDriver's built-in English fallback.
//
// Implementations MUST be safe for concurrent use and MUST NOT return trusted
// HTML: HTMLDriver contextually escapes every returned string before writing.
type MessageTranslator func(locale, key string, data map[string]string) (string, bool)

// Compile-time confirmation that HTMLDriver satisfies Driver.
var _ Driver = HTMLDriver{}

// ErrUnsupportedContentType is returned by [HTMLDriver.ParseSubmission]
// when the request Content-Type is not
// "application/x-www-form-urlencoded". The orchestrator translates the
// error to a 415 / 400 without echoing the offending value back to the
// caller.
var ErrUnsupportedContentType = errors.New("interaction: unsupported content type")

// ErrMissingStateRef is returned by [HTMLDriver.ParseSubmission] when
// the form body parses cleanly but does not contain the hidden
// state_ref field [HTMLDriver.Render] always emits. A submission that
// loses the field is either tampered or replayed across factors and
// the orchestrator must not treat it as a valid continuation.
var ErrMissingStateRef = errors.New("interaction: missing state_ref")

// Render writes prompt as a complete HTML document. The function sets
// Content-Type, Cache-Control, and X-Frame-Options before any byte is
// written, so callers MUST NOT have stamped headers themselves.
func (d HTMLDriver) Render(w http.ResponseWriter, _ *http.Request, prompt Prompt) error {
	body := d.buildHTMLDocument(prompt)
	stampHTMLHeaders(w)
	w.WriteHeader(http.StatusOK)
	// body is assembled exclusively by buildHTMLDocument, which applies
	// html.EscapeString at every prompt- and translator-controlled emission
	// site. Keeping the final write whole preserves deterministic output.
	if _, err := io.WriteString(w, body); err != nil {
		return fmt.Errorf("interaction: render html prompt: %w", err)
	}
	return nil
}

func stampHTMLHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin (not no-referrer): a no-referrer page makes the
	// browser serialize the form-POST Origin header as "null" (Fetch
	// "Append a request Origin header" §3), which the interaction CSRF
	// Origin gate then rejects with 403. same-origin keeps the Origin on
	// the same-origin submission while still suppressing cross-origin
	// Referer leakage; the page URL carries only the opaque interaction
	// uid and loads no subresources.
	h.Set("Referrer-Policy", "same-origin")
	// The policy and the reasoning behind each directive live on
	// defaultCSP. Pages rendered from an embedder-supplied template
	// override it through [TemplateOverlayDriver.ConsentCSP] /
	// [TemplateOverlayDriver.ChooserCSP]; nothing HTMLDriver itself
	// emits needs a subresource.
	h.Set("Content-Security-Policy", defaultCSP)
}

// ParseSubmission reads at most 32 KiB from r.Body and
// decodes a url-encoded form into a [FormSubmission]. The function
// rejects requests that do not declare
// "application/x-www-form-urlencoded" with [ErrUnsupportedContentType]
// and submissions missing the hidden state_ref field with
// [ErrMissingStateRef].
func (HTMLDriver) ParseSubmission(r *http.Request) (FormSubmission, error) {
	if !isFormURLEncoded(r.Header.Get("Content-Type")) {
		return FormSubmission{}, ErrUnsupportedContentType
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxSubmissionBytes)
	if err := r.ParseForm(); err != nil {
		return FormSubmission{}, fmt.Errorf("%w: %w", ErrSubmissionMalformed, err)
	}
	stateRef := r.PostForm.Get("state_ref")
	if stateRef == "" {
		return FormSubmission{}, ErrMissingStateRef
	}
	values := make(map[string]string, len(r.PostForm))
	for k, vs := range r.PostForm {
		if k == "state_ref" {
			continue
		}
		if len(vs) > 0 {
			values[k] = strings.Join(vs, " ")
		}
	}
	return FormSubmission{StateRef: stateRef, Values: values}, nil
}

// isFormURLEncoded reports whether ct declares form-urlencoded. The
// match is case-insensitive on the type/subtype portion and tolerant
// of trailing parameters (e.g., "; charset=UTF-8").
func isFormURLEncoded(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), htmlSubmissionContentType)
}

// buildHTMLDocument renders prompt as a self-contained HTML document.
// The function dispatches on [Prompt.Data] to surface per-prompt
// affordances (e.g., the consent scope list); when the type is
// unrecognised it falls through to a generic FieldSpec form so user-
// extension factors render without code changes.
func (d HTMLDriver) buildHTMLDocument(prompt Prompt) string {
	var b strings.Builder
	title := d.titleFor(prompt)
	locale := prompt.Locale
	if locale == "" {
		locale = "en"
	}
	b.WriteString(`<!doctype html><html lang="`)
	b.WriteString(html.EscapeString(locale))
	b.WriteString(`"><head><meta charset="utf-8"><title>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</title></head><body>`)
	b.WriteString(`<h1>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</h1>`)
	// The chooser is the one prompt whose page is not "some inputs and
	// a submit button": the answer is which of N rows the user picked,
	// so each row carries its own submit and there is no single
	// Continue to press. It gets its own body writer rather than three
	// conditionals threaded through the shared one.
	if data, ok := prompt.Data.(ChooserPromptData); ok {
		d.writeChooserBody(&b, prompt, data)
	} else {
		d.writeStandardBody(&b, prompt)
	}
	b.WriteString(`</body></html>`)
	return b.String()
}

// writeStandardBody emits the intro, the form, and the single submit
// button every non-chooser prompt shares.
func (d HTMLDriver) writeStandardBody(b *strings.Builder, prompt Prompt) {
	writePromptIntro(b, prompt)
	b.WriteString(`<form method="post">`)
	writeHiddenStateRef(b, prompt.StateRef)
	if prompt.CSRFToken != "" {
		writeHiddenInput(b, "csrf_token", prompt.CSRFToken)
	}
	d.writePromptBody(b, prompt)
	b.WriteString(`<button type="submit">`)
	b.WriteString(html.EscapeString(d.buttonFor(prompt)))
	b.WriteString(`</button></form>`)
}

// writeChooserBody renders the account picker: one submit button per
// live account, followed by the "use another account" link.
//
// Each button carries name="session_id" with the row's opaque session
// identifier as its value, so activating it submits exactly the field
// the chooser interaction reads — a browser sends the name/value pair
// of the activated submit button only. That is what lets the whole
// picker live in one form, sharing the hidden state_ref and CSRF
// token, without any script.
//
// The prompt's own session_id [FieldSpec] is deliberately not rendered
// as a text input here. Its value is an opaque identifier the user has
// never been shown, so asking them to type it is asking for something
// they cannot supply; the buttons carry it instead.
func (d HTMLDriver) writeChooserBody(b *strings.Builder, prompt Prompt, data ChooserPromptData) {
	if len(data.Accounts) == 0 {
		// No form at all: there is nothing to submit, and an empty one
		// would render a dead control on a page whose only remaining
		// affordance is the link below.
		b.WriteString(`<p>`)
		b.WriteString(html.EscapeString(d.chooserMessage(prompt.Locale, "chooser.no_accounts", chooserNoAccountsFallback)))
		b.WriteString(`</p>`)
	} else {
		b.WriteString(`<form method="post">`)
		writeHiddenStateRef(b, prompt.StateRef)
		if prompt.CSRFToken != "" {
			writeHiddenInput(b, "csrf_token", prompt.CSRFToken)
		}
		for _, account := range data.Accounts {
			writeChooserAccountButton(b, account)
		}
		b.WriteString(`</form>`)
	}
	if data.AddAccountURL == "" {
		// The orchestrator leaves the URL empty when it cannot mint one
		// the OP would accept (a deployment that requires PAR). Emitting
		// a dead link would be worse than emitting none.
		return
	}
	b.WriteString(`<p><a href="`)
	b.WriteString(html.EscapeString(data.AddAccountURL))
	b.WriteString(`">`)
	b.WriteString(html.EscapeString(d.chooserMessage(prompt.Locale, "chooser.add_account", chooserAddAccountFallback)))
	b.WriteString(`</a></p>`)
}

// writeChooserAccountButton emits one account row. The label is the
// display name when the user store supplied one and the subject
// otherwise, matching what the shipped chooser template and the SPA
// bundle do with the same two fields.
func writeChooserAccountButton(b *strings.Builder, account ChooserAccount) {
	label := account.DisplayName
	if label == "" {
		label = account.Subject
	}
	b.WriteString(`<p><button type="submit" name="`)
	b.WriteString(html.EscapeString(ChooserSessionIDField))
	b.WriteString(`" value="`)
	b.WriteString(html.EscapeString(account.SessionID))
	b.WriteString(`">`)
	b.WriteString(html.EscapeString(label))
	b.WriteString(`</button></p>`)
}

// chooserMessage resolves key through the translator and falls back to
// the built-in English string when no catalogue answers.
func (d HTMLDriver) chooserMessage(locale, key, fallback string) string {
	if message, ok := d.message(locale, key, nil); ok {
		return message
	}
	return fallback
}

// Built-in English for the two strings the chooser page needs that no
// [FieldSpec] carries. They follow the same rule as [htmlLabelFor]:
// the catalogue answers first, these answer when it does not.
const (
	chooserAddAccountFallback = "Use another account"
	chooserNoAccountsFallback = "No accounts are signed in on this browser."
)

// writePromptIntro emits any per-prompt informational text that lives
// outside the <form>. The text is metadata the SPA would normally
// render (masked email, attempts remaining, captcha provider) and is
// surfaced in plain prose so the HTML driver remains usable without
// JS. All values pass through [html.EscapeString].
func writePromptIntro(b *strings.Builder, prompt Prompt) {
	switch d := prompt.Data.(type) {
	case PasswordPromptData:
		if d.UsernameHint != "" {
			b.WriteString(`<p>Hint: `)
			b.WriteString(html.EscapeString(d.UsernameHint))
			b.WriteString(`</p>`)
		}
	case TOTPPromptData:
		writeAttemptsRemaining(b, d.AttemptsRemaining)
	case RecoveryCodePromptData:
		writeAttemptsRemaining(b, d.AttemptsRemaining)
	case EmailOTPVerifyPromptData:
		if d.MaskedEmail != "" {
			b.WriteString(`<p>Code sent to `)
			b.WriteString(html.EscapeString(d.MaskedEmail))
			b.WriteString(`.</p>`)
		}
	case CaptchaPromptData:
		if d.Provider != "" {
			b.WriteString(`<p>Captcha provider: `)
			b.WriteString(html.EscapeString(d.Provider))
			b.WriteString(`</p>`)
		}
	case ConsentScopePromptData:
		writeConsentScopeList(b, d)
	default:
		// PasskeyPromptData, EmailOTPSendPromptData, nil, and user-
		// extension PromptData values share this branch: no
		// introductory text — the form fields carry the affordance.
	}
}

// writePromptBody emits the form-internal markup. Most prompts render
// their [FieldSpec] inputs verbatim; consent renders a single hidden
// approved_scopes field instead, matching the consent interaction
// contract documented at internal/authn/consent/interaction.go
// (ApprovedScopesField).
func (d HTMLDriver) writePromptBody(b *strings.Builder, prompt Prompt) {
	if scopes, ok := prompt.Data.(ConsentScopePromptData); ok {
		writeConsentApprovedField(b, scopes)
		return
	}
	d.writeFieldInputs(b, prompt.Locale, prompt.Inputs)
}

// writeAttemptsRemaining emits an "attempts remaining" line when the
// orchestrator has reported a non-zero count. Zero is suppressed
// because zero either means "unknown" or "no further attempts" and
// surfacing either to the user is misleading without context.
func writeAttemptsRemaining(b *strings.Builder, attempts int) {
	if attempts <= 0 {
		return
	}
	b.WriteString(`<p>Attempts remaining: `)
	b.WriteString(strconv.Itoa(attempts))
	b.WriteString(`</p>`)
}

// writeConsentScopeList renders the read-only list of scopes the user
// is being asked to approve. Each row carries an explicit "(required)"
// marker for scopes the catalogue declared mandatory, matching the
// orchestrator's server-side enforcement.
func writeConsentScopeList(b *strings.Builder, data ConsentScopePromptData) {
	writeConsentClient(b, data.Client)
	b.WriteString(`<ul>`)
	for _, s := range data.Scopes {
		b.WriteString(`<li>`)
		b.WriteString(html.EscapeString(s.Name))
		if s.Description != "" {
			b.WriteString(` - `)
			b.WriteString(html.EscapeString(s.Description))
		}
		if s.Required {
			b.WriteString(` (required)`)
		}
		b.WriteString(`</li>`)
	}
	b.WriteString(`</ul>`)
}

func writeConsentClient(b *strings.Builder, client ClientView) {
	name := client.Name
	if name == "" {
		name = client.ClientID
	}
	if name == "" {
		return
	}
	b.WriteString(`<p>Client: `)
	b.WriteString(html.EscapeString(name))
	b.WriteString(`</p>`)
}

// writeConsentApprovedField emits the single hidden field the
// consent interaction expects on submission. The value is the space-
// separated list of every requested scope name, in the order the
// orchestrator surfaced them. Deselection requires JS, which the
// driver intentionally omits; embedders who need partial consent ship
// a custom Driver or a SPA via [op.WithSPAUI].
func writeConsentApprovedField(b *strings.Builder, data ConsentScopePromptData) {
	names := make([]string, 0, len(data.Scopes))
	for _, s := range data.Scopes {
		names = append(names, s.Name)
	}
	writeHiddenInput(b, "approved_scopes", strings.Join(names, " "))
}

// writeFieldInputs renders one labelled <input> per [FieldSpec]. The
// fields are emitted in [FieldSpec.Name] sort order so the output is
// deterministic for golden testing; the orchestrator does not rely on
// input ordering at the wire level.
func (d HTMLDriver) writeFieldInputs(b *strings.Builder, locale string, inputs []FieldSpec) {
	if len(inputs) == 0 {
		return
	}
	sorted := make([]FieldSpec, len(inputs))
	copy(sorted, inputs)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})
	for _, in := range sorted {
		d.writeFieldInput(b, locale, in)
	}
}

// writeFieldInput emits one labelled input. An optional hidden field
// (Kind == FieldHidden) skips the label wrapper; everything else renders
// as a <p><label>Label<br><input ...></label></p> block. Length
// attributes translate from [FieldSpec.MinLen] / [FieldSpec.MaxLen] to
// HTML minlength / maxlength so the browser surfaces a client-side hint
// before the server-side validator rejects the submission.
//
// A hidden field marked [FieldSpec.Required] is the exception: it is
// presented as a text input. See [HTMLDriver] for why the alternative
// is a step no user of this surface can ever complete.
func (d HTMLDriver) writeFieldInput(b *strings.Builder, locale string, in FieldSpec) {
	if in.Kind == FieldHidden && !in.Required {
		writeHiddenInput(b, in.Name, "")
		return
	}
	kind := in.Kind
	if kind == FieldHidden {
		kind = FieldText
	}
	b.WriteString(`<p><label>`)
	b.WriteString(html.EscapeString(d.labelFor(locale, in.Label)))
	b.WriteString(`<br><input name="`)
	b.WriteString(html.EscapeString(in.Name))
	b.WriteString(`" type="`)
	b.WriteString(htmlInputType(kind))
	b.WriteString(`"`)
	if in.Required {
		b.WriteString(` required`)
	}
	if in.MinLen > 0 {
		b.WriteString(` minlength="`)
		b.WriteString(strconv.Itoa(in.MinLen))
		b.WriteString(`"`)
	}
	if in.MaxLen > 0 {
		b.WriteString(` maxlength="`)
		b.WriteString(strconv.Itoa(in.MaxLen))
		b.WriteString(`"`)
	}
	b.WriteString(`></label></p>`)
}

// writeHiddenStateRef emits the orchestrator-supplied continuation
// token as a hidden field. The value is mandatory; an empty StateRef
// would mean the orchestrator handed an unsigned prompt to the driver,
// which Render does not attempt to repair.
func writeHiddenStateRef(b *strings.Builder, stateRef string) {
	writeHiddenInput(b, "state_ref", stateRef)
}

// writeHiddenInput emits a single <input type="hidden"> tag. The value
// is HTML-escaped; the name is escaped because user-extension factors
// can introduce field names the driver has not seen.
func writeHiddenInput(b *strings.Builder, name, value string) {
	b.WriteString(`<input type="hidden" name="`)
	b.WriteString(html.EscapeString(name))
	b.WriteString(`" value="`)
	b.WriteString(html.EscapeString(value))
	b.WriteString(`">`)
}

// htmlInputType maps a [FieldKind] to the matching HTML
// <input type="..."> attribute. The exhaustive switch is the only
// consumer of [FieldKind]; adding a new kind without extending this
// function fails the exhaustive lint pass.
func htmlInputType(k FieldKind) string {
	switch k {
	case FieldPassword:
		return "password"
	case FieldEmail:
		return "email"
	case FieldOTPCode:
		return "text"
	case FieldHidden:
		return "hidden"
	case FieldText:
		return "text"
	default:
		return "text"
	}
}

// htmlLabelFor maps the i18n keys library-shipped factors emit on
// FieldSpec.Label back to short English strings. The driver echoes
// unknown keys verbatim so embedder-defined factors (and embedders
// shipping their own client-side i18n table) keep working without
// modification.
func htmlLabelFor(labelKey string) string {
	switch labelKey {
	case "auth.password.username":
		return "Username"
	case "auth.password.password":
		return "Password"
	case "auth.totp.code":
		return "Authenticator code"
	case "auth.email_otp.email":
		return "Email address"
	case "auth.email_otp.code":
		return "Email code"
	case "auth.recovery_code.code":
		return "Recovery code"
	case "auth.passkey.response":
		return "Passkey response"
	case "auth.captcha.token":
		return "Verification token"
	case "chooser.session_id":
		return "Account"
	case "consent.approved_scopes":
		return "Approved access"
	default:
		return labelKey
	}
}

func messageLabelKey(labelKey string) string {
	switch labelKey {
	case "auth.password.username":
		return "login.identifier.label"
	case "auth.password.password":
		return "login.password.label"
	default:
		return labelKey
	}
}

func (d HTMLDriver) labelFor(locale, labelKey string) string {
	if message, ok := d.message(locale, messageLabelKey(labelKey), nil); ok {
		return message
	}
	return htmlLabelFor(labelKey)
}

func (d HTMLDriver) titleFor(prompt Prompt) string {
	key := prompt.Type
	data := map[string]string(nil)
	switch prompt.Type {
	case "auth.password":
		key = "login.title"
	case "consent.scope":
		key = "consent.title"
		if consent, ok := prompt.Data.(ConsentScopePromptData); ok {
			clientName := consent.Client.Name
			if clientName == "" {
				clientName = consent.Client.ClientID
			}
			data = map[string]string{"client_name": clientName}
		}
	}
	if message, ok := d.message(prompt.Locale, key, data); ok {
		return message
	}
	return htmlTitleFor(prompt.Type)
}

func (d HTMLDriver) buttonFor(prompt Prompt) string {
	key := ""
	switch prompt.Type {
	case "auth.password":
		key = "login.button.submit"
	case "consent.scope":
		key = "consent.button.allow"
	}
	if message, ok := d.message(prompt.Locale, key, nil); ok {
		return message
	}
	return "Continue"
}

func (d HTMLDriver) message(locale, key string, data map[string]string) (string, bool) {
	if d.Translator == nil || key == "" {
		return "", false
	}
	return d.Translator(locale, key, data)
}

// htmlTitleFor returns the page title shown in <title> and <h1>. The
// mapping covers the prompt types the library ships; unknown types
// fall through to the prompt identifier verbatim (escaped at the
// emission site) so user-extension factors render with a sensible
// heading.
func htmlTitleFor(promptType string) string {
	switch promptType {
	case "auth.password":
		return "Sign in"
	case "auth.totp":
		return "Two-factor code"
	case "auth.email_otp.send":
		return "Send email code"
	case "auth.email_otp.verify":
		return "Email code"
	case "auth.passkey":
		return "Passkey"
	case "auth.recovery_code":
		return "Recovery code"
	case "captcha":
		return "Verify you are human"
	case "consent.scope":
		return "Authorize access"
	case "interaction.chooser":
		return "Choose an account"
	default:
		if promptType == "" {
			return "Continue"
		}
		return promptType
	}
}
