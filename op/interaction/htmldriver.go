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
// Embedders that want branding or CSS replace the driver via
// [op.WithInteraction]; the canonical examples for that path live
// under examples/04-custom-interaction/ and 10-react-login/.
//
// HTMLDriver carries no state and is safe for concurrent use.
type HTMLDriver struct{}

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
func (HTMLDriver) Render(w http.ResponseWriter, _ *http.Request, prompt Prompt) error {
	body := buildHTMLDocument(prompt)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, body); err != nil {
		return fmt.Errorf("interaction: render html prompt: %w", err)
	}
	return nil
}

// ParseSubmission reads at most [maxSubmissionBytes] from r.Body and
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
			values[k] = vs[0]
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
func buildHTMLDocument(prompt Prompt) string {
	var b strings.Builder
	title := htmlTitleFor(prompt.Type)
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</title></head><body>`)
	b.WriteString(`<h1>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</h1>`)
	writePromptIntro(&b, prompt)
	b.WriteString(`<form method="post">`)
	writeHiddenStateRef(&b, prompt.StateRef)
	if prompt.CSRFToken != "" {
		writeHiddenInput(&b, "csrf_token", prompt.CSRFToken)
	}
	writePromptBody(&b, prompt)
	b.WriteString(`<button type="submit">Continue</button></form></body></html>`)
	return b.String()
}

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
func writePromptBody(b *strings.Builder, prompt Prompt) {
	if scopes, ok := prompt.Data.(ConsentScopePromptData); ok {
		writeConsentApprovedField(b, scopes)
		return
	}
	writeFieldInputs(b, prompt.Inputs)
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
func writeFieldInputs(b *strings.Builder, inputs []FieldSpec) {
	if len(inputs) == 0 {
		return
	}
	sorted := make([]FieldSpec, len(inputs))
	copy(sorted, inputs)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})
	for _, in := range sorted {
		writeFieldInput(b, in)
	}
}

// writeFieldInput emits one labelled input. Hidden fields (Kind ==
// FieldHidden) skip the label wrapper; everything else renders as a
// <p><label>Label<br><input ...></label></p> block. Length attributes
// translate from [FieldSpec.MinLen] / [FieldSpec.MaxLen] to HTML
// minlength / maxlength so the browser surfaces a client-side hint
// before the server-side validator rejects the submission.
func writeFieldInput(b *strings.Builder, in FieldSpec) {
	if in.Kind == FieldHidden {
		writeHiddenInput(b, in.Name, "")
		return
	}
	b.WriteString(`<p><label>`)
	b.WriteString(html.EscapeString(htmlLabelFor(in.Label)))
	b.WriteString(`<br><input name="`)
	b.WriteString(html.EscapeString(in.Name))
	b.WriteString(`" type="`)
	b.WriteString(htmlInputType(in.Kind))
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
	default:
		return labelKey
	}
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
	default:
		if promptType == "" {
			return "Continue"
		}
		return promptType
	}
}
