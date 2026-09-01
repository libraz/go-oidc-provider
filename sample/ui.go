//go:build example

package main

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// maxSubmissionBytes caps what ParseSubmission reads. The orchestrator
// enforces per-field limits afterwards; this is the transport-level bound.
const maxSubmissionBytes = 64 << 10

const (
	// scopeCheckboxField is what the consent page names its per-scope
	// checkboxes. It is private to this application's form.
	scopeCheckboxField = "scope"

	// approvedScopesField is the field the consent step reads: one
	// space-separated list of the scopes the member approved. The name is
	// part of the orchestrator's submission contract, not of the page.
	approvedScopesField = "approved_scopes"
)

// chooserPromptType is the account chooser's prompt type. It is the one
// prompt a driver cannot decline to implement: op.New registers the
// chooser on every Provider, so it is emitted whenever an authorization
// request carries prompt=select_account, whether or not the application
// configured anything for it.
const chooserPromptType = "interaction.chooser"

// appDriver renders the OP's prompts as this application's own pages.
//
// Replacing the bundled driver is the reason it exists. The library decides
// which factor comes next and what fields it needs; the application decides
// what the user sees. Everything protocol-visible — factor sequencing,
// validation, CSRF verification — stays on the orchestrator's side, so the
// only obligations here are to echo Prompt.StateRef and Prompt.CSRFToken
// back and to read the reply as a form.
//
// The response headers a prompt carries are set by [stampHeaders], which
// every HTML surface in this process shares; two of the choices it makes
// are load-bearing rather than stylistic, and both are documented there.
type appDriver struct {
	tmpl *template.Template
}

func newAppDriver() (*appDriver, error) {
	tmpl, err := template.New("prompt").Parse(promptTemplates)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &appDriver{tmpl: tmpl}, nil
}

// pageData is the context every prompt template renders against.
type pageData struct {
	Title     string
	Heading   string
	Lead      string
	StateRef  string
	CSRFToken string
	Fields    []fieldView
	Scopes    []scopeView
	Client    string

	// Accounts, SessionIDField and AddAccountURL back the chooser page.
	Accounts       []accountView
	SessionIDField string
	AddAccountURL  string
}

type fieldView struct {
	Name         string
	Label        string
	InputType    string
	Required     bool
	AutoComplete string
}

// accountView is one row of the account chooser. SessionID rides the
// row's submit button rather than a text input: it is an opaque
// identifier the member has never been shown, so asking them to type it
// would be asking for something they cannot supply.
type accountView struct {
	SessionID string
	Label     string
}

type scopeView struct {
	Name        string
	Description string
	// Required marks a scope the member cannot decline. Its checkbox is
	// disabled, which also stops the browser from submitting it, so the
	// template pairs it with a hidden field carrying the same value.
	Required bool
}

// Render implements [interaction.Driver].
func (d *appDriver) Render(w http.ResponseWriter, _ *http.Request, prompt interaction.Prompt) error {
	page, name, err := d.page(prompt)
	if err != nil {
		return err
	}
	stampHeaders(w)
	return d.tmpl.ExecuteTemplate(w, name, page)
}

// page maps a prompt onto the template that renders it. An unrecognised
// prompt type is an error rather than a generic fallback page: the
// application opted into owning the UI, so a factor it has not been taught
// to render is a gap to fix, not something to paper over at runtime.
//
// That reasoning covers the factors the application configured, and the
// chooser is not one of them — it is registered on every Provider and
// emitted on prompt=select_account regardless of what this application
// wired up. A driver that erred on it would leave a 500 behind a request
// parameter any relying party can send, so the chooser is drawn here even
// though the sample never enables multi-account sign-in itself.
func (d *appDriver) page(prompt interaction.Prompt) (pageData, string, error) {
	page := pageData{
		StateRef:  prompt.StateRef,
		CSRFToken: prompt.CSRFToken,
		Fields:    fieldViews(prompt.Inputs),
	}
	switch prompt.Type {
	case "auth.password":
		page.Title = "Sign in"
		page.Heading = "Sign in"
		page.Lead = "Use the email address and password you signed up with."
		return page, "form", nil
	case "auth.totp":
		page.Title = "Two-factor code"
		page.Heading = "Enter your authenticator code"
		page.Lead = "Open your authenticator app and enter the current six-digit code."
		return page, "form", nil
	case "consent.scope":
		data, ok := prompt.Data.(interaction.ConsentScopePromptData)
		if !ok {
			return pageData{}, "", fmt.Errorf("consent prompt carried %T", prompt.Data)
		}
		page.Title = "Authorise"
		page.Heading = "Authorise " + clientLabel(data.Client)
		page.Client = clientLabel(data.Client)
		// The consent prompt declares a single approved_scopes input. This
		// page renders a checkbox per scope instead and folds them back into
		// that field on submission, so the declared input is dropped here
		// rather than rendered alongside its own replacement.
		page.Fields = nil
		for _, s := range data.Scopes {
			page.Scopes = append(page.Scopes, scopeView{
				Name:        s.Name,
				Description: s.Description,
				Required:    s.Required,
			})
		}
		return page, "consent", nil
	case chooserPromptType:
		data, ok := prompt.Data.(interaction.ChooserPromptData)
		if !ok {
			return pageData{}, "", fmt.Errorf("chooser prompt carried %T", prompt.Data)
		}
		page.Title = "Choose an account"
		page.Heading = "Choose an account"
		page.Lead = "Continue as one of the accounts signed in on this browser."
		// The chooser declares a session_id input, but the value is opaque
		// and already known to the OP. Each row carries it on its own submit
		// button instead, so the declared input is dropped rather than
		// rendered as a field nobody can fill in.
		page.Fields = nil
		page.SessionIDField = interaction.ChooserSessionIDField
		page.AddAccountURL = data.AddAccountURL
		for _, a := range data.Accounts {
			page.Accounts = append(page.Accounts, accountView{
				SessionID: a.SessionID,
				Label:     accountLabel(a),
			})
		}
		return page, "chooser", nil
	}
	return pageData{}, "", fmt.Errorf("no page for prompt type %q", prompt.Type)
}

// accountLabel is what a chooser row is shown under. DisplayName comes
// from the "name" claim the member store released; an account with no
// name falls back to the subject, because losing the label must not lose
// the account.
func accountLabel(a interaction.ChooserAccount) string {
	if a.DisplayName != "" {
		return a.DisplayName
	}
	return a.Subject
}

func clientLabel(c interaction.ClientView) string {
	if c.Name != "" {
		return c.Name
	}
	return c.ClientID
}

// fieldLabels maps the i18n keys the library's factors put on
// FieldSpec.Label onto the words this application shows.
//
// FieldSpec.Label is a key, not display text: the library states which
// field is being asked for and leaves the wording — and the language — to
// whoever owns the UI. Rendering the key straight into the page is the
// obvious mistake, and it is a silent one, because the key is a readable
// string that looks plausible until someone reads the form.
var fieldLabels = map[string]string{
	"auth.password.username": "Email address",
	"auth.password.password": "Password",
	"auth.totp.code":         "Six-digit code",
}

// fieldLabel resolves one key. An unmapped key falls back to the field
// name rather than the key, so a factor this application has not been
// taught about renders something a person can still act on.
func fieldLabel(spec interaction.FieldSpec) string {
	if label, ok := fieldLabels[spec.Label]; ok {
		return label
	}
	return spec.Name
}

// fieldViews translates the orchestrator's field specs into what the
// template needs. The library states the validation profile; the mapping to
// an HTML input type, autocomplete hint, and wording is the application's.
func fieldViews(specs []interaction.FieldSpec) []fieldView {
	views := make([]fieldView, 0, len(specs))
	for _, spec := range specs {
		if spec.Kind == interaction.FieldHidden {
			continue
		}
		v := fieldView{Name: spec.Name, Label: fieldLabel(spec), Required: spec.Required, InputType: "text"}
		switch spec.Kind {
		case interaction.FieldPassword:
			v.InputType = "password"
			v.AutoComplete = "current-password"
		case interaction.FieldEmail:
			v.InputType = "email"
			v.AutoComplete = "username"
		case interaction.FieldOTPCode:
			v.InputType = "text"
			v.AutoComplete = "one-time-code"
		case interaction.FieldText:
			v.AutoComplete = "username"
		case interaction.FieldHidden:
		}
		views = append(views, v)
	}
	return views
}

// ParseSubmission implements [interaction.Driver].
//
// This is where the application's form shape is translated into the fields
// the orchestrator reads, and the consent page is the case that needs it.
// The library asks for one space-separated approved_scopes value; the page
// asks the member scope by scope. Folding the repeated checkbox field into
// the single value here is what lets the page offer partial consent without
// the orchestrator knowing anything about checkboxes.
func (d *appDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	if !isFormURLEncoded(r.Header.Get("Content-Type")) {
		return interaction.FormSubmission{}, errors.New("sample: expected application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxSubmissionBytes)
	if err := r.ParseForm(); err != nil {
		return interaction.FormSubmission{}, fmt.Errorf("sample: malformed submission: %w", err)
	}
	stateRef := r.PostForm.Get("state_ref")
	if stateRef == "" {
		return interaction.FormSubmission{}, errors.New("sample: submission is missing state_ref")
	}
	// state_ref is consumed here; csrf_token is left in place because the
	// endpoint reads it from the form to complete the double-submit check.
	values := make(map[string]string, len(r.PostForm))
	for k, vs := range r.PostForm {
		if k == "state_ref" || k == scopeCheckboxField || len(vs) == 0 {
			continue
		}
		values[k] = vs[0]
	}
	if approved, ok := r.PostForm[scopeCheckboxField]; ok {
		values[approvedScopesField] = strings.Join(approved, " ")
	}
	return interaction.FormSubmission{StateRef: stateRef, Values: values}, nil
}

func isFormURLEncoded(ct string) bool {
	base, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(base), "application/x-www-form-urlencoded")
}

// stampHeaders sets the response headers every HTML page in this process
// carries: the OP's prompts, the application's own account pages, and the
// relying party's three screens. One helper rather than three sites is the
// point — a surface added later inherits the framing defence instead of
// being the one page that quietly lacks it.
//
// Two of the choices are load-bearing rather than stylistic, and both are
// easy to get wrong in a way that only shows up in a real browser:
//
//   - Referrer-Policy is same-origin, not no-referrer. A no-referrer page
//     makes the browser serialise the form POST's Origin header as "null",
//     which the interaction CSRF gate rejects with 403.
//   - Content-Security-Policy does not pin form-action. A successful consent
//     POST redirects to the relying party's cross-origin redirect_uri, and
//     browsers enforce form-action across redirects, so form-action 'self'
//     would block the flow at the last step. The screens that never post
//     cross-origin could pin it, but one policy for every page is worth
//     more here than a per-screen one: a reader copying this file gets the
//     same headers on whatever page they add next.
func stampHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
}
