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

// appDriver renders the OP's prompts as this application's own pages.
//
// Replacing the bundled driver is the reason it exists. The library decides
// which factor comes next and what fields it needs; the application decides
// what the user sees. Everything protocol-visible — factor sequencing,
// validation, CSRF verification — stays on the orchestrator's side, so the
// only obligations here are to echo Prompt.StateRef and Prompt.CSRFToken
// back and to read the reply as a form.
//
// Two header choices below are load-bearing rather than stylistic, and both
// are easy to get wrong in a way that only shows up in a real browser:
//
//   - Referrer-Policy is same-origin, not no-referrer. A no-referrer page
//     makes the browser serialise the form POST's Origin header as "null",
//     which the interaction CSRF gate rejects with 403.
//   - Content-Security-Policy does not pin form-action. A successful consent
//     POST redirects to the relying party's cross-origin redirect_uri, and
//     browsers enforce form-action across redirects, so form-action 'self'
//     would block the flow at the last step.
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
}

type fieldView struct {
	Name         string
	Label        string
	InputType    string
	Required     bool
	AutoComplete string
}

type scopeView struct {
	Name        string
	Description string
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
		for _, s := range data.Scopes {
			page.Scopes = append(page.Scopes, scopeView{Name: s.Name, Description: s.Description})
		}
		return page, "consent", nil
	}
	return pageData{}, "", fmt.Errorf("no page for prompt type %q", prompt.Type)
}

func clientLabel(c interaction.ClientView) string {
	if c.Name != "" {
		return c.Name
	}
	return c.ClientID
}

// fieldViews translates the orchestrator's field specs into what the
// template needs. The library states the validation profile; the mapping to
// an HTML input type and autocomplete hint is the application's call.
func fieldViews(specs []interaction.FieldSpec) []fieldView {
	views := make([]fieldView, 0, len(specs))
	for _, spec := range specs {
		if spec.Kind == interaction.FieldHidden {
			continue
		}
		v := fieldView{Name: spec.Name, Label: spec.Label, Required: spec.Required, InputType: "text"}
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
		if v.Label == "" {
			v.Label = spec.Name
		}
		views = append(views, v)
	}
	return views
}

// ParseSubmission implements [interaction.Driver].
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
		if k == "state_ref" || len(vs) == 0 {
			continue
		}
		values[k] = vs[0]
	}
	return interaction.FormSubmission{StateRef: stateRef, Values: values}, nil
}

func isFormURLEncoded(ct string) bool {
	base, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(base), "application/x-www-form-urlencoded")
}

// stampHeaders sets the response headers for every rendered prompt. See the
// appDriver godoc for why Referrer-Policy and form-action are what they are.
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
