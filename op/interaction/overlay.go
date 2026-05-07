package interaction

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
)

// ConsentApprovedScopesField is the form field name the consent
// interaction expects on submission. Mirrors
// internal/authn/consent.ApprovedScopesField; the duplication exists
// because the op/interaction package MUST NOT import internal/.
const ConsentApprovedScopesField = "approved_scopes"

// ChooserSessionIDField is the form field name the chooser
// interaction expects on submission. Mirrors
// internal/authn.ChooserSessionIDField; the duplication exists
// because the op/interaction package MUST NOT import internal/.
const ChooserSessionIDField = "session_id"

// ErrTemplateOverlayInnerNil is returned by
// [TemplateOverlayDriver.Render] and
// [TemplateOverlayDriver.ParseSubmission] when dispatch falls through
// to the inner [Driver] but the Inner field is nil. The library always
// constructs [TemplateOverlayDriver] with a non-nil Inner; this
// sentinel exists for custom Driver authors that compose the wrapper
// themselves and forget to populate Inner.
var ErrTemplateOverlayInnerNil = errors.New("interaction: TemplateOverlayDriver.Inner is nil")

// TemplateOverlayDriver wraps an inner [Driver] and intercepts
// [Driver.Render] for the two well-known prompt types
// "consent.scope" and "interaction.chooser" when the corresponding
// *html/template.Template is non-nil. ParseSubmission is delegated
// to the inner Driver verbatim — submission shape is owned by the
// built-in consent and chooser interactions and is unaffected by
// custom templating.
//
// Embedders do not construct TemplateOverlayDriver directly. op.New
// wires it automatically when [op.WithConsentUI] or [op.WithChooserUI]
// is configured (and [op.WithSPAUI] is not). Custom Driver
// implementations may compose TemplateOverlayDriver themselves to opt
// into the same render seam.
//
// The wrapper is stateless and safe for concurrent use as long as the
// embedded *template.Template values are; html/template templates are
// safe for concurrent Execute once parsed (per html/template doc).
type TemplateOverlayDriver struct {
	// Inner is the fallback [Driver]. Render delegates to Inner for
	// any prompt type the overlay does not handle, and for handled
	// prompt types whose template field is nil. ParseSubmission
	// always delegates to Inner verbatim.
	Inner Driver

	// ConsentTemplate, when non-nil, renders prompts whose payload
	// is [ConsentScopePromptData] using [ConsentTemplateData] as the
	// template data context.
	ConsentTemplate *template.Template

	// ChooserTemplate, when non-nil, renders prompts whose payload
	// is [ChooserPromptData] using [ChooserTemplateData] as the
	// template data context.
	ChooserTemplate *template.Template
}

// Compile-time confirmation that TemplateOverlayDriver satisfies Driver.
var _ Driver = TemplateOverlayDriver{}

// Render dispatches based on the concrete type of [Prompt.Data]. For
// [ConsentScopePromptData] with a non-nil ConsentTemplate, Render
// projects the payload onto a [ConsentTemplateData] and executes the
// template. For [ChooserPromptData] with a non-nil ChooserTemplate, it
// does the same with [ChooserTemplateData]. Any other case (unknown
// payload type, or matching payload type whose template is nil) is
// delegated to Inner.Render. Headers ("Content-Type",
// "Cache-Control", "X-Frame-Options") are stamped before any byte is
// written, mirroring [HTMLDriver.Render].
func (d TemplateOverlayDriver) Render(w http.ResponseWriter, r *http.Request, p Prompt) error {
	switch data := p.Data.(type) {
	case ConsentScopePromptData:
		if d.ConsentTemplate != nil {
			return d.renderConsent(w, r, p, data)
		}
	case ChooserPromptData:
		if d.ChooserTemplate != nil {
			return d.renderChooser(w, r, p, data)
		}
	}
	if d.Inner == nil {
		return ErrTemplateOverlayInnerNil
	}
	return d.Inner.Render(w, r, p)
}

// ParseSubmission delegates verbatim to Inner. Submission shape is
// owned by the built-in consent and chooser interactions and is
// unaffected by custom templating.
func (d TemplateOverlayDriver) ParseSubmission(r *http.Request) (FormSubmission, error) {
	if d.Inner == nil {
		return FormSubmission{}, ErrTemplateOverlayInnerNil
	}
	return d.Inner.ParseSubmission(r)
}

// renderConsent stamps response headers and executes ConsentTemplate
// against a [ConsentTemplateData] populated from the prompt.
func (d TemplateOverlayDriver) renderConsent(w http.ResponseWriter, r *http.Request, p Prompt, data ConsentScopePromptData) error {
	td := ConsentTemplateData{
		Client:              data.Client,
		Scopes:              data.Scopes,
		StateRef:            p.StateRef,
		CSRFToken:           p.CSRFToken,
		ApprovedScopesField: ConsentApprovedScopesField,
		SubmitMethod:        "POST",
		SubmitAction:        r.URL.RequestURI(),
	}
	stampOverlayHeaders(w)
	w.WriteHeader(http.StatusOK)
	if err := d.ConsentTemplate.Execute(w, td); err != nil {
		return fmt.Errorf("interaction: render consent template: %w", err)
	}
	return nil
}

// renderChooser stamps response headers and executes ChooserTemplate
// against a [ChooserTemplateData] populated from the prompt.
func (d TemplateOverlayDriver) renderChooser(w http.ResponseWriter, r *http.Request, p Prompt, data ChooserPromptData) error {
	td := ChooserTemplateData{
		Accounts:       data.Accounts,
		AddAccountURL:  data.AddAccountURL,
		StateRef:       p.StateRef,
		CSRFToken:      p.CSRFToken,
		SessionIDField: ChooserSessionIDField,
		SubmitMethod:   "POST",
		SubmitAction:   r.URL.RequestURI(),
	}
	stampOverlayHeaders(w)
	w.WriteHeader(http.StatusOK)
	if err := d.ChooserTemplate.Execute(w, td); err != nil {
		return fmt.Errorf("interaction: render chooser template: %w", err)
	}
	return nil
}

// stampOverlayHeaders mirrors the response stamping [HTMLDriver.Render]
// applies. The headers MUST be set before WriteHeader; the helper
// keeps consent and chooser dispatch in sync.
func stampOverlayHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("X-Frame-Options", "DENY")
}
