package interaction

import (
	"bytes"
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

// ErrTemplateOverlayNoInnerErrorRenderer is returned by
// [TemplateOverlayDriver.RenderError] when Inner is set but does not
// implement [ErrorRenderer]. The HTTP layer reads a non-nil return as
// "this Driver has no error surface" and falls back to the RFC 6749
// §5.2 JSON envelope, which is exactly the outcome the unwrapped Inner
// would have produced.
var ErrTemplateOverlayNoInnerErrorRenderer = errors.New(
	"interaction: TemplateOverlayDriver.Inner does not implement ErrorRenderer",
)

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

	// ConsentCSP is the Content-Security-Policy sent with a page
	// rendered from ConsentTemplate. Empty selects the library
	// default, which forbids every subresource — correct for the
	// markup [HTMLDriver] emits and wrong for a template that carries
	// branding, since a stylesheet, logo or webfont the default blocks
	// is dropped by the browser with no server-side signal. Declare
	// the origins the template actually loads from.
	//
	// The value is passed through [NormalizeCSP], which appends the
	// framing and base-uri protections when absent and rejects
	// anything that would disable them. A value that fails validation
	// falls back to the default policy; [op.WithConsentUI] rejects it
	// at [op.New] instead, so this path is reachable only for a
	// hand-composed overlay.
	ConsentCSP string

	// ChooserCSP is the Content-Security-Policy sent with a page
	// rendered from ChooserTemplate. It follows the same rules as
	// ConsentCSP and is separate because the two surfaces are
	// independent templates that need not share an asset origin.
	ChooserCSP string
}

// Compile-time confirmation that TemplateOverlayDriver satisfies Driver,
// and that it keeps carrying the optional [ErrorRenderer] capability of
// the Driver it decorates.
//
// The ErrorRenderer assertion is the load-bearing one. A decorator that
// implements Driver and stops there type-asserts as "no error surface":
// the library composes this wrapper the moment an embedder supplies a
// branding template, so every pre-redirect authorization failure would
// silently drop from the wrapped Driver's HTML page back to a raw JSON
// envelope. Nothing exercises that path during a successful ceremony,
// so only the assertion catches the regression.
var (
	_ Driver        = TemplateOverlayDriver{}
	_ ErrorRenderer = TemplateOverlayDriver{}
)

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

// RenderError implements [ErrorRenderer] by delegating to Inner. The
// overlay owns the consent and chooser prompts only; a terminal
// authorization error is not one of them, so the wrapper adds nothing
// of its own and forwards the call unchanged.
//
// Delegation — rather than no method at all — is what keeps the
// capability from being lost. An embedder who configures a consent
// template on top of a Driver that renders errors as HTML keeps that
// HTML; one whose Driver has no RenderError gets the same JSON envelope
// as before, because the sentinel returned here routes the HTTP layer to
// its fallback without touching the response.
func (d TemplateOverlayDriver) RenderError(w http.ResponseWriter, r *http.Request, prompt ErrorPrompt) error {
	if d.Inner == nil {
		return ErrTemplateOverlayInnerNil
	}
	renderer, ok := d.Inner.(ErrorRenderer)
	if !ok {
		return ErrTemplateOverlayNoInnerErrorRenderer
	}
	return renderer.RenderError(w, r, prompt)
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
	var body bytes.Buffer
	if err := d.ConsentTemplate.Execute(&body, td); err != nil {
		return fmt.Errorf("interaction: render consent template: %w", err)
	}
	if err := writeOverlayResponse(w, &body, d.ConsentCSP); err != nil {
		return err
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
	var body bytes.Buffer
	if err := d.ChooserTemplate.Execute(&body, td); err != nil {
		return fmt.Errorf("interaction: render chooser template: %w", err)
	}
	if err := writeOverlayResponse(w, &body, d.ChooserCSP); err != nil {
		return err
	}
	return nil
}

// writeOverlayResponse commits a successfully rendered template body.
// Template execution is buffered by the callers so an execution error
// cannot leak a partial 200 response before the endpoint can react.
func writeOverlayResponse(w http.ResponseWriter, body *bytes.Buffer, policy string) error {
	stampOverlayHeaders(w, policy)
	w.WriteHeader(http.StatusOK)
	if _, err := body.WriteTo(w); err != nil {
		return fmt.Errorf("interaction: write template response: %w", err)
	}
	return nil
}

// stampOverlayHeaders mirrors the response stamping [HTMLDriver.Render]
// applies, then swaps in the per-template Content-Security-Policy when
// the embedder declared one. The headers MUST be set before
// WriteHeader; the helper keeps consent and chooser dispatch in sync.
//
// A policy that fails [NormalizeCSP] leaves the strict default in
// place. The failure modes are directives that would unframe the
// consent page or block its completing redirect, so falling back to
// the policy the library can vouch for is the safe direction; the
// option site catches the same input at [op.New] with a message.
func stampOverlayHeaders(w http.ResponseWriter, policy string) {
	stampHTMLHeaders(w)
	if policy == "" {
		return
	}
	normalized, err := NormalizeCSP(policy)
	if err != nil {
		return
	}
	w.Header().Set("Content-Security-Policy", normalized)
}
