package main

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// maxSubmissionBytes caps the body size [htmlDriver.ParseSubmission]
// reads. A few KiB is far above any legitimate form payload while
// bounding memory use against pathological inputs. The stock
// [interaction.JSONDriver] applies the same cap.
const maxSubmissionBytes = 32 * 1024

// htmlDriver is the [interaction.Driver] op-demo wires so the
// OpenID Foundation Conformance Suite can drive the chain through a
// real browser. The driver renders prompts as a tiny inline HTML form
// (no template engine, no styling) and parses url-encoded submissions
// back into [interaction.FormSubmission].
//
// htmlDriver carries no state and is safe for concurrent use.
type htmlDriver struct{}

// Compile-time confirmation that htmlDriver satisfies the contract.
var _ interaction.Driver = htmlDriver{}

// Render writes prompt as a self-contained HTML document. The form
// posts back to the same URL the browser is on; the orchestrator
// dispatches based on the path.
func (htmlDriver) Render(w http.ResponseWriter, _ *http.Request, prompt interaction.Prompt) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, buildHTML(prompt)); err != nil {
		return fmt.Errorf("op-demo: render prompt: %w", err)
	}
	return nil
}

// ParseSubmission reads up to [maxSubmissionBytes] from r.Body and
// decodes a url-encoded form into an [interaction.FormSubmission]. The
// hidden state_ref field becomes [interaction.FormSubmission.StateRef];
// remaining fields land in [interaction.FormSubmission.Values].
func (htmlDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxSubmissionBytes)
	if err := r.ParseForm(); err != nil {
		return interaction.FormSubmission{}, fmt.Errorf("op-demo: parse form: %w", err)
	}
	sub := interaction.FormSubmission{
		StateRef: r.PostForm.Get("state_ref"),
		Values:   make(map[string]string, len(r.PostForm)),
	}
	for k, vs := range r.PostForm {
		if k == "state_ref" {
			continue
		}
		if len(vs) > 0 {
			sub.Values[k] = vs[0]
		}
	}
	return sub, nil
}

// buildHTML renders prompt into a self-contained HTML document. All
// dynamic strings are passed through [html.EscapeString] so a hostile
// prompt cannot inject markup. The [interaction.ConsentScopePromptData]
// case is split out because consent renders one checkbox per scope
// rather than a generic <input> per [interaction.FieldSpec].
func buildHTML(prompt interaction.Prompt) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>op-demo</title></head><body>`)
	b.WriteString(`<h1>`)
	b.WriteString(html.EscapeString(prompt.Type))
	b.WriteString(`</h1>`)
	b.WriteString(`<form method="POST">`)
	b.WriteString(`<input type="hidden" name="state_ref" value="`)
	b.WriteString(html.EscapeString(prompt.StateRef))
	b.WriteString(`">`)
	if prompt.CSRFToken != "" {
		b.WriteString(`<input type="hidden" name="csrf_token" value="`)
		b.WriteString(html.EscapeString(prompt.CSRFToken))
		b.WriteString(`">`)
	}
	if scopes, ok := prompt.Data.(interaction.ConsentScopePromptData); ok {
		writeConsentInputs(&b, scopes)
	} else {
		writeFieldInputs(&b, prompt.Inputs)
	}
	b.WriteString(`<button type="submit">Continue</button></form></body></html>`)
	return b.String()
}

// writeConsentInputs renders the consent screen as a read-only "you
// are about to approve these scopes" list plus a single hidden field
// named [consent.ApprovedScopesField] that carries the full requested
// set as a space-separated string. The library's consent interaction
// expects exactly one field with that name (see
// internal/authn/consent/interaction.go), so a per-checkbox HTML
// pattern would require client-side JS to fold them into the single
// expected value. op-demo deliberately avoids JS so the conformance
// run is reproducible; the tradeoff is that a user cannot deselect
// optional scopes from the demo UI.
func writeConsentInputs(b *strings.Builder, data interaction.ConsentScopePromptData) {
	for _, s := range data.Scopes {
		b.WriteString(`<p>`)
		b.WriteString(html.EscapeString(s.Name))
		if s.Description != "" {
			b.WriteString(` — `)
			b.WriteString(html.EscapeString(s.Description))
		}
		b.WriteString(`</p>`)
	}
	names := make([]string, 0, len(data.Scopes))
	for _, s := range data.Scopes {
		names = append(names, s.Name)
	}
	b.WriteString(`<input type="hidden" name="approved_scopes" value="`)
	b.WriteString(html.EscapeString(strings.Join(names, " ")))
	b.WriteString(`">`)
}

// writeFieldInputs is the generic branch: one <input> per FieldSpec.
// Hidden fields are emitted with the orchestrator-supplied default if
// the FieldSpec carries one, but the spec carries no default value
// today, so they render empty and the SPA fills them.
func writeFieldInputs(b *strings.Builder, inputs []interaction.FieldSpec) {
	for _, in := range inputs {
		b.WriteString(`<p><label>`)
		b.WriteString(html.EscapeString(in.Label))
		b.WriteString(`<br><input name="`)
		b.WriteString(html.EscapeString(in.Name))
		b.WriteString(`" type="`)
		b.WriteString(inputType(in.Kind))
		b.WriteString(`"`)
		if in.Required {
			b.WriteString(` required`)
		}
		b.WriteString(`></label></p>`)
	}
}

// inputType maps an [interaction.FieldKind] to the matching HTML
// <input type="..."> attribute.
func inputType(k interaction.FieldKind) string {
	switch k {
	case interaction.FieldPassword:
		return "password"
	case interaction.FieldEmail:
		return "email"
	case interaction.FieldHidden:
		return "hidden"
	case interaction.FieldOTPCode, interaction.FieldText:
		return "text"
	default:
		return "text"
	}
}
