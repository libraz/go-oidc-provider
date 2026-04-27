//go:build example

// Example custom-interaction shows how to plug a non-default
// [interaction.Driver] into [op.New]. The library ships
// [interaction.JSONDriver], which speaks JSON over HTTP — the right
// choice when the embedder ships a SPA. Embedders that prefer a server-
// rendered HTML UI swap it for a Driver of their own; the example
// implements one such Driver inline.
//
// htmlDriver renders prompts as a tiny HTML form (no template engine,
// no styling) and parses application/x-www-form-urlencoded submissions
// back into [interaction.FormSubmission]. The example value is the
// wiring shape, not a production-grade UI: a real embedder substitutes
// its own template engine, CSP headers, i18n catalogue, and styling.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/custom-interaction
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, a public HTTP
// listener, an in-memory store, and a template-free renderer. None of
// those are appropriate for production. The example exists to show
// how the [interaction.Driver] seam composes with [op.WithInteraction];
// see [examples/minimal] for the smallest startup wiring and
// [examples/fapi2] for the FAPI 2.0 Baseline profile shape.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	demoIssuer = "https://op.example.com"
	demoListen = ":8080"

	// maxSubmissionBytes caps the body size [htmlDriver.ParseSubmission]
	// reads. A few KiB is far above any legitimate form payload while
	// bounding memory use against pathological inputs (gosec G120). The
	// stock [interaction.JSONDriver] applies the same cap.
	maxSubmissionBytes = 32 * 1024
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(demoIssuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "custom-interaction-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithInteraction(htmlDriver{}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("custom-interaction example OP listening on", demoListen)
	log.Println("issuer:", demoIssuer)
	log.Println("interaction wire format: text/html (htmlDriver)")

	srv := &http.Server{
		Addr:              demoListen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// htmlDriver is a minimal [interaction.Driver] that emits inline HTML
// instead of JSON. The driver carries no state and is safe for
// concurrent use.
type htmlDriver struct{}

// Compile-time confirmation that htmlDriver satisfies the contract.
var _ interaction.Driver = htmlDriver{}

// Render writes prompt as a tiny HTML form. The form posts back to the
// same URL the browser is on; the orchestrator dispatches based on the
// path. Every [interaction.FieldSpec] becomes one <input>, plus a
// hidden state_ref the orchestrator validates on submission.
//
// The function builds the body into a [strings.Builder] and emits it
// with a single [io.WriteString] so write errors round-trip back to the
// caller as a wrapped error (matching the [interaction.JSONDriver]
// behaviour).
func (htmlDriver) Render(w http.ResponseWriter, _ *http.Request, prompt interaction.Prompt) error {
	body := buildHTML(prompt)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, body); err != nil {
		return fmt.Errorf("custom-interaction: render prompt: %w", err)
	}
	return nil
}

// ParseSubmission reads up to [maxSubmissionBytes] from r.Body and
// decodes a url-encoded form into an [interaction.FormSubmission]. The
// hidden state_ref field becomes [interaction.FormSubmission.StateRef];
// remaining fields land in [interaction.FormSubmission.Values].
// Repeated keys collapse to the first value because FormSubmission only
// carries map[string]string.
func (htmlDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxSubmissionBytes)
	if err := r.ParseForm(); err != nil {
		return interaction.FormSubmission{}, fmt.Errorf("custom-interaction: parse form: %w", err)
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
// prompt cannot inject markup; the helper exists to keep
// [htmlDriver.Render] short enough to inline-review.
func buildHTML(prompt interaction.Prompt) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head><body>`)
	b.WriteString(`<h1>`)
	b.WriteString(html.EscapeString(prompt.Type))
	b.WriteString(`</h1>`)
	b.WriteString(`<form method="POST">`)
	b.WriteString(`<input type="hidden" name="state_ref" value="`)
	b.WriteString(html.EscapeString(prompt.StateRef))
	b.WriteString(`">`)
	for _, in := range prompt.Inputs {
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
	b.WriteString(`<button type="submit">Continue</button></form></body></html>`)
	return b.String()
}

// inputType maps an [interaction.FieldKind] to the matching HTML
// <input type="..."> attribute. The mapping is the embedder's contract
// with the SPA; the orchestrator does not enforce it.
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
