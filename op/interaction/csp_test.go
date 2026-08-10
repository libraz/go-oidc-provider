package interaction_test

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// The default policy forbids every subresource, which is right for the
// markup the built-in driver emits and wrong for a branded template:
// the browser drops the stylesheet and the logo, and nothing on the
// server side observes it. These tests pin the seam that lets a
// template declare its own origins, and the three directives it may
// not touch.

func TestNormalizeCSP_EmptySelectsTheSubresourceFreeDefault(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "   ", ";", " ; ; "} {
		got, err := interaction.NormalizeCSP(in)
		if err != nil {
			t.Fatalf("NormalizeCSP(%q): %v", in, err)
		}
		for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(got, want) {
				t.Errorf("NormalizeCSP(%q) = %q, missing %q", in, got, want)
			}
		}
	}
}

func TestNormalizeCSP_KeepsBrandingDirectivesAndAppendsTheProtections(t *testing.T) {
	t.Parallel()

	got, err := interaction.NormalizeCSP("default-src 'none'; style-src 'self' https://cdn.example; img-src 'self' data:; font-src https://cdn.example")
	if err != nil {
		t.Fatalf("NormalizeCSP: %v", err)
	}
	for _, want := range []string{
		"style-src 'self' https://cdn.example",
		"img-src 'self' data:",
		"font-src https://cdn.example",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("NormalizeCSP = %q, missing %q", got, want)
		}
	}
	// The appended directives must not be appended twice when the
	// result is fed back in: the overlay normalizes at render time and
	// the option site normalizes at construction, so the same string
	// passes through more than once.
	again, err := interaction.NormalizeCSP(got)
	if err != nil {
		t.Fatalf("NormalizeCSP(second pass): %v", err)
	}
	if again != got {
		t.Errorf("NormalizeCSP is not idempotent:\n first: %q\nsecond: %q", got, again)
	}
}

// frame-ancestors and base-uri do not inherit from default-src, so a
// policy that names only default-src still has to gain both.
func TestNormalizeCSP_AppendsProtectionsDefaultSrcDoesNotCover(t *testing.T) {
	t.Parallel()

	got, err := interaction.NormalizeCSP("default-src 'self'")
	if err != nil {
		t.Fatalf("NormalizeCSP: %v", err)
	}
	if !strings.Contains(got, "frame-ancestors 'none'") || !strings.Contains(got, "base-uri 'none'") {
		t.Errorf("NormalizeCSP = %q; default-src does not cover frame-ancestors or base-uri", got)
	}
}

func TestNormalizeCSP_RejectsDirectivesTheOPOwns(t *testing.T) {
	t.Parallel()

	for name, policy := range map[string]string{
		// Browsers apply form-action to redirect targets, so any value
		// blocks the cross-origin 302 that completes consent.
		"form-action self":            "default-src 'none'; form-action 'self'",
		"form-action wildcard":        "default-src 'none'; form-action *",
		"framing allowed":             "default-src 'none'; frame-ancestors https://portal.example",
		"framing self":                "default-src 'none'; frame-ancestors 'self'",
		"framing none plus an origin": "default-src 'none'; frame-ancestors 'none' https://portal.example",
		"base-uri relaxed":            "default-src 'none'; base-uri 'self'",
	} {
		if _, err := interaction.NormalizeCSP(policy); !errors.Is(err, interaction.ErrCSPNotPermitted) {
			t.Errorf("%s: NormalizeCSP(%q) error = %v, want ErrCSPNotPermitted", name, policy, err)
		}
	}
}

func TestNormalizeCSP_DirectiveNamesAreCaseInsensitive(t *testing.T) {
	t.Parallel()

	if _, err := interaction.NormalizeCSP("Frame-Ancestors 'self'"); !errors.Is(err, interaction.ErrCSPNotPermitted) {
		t.Errorf("uppercase directive name bypassed the check")
	}
	got, err := interaction.NormalizeCSP("Frame-Ancestors 'none'; Base-URI 'none'; style-src 'self'")
	if err != nil {
		t.Fatalf("NormalizeCSP: %v", err)
	}
	if strings.Count(strings.ToLower(got), "frame-ancestors") != 1 {
		t.Errorf("NormalizeCSP = %q, frame-ancestors declared more than once", got)
	}
}

// The point of the option is that a branded page actually loads its
// assets, so the header on the rendered response is what has to change
// — asserting the normalizer alone would pass even if the overlay
// never sent the result.
func TestTemplateOverlay_ConsentCSPReachesTheResponse(t *testing.T) {
	t.Parallel()

	d := interaction.TemplateOverlayDriver{
		ConsentTemplate: template.Must(template.New("c").Parse(`<!doctype html><html><body>consent</body></html>`)),
		ConsentCSP:      "default-src 'none'; style-src 'self'; img-src 'self' data:",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/interaction/uid-1", nil)
	prompt := interaction.Prompt{Type: "consent.scope", Data: interaction.ConsentScopePromptData{}, StateRef: "ref"}
	if err := d.Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"style-src 'self'", "img-src 'self' data:", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(got, want) {
			t.Errorf("Content-Security-Policy = %q, missing %q", got, want)
		}
	}
	if strings.Contains(got, "style-src 'none'") {
		t.Errorf("Content-Security-Policy = %q still carries the default style-src", got)
	}
	// Everything else the driver stamps is unchanged by the override.
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q", rec.Header().Get("X-Frame-Options"))
	}
	if rec.Header().Get("Referrer-Policy") != "same-origin" {
		t.Errorf("Referrer-Policy = %q", rec.Header().Get("Referrer-Policy"))
	}
}

func TestTemplateOverlay_ChooserCSPIsIndependentOfConsent(t *testing.T) {
	t.Parallel()

	d := interaction.TemplateOverlayDriver{
		ChooserTemplate: template.Must(template.New("c").Parse(`<!doctype html><html><body>chooser</body></html>`)),
		ConsentCSP:      "default-src 'none'; img-src https://consent.example",
		ChooserCSP:      "default-src 'none'; img-src https://chooser.example",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/interaction/uid-1", nil)
	prompt := interaction.Prompt{Type: "interaction.chooser", Data: interaction.ChooserPromptData{}, StateRef: "ref"}
	if err := d.Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(got, "https://chooser.example") || strings.Contains(got, "https://consent.example") {
		t.Errorf("Content-Security-Policy = %q, want the chooser origin only", got)
	}
}

// A hand-composed overlay can set a policy the option site would have
// rejected. Sending it would unframe the consent page or block the
// redirect that completes it, so the driver keeps the policy it can
// vouch for.
func TestTemplateOverlay_UnacceptablePolicyFallsBackToTheDefault(t *testing.T) {
	t.Parallel()

	d := interaction.TemplateOverlayDriver{
		ConsentTemplate: template.Must(template.New("c").Parse(`<!doctype html><html><body>consent</body></html>`)),
		ConsentCSP:      "default-src 'none'; frame-ancestors https://portal.example",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/interaction/uid-1", nil)
	prompt := interaction.Prompt{Type: "consent.scope", Data: interaction.ConsentScopePromptData{}, StateRef: "ref"}
	if err := d.Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(got, "frame-ancestors 'none'") || strings.Contains(got, "portal.example") {
		t.Errorf("Content-Security-Policy = %q, want the strict default", got)
	}
}

// An overlay with no policy set must behave exactly as it did before
// the field existed.
func TestTemplateOverlay_UnsetCSPKeepsTheBuiltInPolicy(t *testing.T) {
	t.Parallel()

	d := interaction.TemplateOverlayDriver{
		ConsentTemplate: template.Must(template.New("c").Parse(`<!doctype html><html><body>consent</body></html>`)),
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/interaction/uid-1", nil)
	prompt := interaction.Prompt{Type: "consent.scope", Data: interaction.ConsentScopePromptData{}, StateRef: "ref"}
	if err := d.Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}

	plain := httptest.NewRecorder()
	if err := (interaction.HTMLDriver{}).Render(plain, req, prompt); err != nil {
		t.Fatalf("HTMLDriver.Render: %v", err)
	}
	if got, want := rec.Header().Get("Content-Security-Policy"), plain.Header().Get("Content-Security-Policy"); got != want {
		t.Errorf("overlay policy = %q, html driver policy = %q; the unset field must not change anything", got, want)
	}
}
