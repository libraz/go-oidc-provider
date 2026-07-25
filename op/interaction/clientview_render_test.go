package interaction_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestHTMLDriver_ClientDisplayNameCannotBecomeMarkup pins that a
// client's own display name stays data when the built-in driver renders
// it.
//
// The name arrives through Dynamic Client Registration, so whoever
// registers a client chooses these bytes, and the consent screen is
// where they are shown back — to a signed-in user, on the OP's origin,
// at the moment they are about to authorise something. That combination
// is what turns an unescaped display name into stored XSS with a
// session to steal: the payload is planted once at registration and
// fires for every user any client sends through consent afterwards.
//
// Registration validating the name is not an option in the way it is
// for a URI. A display name is free text by design — apostrophes,
// ampersands and non-Latin scripts are all legitimate — so the
// containment has to live at the render, not the write.
//
// Tracks: CVE-2026-22752 (Spring Authorization Server) — client
// metadata accepted at the DCR endpoint without sufficient validation
// produced stored XSS, among other impacts, when it was replayed.
func TestHTMLDriver_ClientDisplayNameCannotBecomeMarkup(t *testing.T) {
	t.Parallel()

	payloads := []struct {
		name  string
		value string
	}{
		{"script element", `<script>alert(1)</script>`},
		{"attribute breakout", `" onmouseover="alert(1)`},
		{"single-quoted attribute breakout", `' onfocus='alert(1)`},
		{"tag breakout into an image handler", `<img src=x onerror=alert(1)>`},
		{"closing the surrounding element", `</p><script>alert(1)</script><p>`},
		{"closing the document title", `</title><script>alert(1)</script>`},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()

			prompt := interaction.Prompt{
				Type: "consent.scope",
				Data: interaction.ConsentScopePromptData{
					Scopes: []interaction.ConsentScope{{Name: "openid", Required: true}},
					Client: interaction.ClientView{
						ClientID: "client-display-name",
						Name:     p.value,
					},
				},
				StateRef: "ref-consent",
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
			if err := (interaction.HTMLDriver{}).Render(rec, req, prompt); err != nil {
				t.Fatalf("Render: %v", err)
			}
			body := rec.Body.String()

			// The payload must not appear as written anywhere in the
			// document — not in the body where the name is shown, and
			// not in the <title>, which several of these are shaped to
			// escape from.
			if strings.Contains(body, p.value) {
				t.Fatalf("consent document contains the display name verbatim, so it is markup rather than text:\n%s", body)
			}
			// And the escaped form must be present, or the name was
			// silently dropped and this test would pass against a
			// driver that stopped showing the client at all — which is
			// not the property being pinned.
			if !strings.Contains(body, "&lt;") && !strings.Contains(body, "&#34;") && !strings.Contains(body, "&#39;") {
				t.Fatalf("display name neither escaped nor rendered; the test no longer exercises escaping:\n%s", body)
			}
		})
	}
}
