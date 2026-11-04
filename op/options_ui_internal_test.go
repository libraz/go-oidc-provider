package op

import (
	"html/template"
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestWithUI_ResolvesPerVariant pins the resolved driver and SPA wiring
// each variant produces, and that omitting WithUI equals HTMLUI{}.
func TestWithUI_ResolvesPerVariant(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("p").Parse("ok"))
	custom := &struct{ interaction.Driver }{}

	t.Run("no WithUI equals HTMLUI", func(t *testing.T) {
		t.Parallel()
		none, err := newConfig(nil)
		if err != nil {
			t.Fatalf("newConfig: %v", err)
		}
		explicit, err := newConfig([]Option{WithUI(HTMLUI{})})
		if err != nil {
			t.Fatalf("newConfig: %v", err)
		}
		if _, ok := none.interactionD.(interaction.HTMLDriver); !ok {
			t.Fatalf("interactionD = %T, want interaction.HTMLDriver", none.interactionD)
		}
		if !reflect.DeepEqual(none.interactionD, explicit.interactionD) || none.ui.spa != nil || explicit.ui.spa != nil {
			t.Fatalf("no-WithUI (%T, spa=%v) differs from HTMLUI{} (%T, spa=%v)",
				none.interactionD, none.ui.spa, explicit.interactionD, explicit.ui.spa)
		}
	})

	t.Run("HTMLUI with template resolves to overlay", func(t *testing.T) {
		t.Parallel()
		c, err := newConfig([]Option{WithUI(HTMLUI{Consent: PageTemplate{Template: tmpl}})})
		if err != nil {
			t.Fatalf("newConfig: %v", err)
		}
		overlay, ok := c.interactionD.(interaction.TemplateOverlayDriver)
		if !ok {
			t.Fatalf("interactionD = %T, want interaction.TemplateOverlayDriver", c.interactionD)
		}
		if _, ok := overlay.Inner.(interaction.HTMLDriver); !ok {
			t.Errorf("overlay.Inner = %T, want interaction.HTMLDriver", overlay.Inner)
		}
		if overlay.ConsentTemplate != tmpl || overlay.ChooserTemplate != nil || overlay.LoginTemplate != nil {
			t.Errorf("templates = consent %p chooser %p login %p, want only consent", overlay.ConsentTemplate,
				overlay.ChooserTemplate, overlay.LoginTemplate)
		}
		wantCSP, err := interaction.NormalizeCSP("")
		if err != nil {
			t.Fatalf("NormalizeCSP: %v", err)
		}
		if overlay.ConsentCSP != wantCSP {
			t.Errorf("ConsentCSP = %q, want the library default %q", overlay.ConsentCSP, wantCSP)
		}
		if c.ui.spa != nil {
			t.Errorf("ui.spa = %v, want nil", c.ui.spa)
		}
	})

	t.Run("SPAUI leaves the driver nil", func(t *testing.T) {
		t.Parallel()
		c, err := newConfig([]Option{WithUI(SPAUI{LoginMount: "/login"})})
		if err != nil {
			t.Fatalf("newConfig: %v", err)
		}
		if c.interactionD != nil {
			t.Errorf("interactionD = %T, want nil", c.interactionD)
		}
		if c.ui.spa == nil || c.ui.spa.loginMount != "/login" || c.ui.spa.csp != spaDefaultCSP {
			t.Errorf("ui.spa = %+v, want LoginMount /login with the default CSP", c.ui.spa)
		}
	})

	t.Run("DriverUI keeps the driver verbatim", func(t *testing.T) {
		t.Parallel()
		c, err := newConfig([]Option{WithUI(DriverUI{Driver: custom})})
		if err != nil {
			t.Fatalf("newConfig: %v", err)
		}
		if c.interactionD != interaction.Driver(custom) {
			t.Errorf("interactionD = %T, want the supplied driver", c.interactionD)
		}
		if c.ui.spa != nil {
			t.Errorf("ui.spa = %v, want nil", c.ui.spa)
		}
	})
}

// TestWithUI_TranslatorReachesBundledHTMLDriver pins that the locale
// translator is injected into an HTML driver however WithUI delivers it,
// so Japanese wording is not lost behind DriverUI or an HTMLUI overlay.
func TestWithUI_TranslatorReachesBundledHTMLDriver(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("p").Parse("ok"))
	const wantJA = "サインイン"
	for _, tc := range []struct {
		name string
		ui   UI
	}{
		{"DriverUI over HTMLDriver", DriverUI{Driver: interaction.HTMLDriver{}}},
		{"HTMLUI with Consent", HTMLUI{Consent: PageTemplate{Template: tmpl}}},
		{"HTMLUI without templates", HTMLUI{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := newConfig([]Option{WithUI(tc.ui)})
			if err != nil {
				t.Fatalf("newConfig: %v", err)
			}
			resolver, err := buildLocaleResolver(c)
			if err != nil {
				t.Fatalf("buildLocaleResolver: %v", err)
			}
			wired := wireHTMLDriverTranslator(c.interactionD, resolver)
			if overlay, ok := wired.(interaction.TemplateOverlayDriver); ok {
				wired = overlay.Inner
			}
			html, ok := wired.(interaction.HTMLDriver)
			if !ok || html.Translator == nil {
				t.Fatalf("wired driver = %T (translator set: %v), want an HTMLDriver with a translator", wired, ok && html.Translator != nil)
			}
			if got, found := html.Translator("ja", "login.title", nil); !found || got != wantJA {
				t.Errorf("ja login.title = (%q, %v), want (%q, true)", got, found, wantJA)
			}
		})
	}
}
