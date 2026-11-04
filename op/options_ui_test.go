package op_test

import (
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// pairwiseUIMode names the UI model value of a TestWithUI_Pairwise row.
type pairwiseUIMode string

const (
	uiNone         pairwiseUIMode = "none"
	uiHTMLEmpty    pairwiseUIMode = "html_empty"
	uiHTMLTemplate pairwiseUIMode = "html_templates"
	uiSPA          pairwiseUIMode = "spa"
	uiDriverCustom pairwiseUIMode = "driver_custom"
	uiDriverHTML   pairwiseUIMode = "driver_bundled_html"
)

// pairwiseExpect is the fail-fast outcome of a row: the authorization_code
// requirement is checked before the passkey/UI capability check.
type pairwiseExpect string

const (
	expectNil     pairwiseExpect = "nil"
	expectGrant   pairwiseExpect = "A"
	expectPasskey pairwiseExpect = "B"
)

// pairwiseUI builds the UI value of a row; ok is false for uiNone.
func pairwiseUI(mode pairwiseUIMode) (op.UI, bool) { //nolint:ireturn // the variants share the sealed UI interface.
	switch mode { //nolint:exhaustive // uiNone has no WithUI value; the caller skips WithUI for it.
	case uiHTMLEmpty:
		return op.HTMLUI{}, true
	case uiHTMLTemplate:
		return op.HTMLUI{Consent: op.PageTemplate{Template: template.Must(template.New("c").Parse("ok"))}}, true
	case uiSPA:
		return op.SPAUI{LoginMount: "/login"}, true
	case uiDriverCustom:
		return op.DriverUI{Driver: scriptedDriver{}}, true
	case uiDriverHTML:
		return op.DriverUI{Driver: interaction.HTMLDriver{}}, true
	}
	return nil, false
}

// TestWithUI_Pairwise covers every pair of {UI mode, passkey step,
// authorization_code grant, WithUI placement}. The login flow always sits
// under WithDefaults so it does not itself record a browser surface, and
// the expectation is the single error [op.New] returns first.
func TestWithUI_Pairwise(t *testing.T) {
	t.Parallel()

	rows := []struct {
		ui        pairwiseUIMode
		passkey   bool
		authcode  bool
		placement string
		want      pairwiseExpect
	}{
		{uiSPA, true, false, "both", expectGrant},
		{uiNone, false, true, "explicit", expectNil},
		{uiNone, false, false, "explicit", expectNil},
		{uiHTMLEmpty, true, true, "explicit", expectPasskey},
		{uiHTMLEmpty, false, false, "defaults", expectNil},
		{uiHTMLTemplate, false, false, "explicit", expectGrant},
		{uiHTMLTemplate, true, true, "both", expectPasskey},
		{uiSPA, false, true, "defaults", expectNil},
		{uiDriverHTML, false, false, "both", expectGrant},
		{uiDriverCustom, false, true, "explicit", expectNil},
		{uiDriverHTML, true, true, "defaults", expectPasskey},
		{uiSPA, false, false, "explicit", expectGrant},
		{uiHTMLEmpty, true, false, "both", expectGrant},
		{uiDriverCustom, true, true, "defaults", expectNil},
		{uiDriverHTML, true, true, "explicit", expectPasskey},
		{uiNone, true, true, "explicit", expectPasskey},
		{uiDriverCustom, true, false, "both", expectGrant},
		{uiHTMLTemplate, true, false, "defaults", expectPasskey},
	}

	for i, row := range rows {
		name := fmt.Sprintf("row%02d_%s_passkey=%t_authcode=%t_%s", i+1, row.ui, row.passkey, row.authcode, row.placement)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			st := inmem.New()
			opts := validBaseOptsWithStoreNoAuthn(t, st)
			if row.passkey {
				opts = append(opts, op.WithDefaults(op.WithLoginFlow(flowWithRule(op.PrimaryPasskey{
					Store:         st.Passkeys(),
					RPID:          "id.example.com",
					RPDisplayName: "Example",
					RPOrigins:     []string{"https://id.example.com"},
				}))))
			} else {
				opts = append(opts, op.WithDefaults(op.WithLoginFlow(op.LoginFlow{
					Primary: op.PrimaryPassword{Store: st.UserPasswords()},
				})))
			}
			if !row.authcode {
				opts = append(opts, op.WithGrants(grant.ClientCredentials))
			}
			if ui, ok := pairwiseUI(row.ui); ok {
				switch row.placement {
				case "explicit":
					opts = append(opts, op.WithUI(ui))
				case "defaults":
					opts = append(opts, op.WithDefaults(op.WithUI(ui)))
				case "both":
					opts = append(opts,
						op.WithDefaults(op.WithUI(op.DriverUI{Driver: testkit.AutoConsentDriver{}})),
						op.WithUI(ui))
				}
			}

			_, err := op.New(opts...)
			switch row.want {
			case expectNil:
				if err != nil {
					t.Fatalf("row %d: op.New: %v, want nil", i+1, err)
				}
			case expectGrant:
				if !errors.Is(err, op.ErrAuthorizationCodeGrantRequired) {
					t.Fatalf("row %d: err = %v, want ErrAuthorizationCodeGrantRequired", i+1, err)
				}
				if !strings.Contains(err.Error(), "WithUI") {
					t.Errorf("row %d: err = %v, want it to name WithUI", i+1, err)
				}
			case expectPasskey:
				if err == nil {
					t.Fatalf("row %d: op.New accepted a passkey step on the scriptless HTML driver", i+1)
				}
				if errors.Is(err, op.ErrAuthorizationCodeGrantRequired) {
					t.Fatalf("row %d: err = %v, want the passkey UI error", i+1, err)
				}
				if !strings.Contains(err.Error(), "passkey step") {
					t.Errorf("row %d: err = %v, want it to mention the passkey step", i+1, err)
				}
			}
		})
	}
}

// embeddedHTMLUI satisfies [op.UI] by embedding a variant, as an
// embedder type outside package op can.
type embeddedHTMLUI struct{ op.HTMLUI }

// TestWithUI_Boundaries pins one subtest per input boundary of the
// WithUI option and the variants it accepts.
func TestWithUI_Boundaries(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("p").Parse("ok"))
	badCSP := "default-src 'self', script-src *"
	const (
		onceErr = "WithUI may be called at most once"
		nilDrv  = "WithUI: DriverUI.Driver must not be nil"
	)
	mustBuild := func(t *testing.T, extra ...op.Option) {
		t.Helper()
		if _, err := op.New(append(validBaseOpts(t), extra...)...); err != nil {
			t.Fatalf("op.New: %v", err)
		}
	}
	mustFail := func(t *testing.T, want string, extra ...op.Option) {
		t.Helper()
		_, err := op.New(append(validBaseOpts(t), extra...)...)
		wantConfigurationError(t, err, want)
	}
	a := op.WithUI(op.SPAUI{LoginMount: "/login"})
	b := op.WithUI(op.HTMLUI{Consent: op.PageTemplate{Template: tmpl}})

	t.Run("01 nil UI", func(t *testing.T) {
		t.Parallel()
		mustFail(t, "WithUI received nil UI", op.WithUI(nil))
	})
	t.Run("02 explicit twice", func(t *testing.T) {
		t.Parallel()
		mustFail(t, onceErr, a, b)
	})
	t.Run("03 default then explicit", func(t *testing.T) {
		t.Parallel()
		mustBuild(t, op.WithDefaults(a), b)
	})
	t.Run("04 default twice", func(t *testing.T) {
		t.Parallel()
		mustFail(t, onceErr, op.WithDefaults(a), op.WithDefaults(b))
	})
	t.Run("05 nil default then explicit", func(t *testing.T) {
		t.Parallel()
		mustBuild(t, op.WithDefaults(op.WithUI(nil)), b)
	})
	t.Run("06 empty HTMLUI", func(t *testing.T) {
		t.Parallel()
		mustBuild(t, op.WithUI(op.HTMLUI{}))
	})
	t.Run("07 CSP without Template", func(t *testing.T) {
		t.Parallel()
		mustFail(t, "WithUI: HTMLUI.Consent sets ContentSecurityPolicy without a Template",
			op.WithUI(op.HTMLUI{Consent: op.PageTemplate{ContentSecurityPolicy: "x"}}))
	})
	t.Run("08 Template with empty CSP", func(t *testing.T) {
		t.Parallel()
		mustBuild(t, op.WithUI(op.HTMLUI{
			Login:   op.PageTemplate{Template: tmpl},
			Consent: op.PageTemplate{Template: tmpl},
			Chooser: op.PageTemplate{Template: tmpl},
		}))
	})
	t.Run("09 invalid page CSP", func(t *testing.T) {
		t.Parallel()
		page := op.PageTemplate{Template: tmpl, ContentSecurityPolicy: badCSP}
		mustFail(t, "WithUI: HTMLUI.Login.ContentSecurityPolicy", op.WithUI(op.HTMLUI{Login: page}))
		mustFail(t, "WithUI: HTMLUI.Consent.ContentSecurityPolicy", op.WithUI(op.HTMLUI{Consent: page}))
		mustFail(t, "WithUI: HTMLUI.Chooser.ContentSecurityPolicy", op.WithUI(op.HTMLUI{Chooser: page}))
	})
	t.Run("10 SPAUI empty", func(t *testing.T) {
		t.Parallel()
		mustFail(t, "WithUI: SPAUI.LoginMount must not be empty", op.WithUI(op.SPAUI{}))
	})
	t.Run("11 SPAUI LoginMount without slash", func(t *testing.T) {
		t.Parallel()
		mustFail(t, `WithUI: SPAUI.LoginMount must start with "/"`, op.WithUI(op.SPAUI{LoginMount: "x"}))
	})
	t.Run("12 SPAUI StaticDir", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		missing := filepath.Join(dir, "missing")
		mustFail(t, "WithUI: SPAUI.StaticDir "+missing+" not accessible",
			op.WithUI(op.SPAUI{LoginMount: "/login", StaticDir: missing}))
		file := filepath.Join(dir, "file.txt")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		mustFail(t, "WithUI: SPAUI.StaticDir "+file+" is not a directory",
			op.WithUI(op.SPAUI{LoginMount: "/login", StaticDir: file}))
	})
	t.Run("13 SPAUI invalid CSP", func(t *testing.T) {
		t.Parallel()
		mustFail(t, "WithUI: SPAUI.ContentSecurityPolicy",
			op.WithUI(op.SPAUI{LoginMount: "/login", ContentSecurityPolicy: badCSP}))
	})
	t.Run("14 DriverUI nil driver", func(t *testing.T) {
		t.Parallel()
		mustFail(t, nilDrv, op.WithUI(op.DriverUI{}))
		var typedNil *recordingDriver
		mustFail(t, nilDrv, op.WithUI(op.DriverUI{Driver: typedNil}))
	})
	t.Run("15 overlay with nil Inner", func(t *testing.T) {
		t.Parallel()
		const want = "WithUI: DriverUI.Driver is a TemplateOverlayDriver with a nil Inner"
		overlay := interaction.TemplateOverlayDriver{ConsentTemplate: tmpl}
		mustFail(t, want, op.WithUI(op.DriverUI{Driver: overlay}))
		mustFail(t, want, op.WithUI(op.DriverUI{Driver: &overlay}))
	})
	t.Run("16 overlay with invalid CSP", func(t *testing.T) {
		t.Parallel()
		mustFail(t, "WithUI: DriverUI.Driver ConsentCSP", op.WithUI(op.DriverUI{Driver: interaction.TemplateOverlayDriver{
			Inner: scriptedDriver{}, ConsentCSP: badCSP,
		}}))
		mustFail(t, "WithUI: DriverUI.Driver ChooserCSP", op.WithUI(op.DriverUI{Driver: &interaction.TemplateOverlayDriver{
			Inner: scriptedDriver{}, ChooserCSP: badCSP,
		}}))
		mustFail(t, "WithUI: DriverUI.Driver LoginCSP", op.WithUI(op.DriverUI{Driver: interaction.TemplateOverlayDriver{
			Inner: scriptedDriver{}, LoginCSP: badCSP,
		}}))
	})
	t.Run("17 embedded variant", func(t *testing.T) {
		t.Parallel()
		mustBuild(t, op.WithUI(embeddedHTMLUI{op.HTMLUI{Consent: op.PageTemplate{Template: tmpl}}}))
		// Resolved as the embedded HTMLUI, so its validation runs.
		mustFail(t, "WithUI: HTMLUI.Consent sets ContentSecurityPolicy without a Template",
			op.WithUI(embeddedHTMLUI{op.HTMLUI{Consent: op.PageTemplate{ContentSecurityPolicy: "x"}}}))
	})
}
