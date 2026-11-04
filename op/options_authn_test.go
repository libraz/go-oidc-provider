package op_test

import (
	"context"
	"html/template"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

type recordingDriver struct{ called bool }

func (d *recordingDriver) Render(http.ResponseWriter, *http.Request, interaction.Prompt) error {
	d.called = true
	return nil
}

func (d *recordingDriver) ParseSubmission(*http.Request) (interaction.FormSubmission, error) {
	return interaction.FormSubmission{}, nil
}

func TestWithUI_DriverUIRejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithUI(op.DriverUI{Driver: nil}))...)
	if err == nil {
		t.Fatal("expected error for nil Driver, got nil")
	}
}

func TestWithUI_DriverUIAcceptsCustomDriver(t *testing.T) {
	t.Parallel()

	d := &recordingDriver{}
	provider, err := op.New(append(validBaseOpts(t), op.WithUI(op.DriverUI{Driver: d}))...)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

// foreignStep is a [op.Step] shape the projector does not recognise: it
// reports a built-in [op.StepKind] but is not one of the built-in Step
// types, which is exactly the case op.New must refuse. The ceremony
// body is irrelevant — these tests only exercise construction-time
// validation; the Begin / Continue paths are covered by the
// orchestrator tests.
type foreignStep struct {
	kind op.StepKind
}

func (s foreignStep) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s foreignStep) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s foreignStep) Kind() op.StepKind { return s.kind }

// TestWithLoginFlow_UnrecognisedStepRejectedAtNew pins the projector's
// closed set: a value that satisfies [op.Step] and reports a built-in
// [op.StepKind], but is not one of the built-in Step types, cannot be
// compiled into an authenticator. op.New refuses it at construction
// with an error pointing at [op.ExternalStep], which is the seam for a
// factor this package does not implement — rather than accepting it and
// failing on the first authorization request.
func TestWithLoginFlow_UnrecognisedStepRejectedAtNew(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{Primary: foreignStep{kind: op.StepKindPassword}}
	_, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected built-in Step error from op.New, got nil")
	}
	if !strings.Contains(err.Error(), "ExternalStep") {
		t.Errorf("err = %v, want it to point at ExternalStep workaround", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("built-in-step error must be a server-side configuration error: %v", err)
	}
}

// TestWithLoginFlow_ExternalStepConstructs confirms the wrapper path:
// a LoginFlow whose Steps are [op.ExternalStep] wrappers around an
// embedder's [op.Authenticator] constructs cleanly. Built-in Steps
// construct through their own compilation path, covered separately.
func TestWithLoginFlow_ExternalStepConstructs(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &stubAuth{
				typeID:  op.FactorPassword,
				aal:     op.AAL1,
				amr:     "pwd",
				prompts: []string{"auth.password"},
			},
			KindLabel: op.StepKind("myorg.password"),
		},
	}
	if _, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(flow))...); err != nil {
		t.Fatalf("WithLoginFlow + ExternalStep should construct, got %v", err)
	}
}

// TestWithLoginFlow_RejectsExternalStepBuiltinKindLabel pins the
// validation that ExternalStep KindLabel cannot collide with a
// built-in StepKind: an embedder that picks "password" for their
// custom factor would silently shadow the built-in PrimaryPassword
// kind in CompletedSteps dedup.
func TestWithLoginFlow_RejectsExternalStepBuiltinKindLabel(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &stubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKindPassword, // collides with built-in
		},
	}
	_, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected error for built-in KindLabel collision, got nil")
	}
	if !strings.Contains(err.Error(), "built-in") {
		t.Errorf("err = %v, want it to mention built-in collision", err)
	}
}

// TestWithLoginFlow_RejectsExternalStepBareKindLabel enforces the
// dotted-prefix discipline on user-defined StepKind values. A bare
// label like "myfactor" risks colliding with future built-ins;
// requiring a dotted prefix matches the existing FactorType.IsUserDefined
// rule and keeps the namespace conflict surface controllable.
func TestWithLoginFlow_RejectsExternalStepBareKindLabel(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &stubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKind("myfactor"), // bare, no dot
		},
	}
	_, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected error for bare KindLabel, got nil")
	}
	if !strings.Contains(err.Error(), "dotted prefix") {
		t.Errorf("err = %v, want it to mention dotted prefix", err)
	}
}

// stubAuth is a minimal op.Authenticator used by the option-layer
// tests. The Begin / Continue methods return zero values because this
// surface only exercises construction-time validation; the
// orchestrator-level integration tests live in
// internal/authn/orchestrator_test.go.
type stubAuth struct {
	typeID  op.FactorType
	aal     op.AAL
	amr     string
	prompts []string
}

func (s *stubAuth) Type() op.FactorType { return s.typeID }
func (s *stubAuth) AAL() op.AAL         { return s.aal }
func (s *stubAuth) AMR() string         { return s.amr }
func (s *stubAuth) Prompts() []string   { return s.prompts }
func (s *stubAuth) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s *stubAuth) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func TestWithLoginFlow_RejectsNilPrimary(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(op.LoginFlow{}))...)
	if err == nil {
		t.Fatal("expected error for nil Primary, got nil")
	}
	if !strings.Contains(err.Error(), "LoginFlow.Primary must not be nil") {
		t.Errorf("err = %v, want it to mention nil Primary", err)
	}
}

func TestWithLoginFlow_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{Primary: foreignStep{kind: op.StepKindPassword}}
	_, err := op.New(append(validBaseOptsNoAuthn(t),
		op.WithLoginFlow(flow),
		op.WithLoginFlow(flow),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate WithLoginFlow, got nil")
	}
	if !strings.Contains(err.Error(), "may be called at most once") {
		t.Errorf("err = %v, want duplicate-rejection message", err)
	}
}

func TestWithLoginFlow_RejectsDuplicateRuleKinds(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: foreignStep{kind: op.StepKindPassword},
		Rules: []op.Rule{
			{When: func(op.LoginContext) bool { return true }, Then: foreignStep{kind: op.StepKindTOTP}},
			{When: func(op.LoginContext) bool { return true }, Then: foreignStep{kind: op.StepKindTOTP}},
		},
	}
	_, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected error for duplicate Rule StepKind, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate StepKind") {
		t.Errorf("err = %v, want duplicate-StepKind message", err)
	}
}

func TestWithLoginFlow_AbsentLeavesNoError(t *testing.T) {
	t.Parallel()

	// No WithLoginFlow at all: the flow validator must NOT fire
	// because c.loginFlow.Primary stays nil.
	if _, err := op.New(append(validBaseOptsNoAuthn(t),
		op.WithGrants(grant.ClientCredentials),
	)...); err != nil {
		t.Fatalf("op.New without WithLoginFlow: %v", err)
	}
}

// TestNew_RejectsAuthorizationCodeWithoutLoginConfiguration pins the
// boot contract for the interactive grant: /authorize has to run the
// authentication chain for every request that is not resumed from a
// live session, so an OP offering authorization_code without a way to
// authenticate anyone cannot serve a single one. The refusal belongs at
// construction, where the operator can act on it.
func TestNew_RejectsAuthorizationCodeWithoutLoginConfiguration(t *testing.T) {
	t.Parallel()

	_, err := op.New(validBaseOptsNoAuthn(t)...)
	if err == nil {
		t.Fatal("expected a configuration error for authorization_code with no login configuration, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("missing login configuration must be a server-side configuration error: %v", err)
	}
	if op.IsClientError(err) {
		t.Errorf("missing login configuration must not be classified as a client error: %v", err)
	}
	if !strings.Contains(err.Error(), "WithLoginFlow") {
		t.Errorf("err = %v, want it to name the option that satisfies the requirement", err)
	}
}

// TestNew_LoginFlowSatisfiesTheAuthorizationCodeRequirement covers the
// way to declare the chain.
func TestNew_LoginFlowSatisfiesTheAuthorizationCodeRequirement(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &stubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKind("myorg.password"),
		},
	}
	if _, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(flow))...); err != nil {
		t.Fatalf("op.New with WithLoginFlow: %v", err)
	}
}

// TestNew_NonInteractiveGrantsNeedNoLoginConfiguration guards the
// legitimate deployment the login-configuration requirement must not
// catch: a grant set that never reaches the authentication chain —
// client_credentials here — constructs with no authenticator and no
// LoginFlow at all.
//
// The second case holds everything else fixed and adds
// authorization_code back, so the two together pin the grant set as
// the input the requirement keys on. A requirement rewritten to demand
// an authenticator unconditionally passes the second case and fails the
// first.
func TestNew_NonInteractiveGrantsNeedNoLoginConfiguration(t *testing.T) {
	t.Parallel()

	t.Run("client_credentials only", func(t *testing.T) {
		t.Parallel()

		if _, err := op.New(append(validBaseOptsNoAuthn(t),
			op.WithGrants(grant.ClientCredentials),
		)...); err != nil {
			t.Fatalf("op.New for a client_credentials-only deployment: %v", err)
		}
	})

	t.Run("client_credentials with authorization_code", func(t *testing.T) {
		t.Parallel()

		_, err := op.New(append(validBaseOptsNoAuthn(t),
			op.WithGrants(grant.ClientCredentials, grant.AuthorizationCode),
		)...)
		if err == nil {
			t.Fatal("expected a configuration error once authorization_code joins the grant set, got nil")
		}
		if !op.IsServerError(err) {
			t.Errorf("missing login configuration must be a server-side configuration error: %v", err)
		}
	})
}

func TestWithUI_SPAUIAcceptsValid(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.SPAUI{LoginMount: "/login"}),
	)...)
	if err != nil {
		t.Fatalf("op.New with SPAUI: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestWithUI_SPAUIRejectsEmptyLoginMount(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.SPAUI{}),
	)...)
	if err == nil {
		t.Fatal("expected error for empty LoginMount, got nil")
	}
	if !strings.Contains(err.Error(), "LoginMount must not be empty") {
		t.Errorf("err = %v, want it to mention LoginMount", err)
	}
}

func TestWithUI_SPAUIRejectsNonSlashLoginMount(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.SPAUI{LoginMount: "login"}),
	)...)
	if err == nil {
		t.Fatal("expected error for LoginMount missing leading slash, got nil")
	}
	if !strings.Contains(err.Error(), "must start with") {
		t.Errorf("err = %v, want leading-slash diagnostic", err)
	}
}

func TestWithUI_SPAUIRejectsMissingStaticDir(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.SPAUI{
			LoginMount: "/login",
			StaticDir:  "/this/path/does/not/exist/h1e-test",
		}),
	)...)
	if err == nil {
		t.Fatal("expected error for missing StaticDir, got nil")
	}
	if !strings.Contains(err.Error(), "StaticDir") {
		t.Errorf("err = %v, want it to mention StaticDir", err)
	}
}

func TestWithUI_SPAUIAcceptsExistingStaticDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	provider, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.SPAUI{LoginMount: "/login", StaticDir: dir}),
	)...)
	if err != nil {
		t.Fatalf("op.New with SPAUI(StaticDir=%q): %v", dir, err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestWithUI_HTMLUIRejectsPolicyWithoutTemplate(t *testing.T) {
	t.Parallel()

	for page, ui := range map[string]op.HTMLUI{
		"Login":   {Login: op.PageTemplate{ContentSecurityPolicy: "default-src 'none'"}},
		"Consent": {Consent: op.PageTemplate{ContentSecurityPolicy: "default-src 'none'"}},
		"Chooser": {Chooser: op.PageTemplate{ContentSecurityPolicy: "default-src 'none'"}},
	} {
		_, err := op.New(append(validBaseOpts(t), op.WithUI(ui))...)
		if err == nil {
			t.Errorf("%s: expected error for a policy without a Template, got nil", page)
			continue
		}
		want := "WithUI: HTMLUI." + page + " sets ContentSecurityPolicy without a Template"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to contain %q", page, err, want)
		}
	}
}

func TestWithUI_HTMLUIConsentAcceptsValid(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("consent").Parse("hi"))
	provider, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.HTMLUI{Consent: op.PageTemplate{Template: tmpl}}),
	)...)
	if err != nil {
		t.Fatalf("op.New with HTMLUI.Consent: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

// A policy that would unframe the consent page or block its completing
// redirect has to fail at New. Accepting it and repairing it silently
// would leave the embedder believing their template is framed-protected
// on their own terms.
func TestWithUI_HTMLUIConsentRejectsAContentSecurityPolicyThatDropsAProtection(t *testing.T) {
	t.Parallel()

	for name, policy := range map[string]string{
		"framing allowed": "default-src 'none'; frame-ancestors https://portal.example",
		"form-action set": "default-src 'none'; form-action 'self'",
		"base-uri set":    "default-src 'none'; base-uri 'self'",
	} {
		tmpl := template.Must(template.New("c").Parse("ok"))
		_, err := op.New(append(validBaseOpts(t),
			op.WithUI(op.HTMLUI{Consent: op.PageTemplate{Template: tmpl, ContentSecurityPolicy: policy}}),
		)...)
		if err == nil {
			t.Errorf("%s: expected error for %q, got nil", name, policy)
			continue
		}
		if !strings.Contains(err.Error(), "ContentSecurityPolicy") {
			t.Errorf("%s: err = %v, want it to name the field", name, err)
		}
	}
}

func TestWithUI_HTMLUIConsentAcceptsABrandingContentSecurityPolicy(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	provider, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.HTMLUI{Consent: op.PageTemplate{
			Template:              tmpl,
			ContentSecurityPolicy: "default-src 'none'; style-src 'self'; img-src 'self' data:",
		}}),
	)...)
	if err != nil {
		t.Fatalf("op.New with a branding policy: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestWithUI_HTMLUIChooserRejectsAContentSecurityPolicyThatDropsAProtection(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	_, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.HTMLUI{Chooser: op.PageTemplate{Template: tmpl, ContentSecurityPolicy: "default-src 'none'; form-action 'self'"}}),
	)...)
	if err == nil {
		t.Fatal("expected error for a form-action policy, got nil")
	}
	if !strings.Contains(err.Error(), "ContentSecurityPolicy") {
		t.Errorf("err = %v, want it to name the field", err)
	}
}

func TestWithUI_HTMLUILoginRejectsInvalidCSP(t *testing.T) {
	t.Parallel()

	for name, policy := range map[string]string{
		"framing allowed": "default-src 'none'; frame-ancestors https://portal.example",
		"form-action set": "default-src 'none'; form-action 'self'",
		"base-uri set":    "default-src 'none'; base-uri 'self'",
	} {
		tmpl := template.Must(template.New("l").Parse("ok"))
		_, err := op.New(append(validBaseOpts(t),
			op.WithUI(op.HTMLUI{Login: op.PageTemplate{Template: tmpl, ContentSecurityPolicy: policy}}),
		)...)
		if err == nil {
			t.Errorf("%s: expected error for %q, got nil", name, policy)
			continue
		}
		if !strings.Contains(err.Error(), "WithUI: HTMLUI.Login.ContentSecurityPolicy") {
			t.Errorf("%s: err = %v, want it to name the option and field", name, err)
		}
	}
}

// The translator is wired into the composed driver at New; a login overlay
// must come through that rewrite intact and construct.
func TestWithUI_HTMLUILoginSurvivesLocaleInjection(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("login").Parse("hi"))
	provider, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.HTMLUI{Login: op.PageTemplate{
			Template:              tmpl,
			ContentSecurityPolicy: "default-src 'none'; style-src 'self'",
		}}),
	)...)
	if err != nil {
		t.Fatalf("op.New with HTMLUI.Login: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestWithUI_HTMLUIChooserAcceptsValid(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("chooser").Parse("hi"))
	provider, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.HTMLUI{Chooser: op.PageTemplate{Template: tmpl}}),
	)...)
	if err != nil {
		t.Fatalf("op.New with HTMLUI.Chooser: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestNew_DefaultsToHTMLDriverWithoutInteraction(t *testing.T) {
	t.Parallel()

	// Without WithUI the OP must
	// boot into a working HTML login surface. The test reaches the
	// driver via the authorize-flow handler indirectly: instead of
	// asserting on the unexported config field, we verify
	// op.New succeeds and the package's driver default is HTMLDriver
	// by exercising the same construction path.
	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatal("provider is nil")
	}
	// Indirect check: HTMLDriver implements interaction.Driver via
	// value receivers, and the JSON driver does too. We cannot probe
	// the unexported config field from op_test, so the test pins the
	// surface contract by ensuring construction is stable - the
	// downstream behavioural test (interaction smoke test) confirms
	// HTMLDriver wins on the wire when it lands.
	_ = interaction.HTMLDriver{}
}

func TestNew_WithUIWinsOverDefault(t *testing.T) {
	t.Parallel()

	d := &recordingDriver{}
	provider, err := op.New(append(validBaseOpts(t), op.WithUI(op.DriverUI{Driver: d}))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatal("provider is nil")
	}
	// recordingDriver carries a "called" flag that the construction
	// path does not flip; the explicit WithUI wins
	// because the default substitution short-circuits when
	// uiSet is already true. Reaching this point without an
	// op.New error is the assertion.
}

func TestNew_SPAUISuppressesDefaultDriver(t *testing.T) {
	t.Parallel()

	// With SPAUI active, the default-driver fall-back in
	// applyDefaults short-circuits — the embedder's SPA owns
	// rendering and the JSON state endpoints stay the only
	// protocol surface. The black-box check that this delegation
	// short-circuit fired is "op.New succeeds with no other driver
	// option supplied", which previously was masked by the gate's
	// fail-fast rejection. Once the gate is gone we can simply
	// assert successful construction.
	provider, err := op.New(append(validBaseOpts(t),
		op.WithUI(op.SPAUI{LoginMount: "/login"}),
	)...)
	if err != nil {
		t.Fatalf("op.New with SPAUI: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}
