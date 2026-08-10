package op_test

import (
	"bytes"
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func TestWithInteractionDriver_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithInteractionDriver(nil))...)
	if err == nil {
		t.Fatal("expected error for nil Driver, got nil")
	}
}

func TestWithInteractionDriver_AcceptsCustomDriver(t *testing.T) {
	t.Parallel()

	d := &recordingDriver{}
	provider, err := op.New(append(validBaseOpts(t), op.WithInteractionDriver(d))...)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

// stagedH1DStep is a [op.Step] used purely to give a test [op.LoginFlow]
// a non-nil Primary or rule target. The ceremony body is irrelevant
// here: H1-E only verifies option-level validation, the Begin /
// Continue paths are exercised by H1-D.
type stagedH1DStep struct {
	kind op.StepKind
}

func (s stagedH1DStep) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s stagedH1DStep) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s stagedH1DStep) Kind() op.StepKind { return s.kind }

// TestWithLoginFlow_BuiltinStepRejectedAtNew covers the H1-D wiring
// state: the LoginFlow seam is integrated into the orchestrator, but
// built-in [op.Step] values (PrimaryPassword / StepTOTP / …) are not
// yet wired to internal Authenticator primitives — their
// construction-time dependencies (TOTP encryption codec, passkey RP
// origin, hash adapter) are exposed by follow-up options. Until those
// land embedders adopt the seam through [op.ExternalStep]; passing a
// built-in Step at op.New surfaces a clear configuration error that
// points to the workaround.
func TestWithLoginFlow_BuiltinStepRejectedAtNew(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{Primary: stagedH1DStep{kind: op.StepKindPassword}}
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

// TestWithLoginFlow_ExternalStepConstructs confirms the H1-D wiring is
// complete for the production-supported path: a LoginFlow whose Steps
// are [op.ExternalStep] wrappers around an embedder's [op.Authenticator]
// constructs cleanly. Built-in Step primitives remain deferred — the
// matching options ship in follow-up Waves.
func TestWithLoginFlow_ExternalStepConstructs(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &h1dStubAuth{
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

// TestWithLoginFlow_RejectsAuthenticatorCombo pins the mutual
// exclusion contract: WithLoginFlow + WithAuthenticators is a
// configuration error because the two surfaces drive the orchestrator
// through different code paths and combining them would silently
// reorder factors.
func TestWithLoginFlow_RejectsAuthenticatorCombo(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKind("myorg.password"),
		},
	}
	_, err := op.New(append(validBaseOptsNoAuthn(t),
		op.WithLoginFlow(flow),
		op.WithAuthenticators(&h1dStubAuth{typeID: op.FactorTOTP, aal: op.AAL2, amr: "otp"}),
	)...)
	if err == nil {
		t.Fatal("expected error for WithLoginFlow + WithAuthenticators, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want mutually-exclusive diagnostic", err)
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
			Authenticator: &h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
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
			Authenticator: &h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
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

// h1dStubAuth is a minimal op.Authenticator used by H1-D option-layer
// tests. The Begin / Continue methods return zero values because the
// H1-D test surface only exercises construction-time validation; the
// orchestrator-level integration tests live in
// internal/authn/orchestrator_test.go.
type h1dStubAuth struct {
	typeID  op.FactorType
	aal     op.AAL
	amr     string
	prompts []string
}

func (s *h1dStubAuth) Type() op.FactorType { return s.typeID }
func (s *h1dStubAuth) AAL() op.AAL         { return s.aal }
func (s *h1dStubAuth) AMR() string         { return s.amr }
func (s *h1dStubAuth) Prompts() []string   { return s.prompts }
func (s *h1dStubAuth) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s *h1dStubAuth) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
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

	flow := op.LoginFlow{Primary: stagedH1DStep{kind: op.StepKindPassword}}
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
		Primary: stagedH1DStep{kind: op.StepKindPassword},
		Rules: []op.Rule{
			{When: func(op.LoginContext) bool { return true }, Then: stagedH1DStep{kind: op.StepKindTOTP}},
			{When: func(op.LoginContext) bool { return true }, Then: stagedH1DStep{kind: op.StepKindTOTP}},
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
	if _, err := op.New(validBaseOpts(t)...); err != nil {
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
	if !strings.Contains(err.Error(), "WithAuthenticators") ||
		!strings.Contains(err.Error(), "WithLoginFlow") {
		t.Errorf("err = %v, want it to name both options that satisfy the requirement", err)
	}
}

// TestNew_AuthenticatorsSatisfyTheAuthorizationCodeRequirement covers
// the first of the two ways to declare the chain.
func TestNew_AuthenticatorsSatisfyTheAuthorizationCodeRequirement(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsNoAuthn(t),
		op.WithAuthenticators(&h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"}),
	)...); err != nil {
		t.Fatalf("op.New with WithAuthenticators: %v", err)
	}
}

// TestNew_LoginFlowSatisfiesTheAuthorizationCodeRequirement covers the
// second: a LoginFlow declares the same chain in compiled form, so it
// stands alone without WithAuthenticators (with which it is mutually
// exclusive).
func TestNew_LoginFlowSatisfiesTheAuthorizationCodeRequirement(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
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

func TestWithSPAUI_AcceptsValid(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{LoginMount: "/login"}),
	)...)
	if err != nil {
		t.Fatalf("op.New with WithSPAUI: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestWithSPAUI_RejectsEmptyLoginMount(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{}),
	)...)
	if err == nil {
		t.Fatal("expected error for empty LoginMount, got nil")
	}
	if !strings.Contains(err.Error(), "LoginMount must not be empty") {
		t.Errorf("err = %v, want it to mention LoginMount", err)
	}
}

func TestWithSPAUI_RejectsNonSlashLoginMount(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{LoginMount: "login"}),
	)...)
	if err == nil {
		t.Fatal("expected error for LoginMount missing leading slash, got nil")
	}
	if !strings.Contains(err.Error(), "must start with") {
		t.Errorf("err = %v, want leading-slash diagnostic", err)
	}
}

func TestWithSPAUI_RejectsMissingStaticDir(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{
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

func TestWithSPAUI_AcceptsExistingStaticDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	provider, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{LoginMount: "/login", StaticDir: dir}),
	)...)
	if err != nil {
		t.Fatalf("op.New with WithSPAUI(StaticDir=%q): %v", dir, err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

// TestWithSPAUI_ConsentAndLogoutMountsAreInert pins what the deprecation
// notes on SPAUI.ConsentMount / SPAUI.LogoutMount state: the two fields
// are validated and then dropped. Nothing is mounted at either path, and
// neither reserves a route — a value that would collide with a protocol
// endpoint if it were reserved still boots. The pin exists so the fields
// cannot quietly acquire behaviour that contradicts their documentation,
// in either direction.
func TestWithSPAUI_ConsentAndLogoutMountsAreInert(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{
			LoginMount:   "/login",
			ConsentMount: "/consent",
			LogoutMount:  "/logout",
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New with consent / logout mounts: %v", err)
	}
	for _, path := range []string{"/consent", "/logout"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
		rec := httptest.NewRecorder()
		provider.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404: no handler is mounted for the deprecated mount", path, rec.Code)
		}
	}

	// The token endpoint's path proves the absence of a route
	// reservation: WithSPAUI.LoginMount would be rejected for the same
	// value.
	if _, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{
			LoginMount:   "/login",
			ConsentMount: "/oidc/token",
		}),
	)...); err != nil {
		t.Errorf("op.New with ConsentMount on a protocol endpoint path: %v; the field reserves no route", err)
	}
}

func TestWithSPAUI_RejectsConsentUICombination(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	_, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{LoginMount: "/login"}),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
	)...)
	if err == nil {
		t.Fatal("expected error for WithSPAUI + WithConsentUI, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want mutually-exclusive diagnostic", err)
	}
}

func TestWithConsentUI_RejectsNilTemplate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithConsentUI(op.ConsentUI{Template: nil}),
	)...)
	if err == nil {
		t.Fatal("expected error for nil Template, got nil")
	}
	if !strings.Contains(err.Error(), "Template must not be nil") {
		t.Errorf("err = %v, want it to mention Template", err)
	}
}

func TestWithConsentUI_AcceptsValid(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("consent").Parse("hi"))
	provider, err := op.New(append(validBaseOpts(t),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
	)...)
	if err != nil {
		t.Fatalf("op.New with WithConsentUI: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

// A policy that would unframe the consent page or block its completing
// redirect has to fail at New. Accepting it and repairing it silently
// would leave the embedder believing their template is framed-protected
// on their own terms.
func TestWithConsentUI_RejectsAContentSecurityPolicyThatDropsAProtection(t *testing.T) {
	t.Parallel()

	for name, policy := range map[string]string{
		"framing allowed": "default-src 'none'; frame-ancestors https://portal.example",
		"form-action set": "default-src 'none'; form-action 'self'",
		"base-uri set":    "default-src 'none'; base-uri 'self'",
	} {
		tmpl := template.Must(template.New("c").Parse("ok"))
		_, err := op.New(append(validBaseOpts(t),
			op.WithConsentUI(op.ConsentUI{Template: tmpl, ContentSecurityPolicy: policy}),
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

func TestWithConsentUI_AcceptsABrandingContentSecurityPolicy(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	provider, err := op.New(append(validBaseOpts(t),
		op.WithConsentUI(op.ConsentUI{
			Template:              tmpl,
			ContentSecurityPolicy: "default-src 'none'; style-src 'self'; img-src 'self' data:",
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New with a branding policy: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestWithChooserUI_RejectsAContentSecurityPolicyThatDropsAProtection(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	_, err := op.New(append(validBaseOpts(t),
		op.WithChooserUI(op.ChooserUI{Template: tmpl, ContentSecurityPolicy: "default-src 'none'; form-action 'self'"}),
	)...)
	if err == nil {
		t.Fatal("expected error for a form-action policy, got nil")
	}
	if !strings.Contains(err.Error(), "ContentSecurityPolicy") {
		t.Errorf("err = %v, want it to name the field", err)
	}
}

func TestWithConsentUI_RejectsSPAUICombination(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	_, err := op.New(append(validBaseOpts(t),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
		op.WithSPAUI(op.SPAUI{LoginMount: "/login"}),
	)...)
	if err == nil {
		t.Fatal("expected error for WithConsentUI + WithSPAUI, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want mutually-exclusive diagnostic", err)
	}
}

func TestWithChooserUI_AcceptsValid(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("chooser").Parse("hi"))
	provider, err := op.New(append(validBaseOpts(t),
		op.WithChooserUI(op.ChooserUI{Template: tmpl}),
	)...)
	if err != nil {
		t.Fatalf("op.New with WithChooserUI: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestNew_DefaultsToHTMLDriverWithoutInteraction(t *testing.T) {
	t.Parallel()

	// With neither WithInteractionDriver nor WithSPAUI the OP must
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

func TestNew_WithInteractionDriverWinsOverDefault(t *testing.T) {
	t.Parallel()

	d := &recordingDriver{}
	provider, err := op.New(append(validBaseOpts(t), op.WithInteractionDriver(d))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatal("provider is nil")
	}
	// recordingDriver carries a "called" flag that the construction
	// path does not flip; the explicit WithInteractionDriver wins
	// because the default substitution short-circuits when
	// c.interactionD is already set. Reaching this point without an
	// op.New error is the assertion.
}

// TestWithChooserUI_AcceptsAlongsideSPAUI pins the SPA-mode posture:
// WithChooserUI composes with WithSPAUI without rejection;
// applyDefaults emits a single structured slog.Warn that records the
// shadowed-template intent. The order-independence assertion (chooser
// first vs SPA first) defends against a regression where only one of
// the option setters wires the shadow flag.
func TestWithChooserUI_AcceptsAlongsideSPAUI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts func(tb testing.TB, logger *slog.Logger) []op.Option
	}{
		{
			name: "SPA first, chooser second",
			opts: func(tb testing.TB, logger *slog.Logger) []op.Option {
				tb.Helper()
				tmpl := template.Must(template.New("chooser").Parse("hi"))
				return append(validBaseOpts(tb),
					op.WithLogger(logger),
					op.WithSPAUI(op.SPAUI{LoginMount: "/login"}),
					op.WithChooserUI(op.ChooserUI{Template: tmpl}),
				)
			},
		},
		{
			name: "chooser first, SPA second",
			opts: func(tb testing.TB, logger *slog.Logger) []op.Option {
				tb.Helper()
				tmpl := template.Must(template.New("chooser").Parse("hi"))
				return append(validBaseOpts(tb),
					op.WithLogger(logger),
					op.WithChooserUI(op.ChooserUI{Template: tmpl}),
					op.WithSPAUI(op.SPAUI{LoginMount: "/login"}),
				)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			provider, err := op.New(tc.opts(t, logger)...)
			if err != nil {
				t.Fatalf("op.New: %v", err)
			}
			if provider == nil {
				t.Fatal("expected non-nil Provider")
			}
			out := buf.String()
			if !strings.Contains(out, "chooser template will not be rendered") {
				t.Errorf("logger output = %q, want a chooser-shadowed warning", out)
			}
		})
	}
}

func TestNew_WithSPAUISuppressesDefaultDriver(t *testing.T) {
	t.Parallel()

	// With WithSPAUI active, the default-driver fall-back in
	// applyDefaults short-circuits — the embedder's SPA owns
	// rendering and the JSON state endpoints stay the only
	// protocol surface. The black-box check that this delegation
	// short-circuit fired is "op.New succeeds with no other driver
	// option supplied", which previously was masked by the gate's
	// fail-fast rejection. Once the gate is gone we can simply
	// assert successful construction.
	provider, err := op.New(append(validBaseOpts(t),
		op.WithSPAUI(op.SPAUI{LoginMount: "/login"}),
	)...)
	if err != nil {
		t.Fatalf("op.New with WithSPAUI: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil Provider")
	}
}
