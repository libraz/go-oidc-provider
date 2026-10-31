package authorizeendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	// registerPromptType is the prompt the Registration step emits; a
	// first prompt of any other type means Primary ran instead.
	registerPromptType = "auth.test.register"
	// registerFieldName carries the subject the registration creates.
	registerFieldName = "new_subject"
	// promptCreateSubject is the account the Registration step creates.
	promptCreateSubject = "user-registered"
)

// registrationEcho is a test-only Registration authenticator: it binds
// the subject the submission names, standing in for an embedder that
// creates the account. AuthTime is stamped from the fixture clock so the
// id_token's auth_time can be told apart from the session's.
type registrationEcho struct {
	clock *movableClock
}

func (registrationEcho) Type() op.FactorType { return op.FactorPassword }
func (registrationEcho) AAL() op.AAL         { return op.AAL1 }
func (registrationEcho) AMR() string         { return "pwd" }
func (registrationEcho) Prompts() []string   { return []string{registerPromptType} }

func (registrationEcho) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: registerPromptType,
		Inputs: []interaction.FieldSpec{{
			Name:     registerFieldName,
			Kind:     interaction.FieldText,
			Required: true,
			MinLen:   1,
			MaxLen:   256,
		}},
	}}, nil
}

func (a registrationEcho) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	sub := in.Submission.Values[registerFieldName]
	if sub == "" {
		return interaction.Step{}, testkit.ErrSubjectMissing
	}
	return interaction.Step{Result: &interaction.Result{Subject: sub, AuthTime: a.clock.Now()}}, nil
}

var _ op.Authenticator = registrationEcho{}

// newPromptCreateDriver builds a Provider whose LoginFlow has the
// credential factor as Primary and, when withRegistration is set, a
// Registration step. It goes through op.New because testkit.NewProvider
// pre-installs its own LoginFlow.
func newPromptCreateDriver(t *testing.T, withRegistration bool) *reauthDriver {
	t.Helper()
	clock := newMovableClock(time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC))
	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: passwordEchoAuthenticator{clock: clock},
			KindLabel:     op.StepKind("test.primary"),
		},
	}
	if withRegistration {
		flow.Registration = op.ExternalStep{
			Authenticator: registrationEcho{clock: clock},
			KindLabel:     op.StepKind("test.register"),
		}
	}
	d := newReauthDriver(t, buildFlowFixture(t, "LoginFlow+Registration", clock, op.WithLoginFlow(flow)))
	// The token endpoint looks the subject up; the account the
	// Registration step reports as created has to exist there.
	d.fix.store.PutUser(context.Background(), &store.User{Subject: promptCreateSubject})
	return d
}

// register answers the Registration prompt at path with
// promptCreateSubject, approves consent when it is shown, and returns the
// RP redirect, whether consent was shown, and the submission time.
func register(d *reauthDriver, path string) (*url.URL, bool, time.Time) {
	d.t.Helper()
	env, csrf := d.firstPrompt(path)
	if got, _ := env["type"].(string); got != registerPromptType {
		d.t.Fatalf("first prompt type=%q want %q (Registration did not run)", got, registerPromptType)
	}
	stateRef, _ := env["state_ref"].(string)
	d.fix.clock.Advance(5 * time.Minute)
	submitted := d.fix.clock.Now()
	resp := d.submit(path, csrf, stateRef, map[string]string{registerFieldName: promptCreateSubject})
	defer resp.Body.Close()

	consent, consentEnv, err := testkit.IsConsentPrompt(resp)
	if err != nil {
		d.t.Fatalf("inspect consent prompt: %v", err)
	}
	final := resp
	if consent {
		if rotated := findCookie(resp.Cookies(), "__Host-oidc_csrf"); rotated != nil {
			csrf = rotated.Value
		}
		ref, _ := consentEnv["state_ref"].(string)
		final = testkit.PostConsentApproval(d.t, d.cl, d.fix.server.URL+path, d.fix.issuer,
			csrf, ref, approvedScopesFromPrompt(consentEnv))
		defer final.Body.Close()
	}
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		d.t.Fatalf("interaction final status=%d body=%s", final.StatusCode, dump)
	}
	loc, err := final.Location()
	if err != nil {
		d.t.Fatalf("final Location: %v", err)
	}
	return loc, consent, submitted
}

// assertRegistered redeems the code on redirect and checks the id_token
// names the registered subject with the registration's auth_time.
func assertRegistered(t *testing.T, d *reauthDriver, redirect *url.URL, submitted time.Time) {
	t.Helper()
	claims := d.exchange(d.codeFrom(redirect))
	if got, _ := claims["sub"].(string); got != promptCreateSubject {
		t.Errorf("id_token sub=%q want %q", got, promptCreateSubject)
	}
	if got, _ := claims["auth_time"].(float64); int64(got) != submitted.Unix() {
		t.Errorf("id_token auth_time=%d want %d (the registration submission)", int64(got), submitted.Unix())
	}
}

// assertAuthorizeError checks redirect is the RP callback carrying
// invalid_request with description and no code.
func assertAuthorizeError(t *testing.T, d *reauthDriver, redirect *url.URL, description string) {
	t.Helper()
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != d.fix.client.RedirectURIs[0] {
		t.Fatalf("redirect target=%q want the RP callback %q", got, d.fix.client.RedirectURIs[0])
	}
	q := redirect.Query()
	if got := q.Get("error"); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (redirect: %s)", got, redirect)
	}
	if got := q.Get("error_description"); got != description {
		t.Errorf("error_description=%q want %q", got, description)
	}
	if got := q.Get("code"); got != "" {
		t.Errorf("code=%q want none", got)
	}
}

// TestPromptCreate_NoSessionRunsRegistration pins the plain path:
// prompt=create without a session runs Registration rather than Primary,
// consent follows, and the code is issued for the registered subject.
func TestPromptCreate_NoSessionRunsRegistration(t *testing.T) {
	t.Parallel()
	d := newPromptCreateDriver(t, true)

	loc := d.authorize(url.Values{"prompt": {interaction.PromptCreate}})
	if loc.Query().Get("code") != "" {
		t.Fatalf("prompt=create produced a code without an interaction: %s", loc)
	}
	redirect, consent, submitted := register(d, loc.Path)
	if !consent {
		t.Error("consent screen was not shown for the registered subject")
	}
	assertRegistered(t, d, redirect, submitted)
}

// TestPromptCreate_LiveSessionWithCoveringGrantRegistersNewSubject pins
// that neither the session's subject nor its grant carries over: with a
// session whose subject already holds a grant covering the request,
// prompt=create still runs Registration, shows consent for the new
// subject, and issues the code for it. Pre-marking consent from the old
// subject's grant would instead fail the authorization at the terminal
// consent gate.
func TestPromptCreate_LiveSessionWithCoveringGrantRegistersNewSubject(t *testing.T) {
	t.Parallel()
	d := newPromptCreateDriver(t, true)

	loc1 := d.authorize(nil)
	claims1 := d.exchange(d.codeFrom(d.completeCredentialLogin(loc1.Path, 0)))
	if got, _ := claims1["sub"].(string); got != reauthSubject {
		t.Fatalf("pass 1 sub=%q want %q", got, reauthSubject)
	}
	// Control: the session and its grant serve the request silently, so
	// the prompt=create pass below starts from a covering grant.
	if ctl := d.authorize(nil); ctl.Query().Get("code") == "" {
		t.Fatalf("control request was not served from the session: %s", ctl)
	}

	d.fix.clock.Advance(30 * time.Minute)
	loc2 := d.authorize(url.Values{"prompt": {interaction.PromptCreate}})
	if loc2.Query().Get("code") != "" {
		t.Fatalf("prompt=create was served from the session: %s", loc2)
	}
	redirect, consent, submitted := register(d, loc2.Path)
	if !consent {
		t.Error("consent screen was not shown for the registered subject; the old subject's grant stood in")
	}
	assertRegistered(t, d, redirect, submitted)
}

// TestPromptCreate_WithoutRegistrationIsInvalidRequest pins that an OP
// whose LoginFlow declares no Registration refuses prompt=create as an
// unrecognised value.
func TestPromptCreate_WithoutRegistrationIsInvalidRequest(t *testing.T) {
	t.Parallel()
	d := newPromptCreateDriver(t, false)

	loc := d.authorize(url.Values{"prompt": {interaction.PromptCreate}})
	assertAuthorizeError(t, d, loc, "prompt contains an unrecognised value")
}

// TestPromptCreate_CombinedWithLoginIsInvalidRequest pins that
// prompt=create combined with another value is refused even when
// Registration is configured.
func TestPromptCreate_CombinedWithLoginIsInvalidRequest(t *testing.T) {
	t.Parallel()
	d := newPromptCreateDriver(t, true)

	loc := d.authorize(url.Values{"prompt": {interaction.PromptCreate + " " + interaction.PromptLogin}})
	assertAuthorizeError(t, d, loc, "prompt=create cannot combine with other prompts")
}
