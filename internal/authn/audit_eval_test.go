package authn_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	opaudit "github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// These tests pin the OP-wide audit stream the orchestrator feeds for
// every resolved factor. The stream is what a Prometheus registry and an
// embedder's SOC sink see: a catalogue name that no code path emits is a
// permanently-zero series and an alert that never arrives, so the
// assertions below are about emission itself as much as about content.

// recordingAuditEmitter collects every audit record for later
// assertions. It mirrors [recordingObserver] — the orchestrator fans out
// to both feeds from the same call sites, and several tests below assert
// on the two side by side.
type recordingAuditEmitter struct {
	mu     sync.Mutex
	events []opaudit.Event
}

func (r *recordingAuditEmitter) Emit(_ context.Context, ev opaudit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingAuditEmitter) snapshot() []opaudit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]opaudit.Event, len(r.events))
	copy(out, r.events)
	return out
}

// wantAuditEvent is the expected shape of one emitted record.
type wantAuditEvent struct {
	name   auditevent.Name
	level  opaudit.Level
	actor  string
	factor op.FactorType
}

// assertAuditEvents compares the emitted stream against want in order.
// The comparison is exhaustive on count: "exactly one event per resolved
// factor" is the invariant that makes the login-attempt metric meaningful,
// so an extra record is as much a failure as a missing one.
func assertAuditEvents(t *testing.T, got []opaudit.Event, want []wantAuditEvent) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("audit events = %s, want %s (one event per resolved factor)",
			describeAuditEvents(got), describeWantAuditEvents(want))
	}
	for i, w := range want {
		ev := got[i]
		if ev.Name != string(w.name) {
			t.Errorf("event %d: Name = %q, want %q", i, ev.Name, w.name)
		}
		if ev.Level != w.level {
			t.Errorf("event %d (%s): Level = %v, want %v", i, ev.Name, ev.Level, w.level)
		}
		if ev.ActorID != w.actor {
			t.Errorf("event %d (%s): ActorID = %q, want %q", i, ev.Name, ev.ActorID, w.actor)
		}
		if ev.ClientID != initialState().ClientID {
			t.Errorf("event %d (%s): ClientID = %q, want %q", i, ev.Name, ev.ClientID, initialState().ClientID)
		}
		if got, ok := ev.Extras["factor"].(string); !ok || got != string(w.factor) {
			t.Errorf("event %d (%s): Extras[factor] = %v, want %q", i, ev.Name, ev.Extras["factor"], w.factor)
		}
	}
}

// describeAuditEvents renders the emitted stream as name/factor pairs so
// a count mismatch reports what actually fired rather than a bare number.
func describeAuditEvents(events []opaudit.Event) string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, fmt.Sprintf("%s(%v)", ev.Name, ev.Extras["factor"]))
	}
	return "[" + strings.Join(out, " ") + "]"
}

// describeWantAuditEvents renders the expectation in the same shape as
// [describeAuditEvents].
func describeWantAuditEvents(want []wantAuditEvent) string {
	out := make([]string, 0, len(want))
	for _, w := range want {
		out = append(out, fmt.Sprintf("%s(%s)", w.name, w.factor))
	}
	return "[" + strings.Join(out, " ") + "]"
}

// retryError builds the ErrFactorRetry-wrapping sentinel the credential
// adapters return on a wrong guess.
func retryError(factor op.FactorType) error {
	return fmt.Errorf("%s: rejected: %w", factor, authn.ErrFactorRetry)
}

// failingAuthenticator emits a prompt on Begin and rejects every
// submission with a soft credential failure.
func failingAuthenticator(typeID op.FactorType, aal op.AAL, amr string) *stubAuthenticator {
	prompt := promptForFactor(typeID)
	return &stubAuthenticator{
		typeID:  typeID,
		aal:     aal,
		amr:     amr,
		prompts: []string{prompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &prompt}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{}, retryError(typeID)
		},
	}
}

// TestAuditAttemptLegacyChainPrimaryFactor pins the primary-factor
// vocabulary on the Config.Authenticators path: the first factor to
// resolve is reported as login.success / login.failed, never under the
// mfa.* names.
func TestAuditAttemptLegacyChainPrimaryFactor(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		emitter := &recordingAuditEmitter{}
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")},
			AuditEmitter:   emitter,
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		if _, _, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "hunter2"}},
			Now:        fakeNow(),
		}); err != nil {
			t.Fatalf("second Tick: %v", err)
		}

		assertAuditEvents(t, emitter.snapshot(), []wantAuditEvent{
			{name: auditevent.AuditLoginSuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorPassword},
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()

		emitter := &recordingAuditEmitter{}
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{failingAuthenticator(op.FactorPassword, op.AAL1, "pwd")},
			AuditEmitter:   emitter,
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		// Identifier-first deployments bind the subject before the
		// credential factor runs, which is what gives a failed primary
		// attempt an actor to record.
		state := initialState()
		state.Subject = "user-1"

		st, step, err := o.Tick(context.Background(), state, authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		if _, _, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "wrong"}},
			Now:        fakeNow(),
		}); err != nil {
			t.Fatalf("second Tick: %v", err)
		}

		assertAuditEvents(t, emitter.snapshot(), []wantAuditEvent{
			{name: auditevent.AuditLoginFailed, level: opaudit.LevelWarn, actor: "user-1", factor: op.FactorPassword},
		})
	})
}

// TestAuditAttemptLegacyChainAdditionalFactor pins the mfa.* vocabulary
// on the Config.Authenticators path. The primary/additional distinction
// is read off State.Factors, so a chain resumed with a factor already
// recorded reports its next outcome as an additional factor. Both
// outcomes are covered because the two call sites read the count at
// deliberately different moments — the success path after the factor is
// appended, the failure path before.
func TestAuditAttemptLegacyChainAdditionalFactor(t *testing.T) {
	t.Parallel()

	// resumedState is a chain that already recorded a password factor
	// and is now running a second one.
	resumedState := func() authn.State {
		st := initialState()
		st.Subject = "user-1"
		st.Factors = []authn.Factor{{Type: op.FactorPassword, AssuranceLevel: op.AAL1}}
		return st
	}

	for _, tc := range []struct {
		name string
		auth *stubAuthenticator
		want wantAuditEvent
	}{
		{
			name: "success",
			auth: buildSuccessAuthenticator(op.FactorTOTP, op.AAL2, "otp"),
			want: wantAuditEvent{name: auditevent.AuditMFASuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorTOTP},
		},
		{
			name: "failure",
			auth: failingAuthenticator(op.FactorTOTP, op.AAL2, "otp"),
			want: wantAuditEvent{name: auditevent.AuditMFAFailed, level: opaudit.LevelWarn, actor: "user-1", factor: op.FactorTOTP},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			emitter := &recordingAuditEmitter{}
			o, err := authn.New(authn.Config{
				Authenticators: []op.Authenticator{tc.auth},
				AuditEmitter:   emitter,
				StateRefSigner: newSigner(t),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			st, step, err := o.Tick(context.Background(), resumedState(), authn.Input{Now: fakeNow()})
			if err != nil {
				t.Fatalf("first Tick: %v", err)
			}
			if _, _, err = o.Tick(context.Background(), st, authn.Input{
				Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
				Now:        fakeNow(),
			}); err != nil {
				t.Fatalf("second Tick: %v", err)
			}

			assertAuditEvents(t, emitter.snapshot(), []wantAuditEvent{tc.want})
		})
	}
}

// TestAuditAttemptLegacyChainImmediateResult covers the third
// observeSuccess call site on the legacy path: an authenticator whose
// Begin resolves without ever emitting a prompt (a silent re-auth from a
// still-valid device binding, say) is dispatched from the chain advance
// rather than from a submission, and MUST still be recorded.
func TestAuditAttemptLegacyChainImmediateResult(t *testing.T) {
	t.Parallel()

	silent := &stubAuthenticator{
		typeID:  op.FactorPasskey,
		aal:     op.AAL2,
		amr:     "hwk",
		prompts: []string{"auth.passkey"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow(), UserVerified: true}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{}, retryError(op.FactorPasskey)
		},
	}
	emitter := &recordingAuditEmitter{}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{silent},
		AuditEmitter:   emitter,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := initialState()
	state.Subject = "user-1"
	_, step, err := o.Tick(context.Background(), state, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}

	assertAuditEvents(t, emitter.snapshot(), []wantAuditEvent{
		{name: auditevent.AuditLoginSuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorPasskey},
	})
}

// TestAuditAttemptLoginFlowChain pins the same vocabulary on the
// Config.LoginFlow path, which reaches the emitter through its own
// success / failure call sites. A regression that only unwired one of
// the two chain implementations would leave the other green, so the
// primary-then-additional sequence is driven end to end here as well as
// on the legacy chain.
func TestAuditAttemptLoginFlowChain(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		second *stubAuthenticator
		want   []wantAuditEvent
	}{
		{
			name:   "additional-success",
			second: successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1"),
			want: []wantAuditEvent{
				{name: auditevent.AuditLoginSuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorPassword},
				{name: auditevent.AuditMFASuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorTOTP},
			},
		},
		{
			name:   "additional-failure",
			second: failingAuthenticator(op.FactorTOTP, op.AAL2, "otp"),
			want: []wantAuditEvent{
				{name: auditevent.AuditLoginSuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorPassword},
				{name: auditevent.AuditMFAFailed, level: opaudit.LevelWarn, actor: "user-1", factor: op.FactorTOTP},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			emitter := &recordingAuditEmitter{}
			flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
				Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
				Rules: []authn.LoginFlowRule{{
					When: func(authn.LoginFlowContext) bool { return true },
					Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: tc.second},
				}},
			})
			if err != nil {
				t.Fatalf("CompileLoginFlow: %v", err)
			}
			o, err := authn.New(authn.Config{
				LoginFlow:      flow,
				AuditEmitter:   emitter,
				StateRefSigner: newSigner(t),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
			if err != nil {
				t.Fatalf("primary prompt Tick: %v", err)
			}
			st, step, err = o.Tick(context.Background(), st, authn.Input{
				Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "hunter2"}},
				Now:        fakeNow(),
			})
			if err != nil {
				t.Fatalf("primary submit Tick: %v", err)
			}
			if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
				t.Fatalf("expected the rule step prompt, got %+v", step.Prompt)
			}
			if _, _, err = o.Tick(context.Background(), st, authn.Input{
				Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
				Now:        fakeNow(),
			}); err != nil {
				t.Fatalf("additional factor Tick: %v", err)
			}

			assertAuditEvents(t, emitter.snapshot(), tc.want)
		})
	}
}

// TestAuditAttemptOnePerResolvedFactor drives a real wrong-code retry on
// both chain implementations. A multi-step factor re-shows its verify
// screen after a miss without resolving anything, and that re-emission
// must not add a second record: the login-attempt counter would
// otherwise drift upward on every re-render.
func TestAuditAttemptOnePerResolvedFactor(t *testing.T) {
	t.Parallel()

	const (
		sendType   = "auth.email_otp.send"
		verifyType = "auth.email_otp.verify"
	)
	verifyScratch := []byte{0x01}

	// multiStepOTP delivers a code on the first Continue, rejects a
	// wrong guess while re-showing the verify screen, and resolves on
	// "correct".
	multiStepOTP := func() *stubAuthenticator {
		return &stubAuthenticator{
			typeID:  op.FactorEmailOTP,
			aal:     op.AAL2,
			amr:     "otp",
			prompts: []string{sendType, verifyType},
			beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
				return interaction.Step{Prompt: &interaction.Prompt{Type: sendType}}, nil
			},
			continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
				if len(in.Scratch) == 0 {
					return interaction.Step{Prompt: &interaction.Prompt{Type: verifyType}, Scratch: verifyScratch}, nil
				}
				if in.Submission.Values["code"] == "correct" {
					return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
				}
				return interaction.Step{Prompt: &interaction.Prompt{Type: verifyType}, Scratch: verifyScratch}, retryError(op.FactorEmailOTP)
			},
		}
	}

	// driveRetry walks send -> wrong code -> wrong code -> correct code,
	// asserting the verify screen is re-shown after each miss so the
	// "no extra record" claim rests on a retry that really happened.
	driveRetry := func(t *testing.T, o *authn.Orchestrator, st authn.State) {
		t.Helper()

		st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("begin Tick: %v", err)
		}
		if step.Prompt == nil || step.Prompt.Type != sendType {
			t.Fatalf("expected send prompt, got %+v", step.Prompt)
		}
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"email": "a@b.c"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("send Tick: %v", err)
		}
		if step.Prompt == nil || step.Prompt.Type != verifyType {
			t.Fatalf("expected verify prompt, got %+v", step.Prompt)
		}
		for i := 1; i <= 2; i++ {
			st, step, err = o.Tick(context.Background(), st, authn.Input{
				Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
				Now:        fakeNow(),
			})
			if err != nil {
				t.Fatalf("wrong-code Tick %d: %v", i, err)
			}
			if step.Prompt == nil || step.Prompt.Type != verifyType {
				t.Fatalf("wrong-code Tick %d: expected the verify prompt to be re-shown, got %+v", i, step.Prompt)
			}
		}
		_, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "correct"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("correct-code Tick: %v", err)
		}
		if step.Result == nil {
			t.Fatalf("expected terminal Result, got %+v", step)
		}
	}

	t.Run("legacy-chain", func(t *testing.T) {
		t.Parallel()

		emitter := &recordingAuditEmitter{}
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{multiStepOTP()},
			AuditEmitter:   emitter,
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		st := initialState()
		st.Subject = "user-1"
		driveRetry(t, o, st)

		assertAuditEvents(t, emitter.snapshot(), []wantAuditEvent{
			{name: auditevent.AuditLoginFailed, level: opaudit.LevelWarn, actor: "user-1", factor: op.FactorEmailOTP},
			{name: auditevent.AuditLoginFailed, level: opaudit.LevelWarn, actor: "user-1", factor: op.FactorEmailOTP},
			{name: auditevent.AuditLoginSuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorEmailOTP},
		})
	})

	t.Run("login-flow", func(t *testing.T) {
		t.Parallel()

		emitter := &recordingAuditEmitter{}
		flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
			Primary: authn.LoginFlowStep{Kind: "myorg.email_otp", Authenticator: multiStepOTP()},
		})
		if err != nil {
			t.Fatalf("CompileLoginFlow: %v", err)
		}
		o, err := authn.New(authn.Config{
			LoginFlow:      flow,
			AuditEmitter:   emitter,
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// The LoginFlow path keys its pre-primary phase off an unbound
		// Subject, so the primary step is what binds it here and the
		// failed attempts have no actor to record yet.
		driveRetry(t, o, initialState())

		assertAuditEvents(t, emitter.snapshot(), []wantAuditEvent{
			{name: auditevent.AuditLoginFailed, level: opaudit.LevelWarn, factor: op.FactorEmailOTP},
			{name: auditevent.AuditLoginFailed, level: opaudit.LevelWarn, factor: op.FactorEmailOTP},
			{name: auditevent.AuditLoginSuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorEmailOTP},
		})
	})
}

// TestAuditAttemptFailureCarriesSubject pins the deliberate divergence
// between the two feeds a failed factor reaches. Both are driven from
// the same call site in the same run, so the difference asserted here is
// the difference in the code, not a difference in fixtures.
func TestAuditAttemptFailureCarriesSubject(t *testing.T) {
	t.Parallel()

	emitter := &recordingAuditEmitter{}
	obs := &recordingObserver{}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{failingAuthenticator(op.FactorPassword, op.AAL1, "pwd")},
		Observers:      []op.LoginAttemptObserver{obs},
		AuditEmitter:   emitter,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := initialState()
	state.Subject = "user-1"
	st, step, err := o.Tick(context.Background(), state, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if _, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "wrong"}},
		Now:        fakeNow(),
	}); err != nil {
		t.Fatalf("second Tick: %v", err)
	}

	attempts := obs.snapshot()
	if len(attempts) != 1 {
		t.Fatalf("observer events = %d, want 1", len(attempts))
	}
	if attempts[0].Subject != "" {
		t.Errorf("LoginAttempt.Subject = %q, want empty: the observer feed runs inside the attempt and can steer the response, "+
			"so carrying the subject there would turn an embedder policy hook into a user-enumeration oracle", attempts[0].Subject)
	}

	records := emitter.snapshot()
	if len(records) != 1 {
		t.Fatalf("audit events = %s, want one login.failed", describeAuditEvents(records))
	}
	if records[0].ActorID != "user-1" {
		t.Errorf("audit ActorID on the failure path = %q, want %q. The blanked Subject on the observer feed above and the "+
			"populated ActorID here are not an inconsistency to harmonise: the audit record reaches the embedder's own sink "+
			"and never the wire, and which account was being guessed at is the one question a failed-login audit exists to "+
			"answer. Dropping it to match the observer feed would empty the record of its purpose", records[0].ActorID, "user-1")
	}
}

// faultingAuthenticator emits a prompt on Begin and fails every
// submission with a backend fault rather than a credential rejection.
// The error deliberately does NOT wrap [authn.ErrFactorRetry]: that
// sentinel is how an authenticator says "the credential was wrong", and
// a store that timed out never got far enough to have an opinion.
func faultingAuthenticator(typeID op.FactorType, aal op.AAL, amr string, fault error) *stubAuthenticator {
	prompt := promptForFactor(typeID)
	return &stubAuthenticator{
		typeID:  typeID,
		aal:     aal,
		amr:     amr,
		prompts: []string{prompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &prompt}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{}, fault
		},
	}
}

// TestAuditAttemptBackendFaultIsNotACredentialFailure pins the rule that
// separates a judgement from an outage: both feeds a failed factor
// reaches exist to record what happened to a presented credential, and
// an authenticator whose user store timed out never evaluated one.
//
// The consequences of getting this wrong are asymmetric, which is why
// both feeds are asserted. On the audit stream a fault filed as
// login.failed / mfa.failed inflates the failed-login counter, so a
// database outage reads as a credential-stuffing campaign. On the
// observer feed it is worse than misleading: the feed is a policy input,
// so an embedder driving lockout from it locks real users out of their
// accounts precisely while the backend is unable to authenticate anyone.
//
// Both chain implementations are driven because each has its own failure
// call site; a fix applied to one alone would leave the other silently
// mis-filing.
func TestAuditAttemptBackendFaultIsNotACredentialFailure(t *testing.T) {
	t.Parallel()

	// A deadline is the canonical shape of "the store did not answer".
	fault := fmt.Errorf("password: user store: %w", context.DeadlineExceeded)

	// assertNothingRecorded checks the outcome shared by both chains:
	// the fault reaches the HTTP layer intact and neither feed saw an
	// attempt.
	assertNothingRecorded := func(t *testing.T, err error, emitter *recordingAuditEmitter, obs *recordingObserver) {
		t.Helper()

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("submission Tick err = %v, want the injected store fault to surface unchanged", err)
		}
		// The observer feed is checked first, and without a Fatal, so a
		// regression reports both feeds in one run: the audit record is
		// the misleading one, the observer event is the harmful one.
		if attempts := obs.snapshot(); len(attempts) != 0 {
			t.Errorf("observer saw %d attempt(s) = %+v, want none: an embedder driving lockout off this feed "+
				"would lock accounts out for the duration of a backend outage", len(attempts), attempts)
		}
		assertAuditEvents(t, emitter.snapshot(), nil)
	}

	t.Run("legacy-chain", func(t *testing.T) {
		t.Parallel()

		emitter := &recordingAuditEmitter{}
		obs := &recordingObserver{}
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{faultingAuthenticator(op.FactorPassword, op.AAL1, "pwd", fault)},
			Observers:      []op.LoginAttemptObserver{obs},
			AuditEmitter:   emitter,
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		state := initialState()
		state.Subject = "user-1"
		st, step, err := o.Tick(context.Background(), state, authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		_, _, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "hunter2"}},
			Now:        fakeNow(),
		})
		assertNothingRecorded(t, err, emitter, obs)
	})

	t.Run("login-flow", func(t *testing.T) {
		t.Parallel()

		emitter := &recordingAuditEmitter{}
		obs := &recordingObserver{}
		flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
			Primary: authn.LoginFlowStep{
				Kind:          "myorg.password",
				Authenticator: faultingAuthenticator(op.FactorPassword, op.AAL1, "pwd", fault),
			},
		})
		if err != nil {
			t.Fatalf("CompileLoginFlow: %v", err)
		}
		o, err := authn.New(authn.Config{
			LoginFlow:      flow,
			Observers:      []op.LoginAttemptObserver{obs},
			AuditEmitter:   emitter,
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		_, _, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "hunter2"}},
			Now:        fakeNow(),
		})
		assertNothingRecorded(t, err, emitter, obs)
	})
}

// TestAuditAttemptNilEmitter asserts an orchestrator built without an
// AuditEmitter stays usable and silent. Every emission site runs
// unconditionally, so a missing sink substitution would surface as a nil
// dereference on the first resolved factor rather than as a missing
// record.
func TestAuditAttemptNilEmitter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		auth *stubAuthenticator
	}{
		{name: "success", auth: buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")},
		{name: "failure", auth: failingAuthenticator(op.FactorPassword, op.AAL1, "pwd")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o, err := authn.New(authn.Config{
				Authenticators: []op.Authenticator{tc.auth},
				StateRefSigner: newSigner(t),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
			if err != nil {
				t.Fatalf("first Tick: %v", err)
			}
			if _, _, err = o.Tick(context.Background(), st, authn.Input{
				Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "hunter2"}},
				Now:        fakeNow(),
			}); err != nil {
				t.Fatalf("second Tick: %v", err)
			}
		})
	}
}
