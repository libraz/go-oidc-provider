package authn_test

// A rejected WebAuthn assertion is a credential failure like any other:
// the user cancelled the dialog, touched the wrong security key, or came
// back after the five-minute challenge ran out. The orchestrator reads
// the factor's error to decide what it records and where the chain goes,
// so an unclassified one is filed as an authenticator fault — no observer
// event, no audit record, and a 500 where the user should have seen
// another prompt. These tests drive the real ceremony against a soft
// authenticator on both dispatchers, because each has its own failure
// call site and a fix applied to one would leave the other silent.

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	opaudit "github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	webauthnRPID    = "id.example.com"
	webauthnOrigin  = "https://id.example.com"
	passkeySubject  = "user-1"
	passkeyStepKind = "myorg.passkey"
)

// movingClock is the ceremony clock the expiry case advances. The
// orchestrator ticks on the fixture time throughout; only the WebAuthn
// session's own five-minute window moves.
type movingClock struct{ t time.Time }

func (c *movingClock) Now() time.Time { return c.t }

// passkeyFixture is one subject with one enrolled credential and the
// adapter that authenticates it.
type passkeyFixture struct {
	auth  *passkey.Authenticator
	key   *softkey.Key
	clock *movingClock
}

// newPasskeyFixture enrols a credential through the real registration
// ceremony and returns the login adapter over the same store, so the
// assertions under test run against a credential the verifier itself
// accepted rather than a hand-built record.
func newPasskeyFixture(t *testing.T) *passkeyFixture {
	t.Helper()

	ctx := context.Background()
	clock := &movingClock{t: fakeNow()}
	verifier, err := passkey.New(passkey.ConfigFrom(passkey.StepPolicy{
		RPID:          webauthnRPID,
		RPDisplayName: "Example Identity",
		RPOrigins:     []string{webauthnOrigin},
		SessionTTL:    5 * time.Minute,
	}))
	if err != nil {
		t.Fatalf("passkey.New: %v", err)
	}
	verifier.Clock = timex.ClockFunc(clock.Now)

	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}
	credentials := inmem.New().Passkeys()

	challenge, session, err := verifier.BeginRegistration(ctx, passkeySubject, "alice@example.com", "Alice", nil)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	raw, err := softkey.ChallengeFromOptions(challenge.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	created, err := key.Create(webauthnRPID, webauthnOrigin, raw)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cred, err := verifier.FinishRegistration(ctx, credentials, session, passkeySubject, "alice@example.com", "Alice", nil, created)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	record := passkey.RecordFromCredential(passkeySubject, *cred)
	if err := credentials.Put(ctx, &record); err != nil {
		t.Fatalf("Passkeys.Put: %v", err)
	}

	auth, err := passkey.NewAuthenticator(verifier, credentials)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return &passkeyFixture{auth: auth, key: key, clock: clock}
}

// assert produces the JSON a browser would post for challenge.
func (f *passkeyFixture) assert(t *testing.T, challenge []byte) string {
	t.Helper()

	response, err := f.key.Assert(webauthnRPID, webauthnOrigin, challenge, []byte(passkeySubject))
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	return string(response)
}

// passkeyChallenge reads the challenge bytes off an emitted prompt.
func passkeyChallenge(t *testing.T, prompt *interaction.Prompt) []byte {
	t.Helper()

	if prompt == nil {
		t.Fatal("no prompt emitted; the passkey factor never ran")
	}
	data, ok := prompt.Data.(interaction.PasskeyPromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want interaction.PasskeyPromptData", prompt.Data)
	}
	return data.Challenge
}

// passkeyState is a chain that already knows who the user is and has been
// told to authenticate them afresh — the shape a passkey primary runs in,
// since the factor needs a bound subject and the LoginFlow dispatcher
// would otherwise let the inherited one stand in for the whole step.
func passkeyState() authn.State {
	st := initialState()
	st.Subject = passkeySubject
	st.ReauthRequired = true
	return st
}

// newPasskeyOrchestrators builds the same factor on both dispatchers so a
// case can be driven through each without restating the wiring.
func newPasskeyOrchestrators(
	t *testing.T,
	auth *passkey.Authenticator,
	obs *recordingObserver,
	emitter *recordingAuditEmitter,
) map[string]*authn.Orchestrator {
	t.Helper()

	legacy, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{auth},
		Observers:      []op.LoginAttemptObserver{obs},
		AuditEmitter:   emitter,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New (legacy chain): %v", err)
	}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: passkeyStepKind, Authenticator: auth},
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	loginFlow, err := authn.New(authn.Config{
		LoginFlow:      flow,
		Observers:      []op.LoginAttemptObserver{obs},
		AuditEmitter:   emitter,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New (login flow): %v", err)
	}
	return map[string]*authn.Orchestrator{"legacy-chain": legacy, "login-flow": loginFlow}
}

// TestPasskeyRejectedAssertionIsRetriedAndRecorded drives the two
// failures a user actually produces — an assertion that does not verify,
// and one posted after the ceremony expired — and asserts the same three
// things about each: the user gets another prompt rather than an error
// page, the attempt reaches the observer feed an embedder drives lockout
// from, and the audit stream carries the record a SOC would need to see
// passkey credential stuffing at all.
func TestPasskeyRejectedAssertionIsRetriedAndRecorded(t *testing.T) {
	t.Parallel()

	cases := map[string]func(t *testing.T, f *passkeyFixture, challenge []byte) string{
		"assertion-does-not-verify": func(t *testing.T, f *passkeyFixture, _ []byte) string {
			t.Helper()
			// Signed over a challenge this ceremony never issued: what
			// the library reports for a stale dialog, a replayed capture,
			// or any other §7.2 check the response fails.
			stale := make([]byte, 32)
			if _, err := rand.Read(stale); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			return f.assert(t, stale)
		},
		"challenge-expired": func(t *testing.T, f *passkeyFixture, challenge []byte) string {
			t.Helper()
			response := f.assert(t, challenge)
			// The user walked away and came back after the ceremony's
			// five-minute window.
			f.clock.t = f.clock.t.Add(10 * time.Minute)
			return response
		},
	}

	for name, submission := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, dispatcher := range []string{"legacy-chain", "login-flow"} {
				t.Run(dispatcher, func(t *testing.T) {
					t.Parallel()

					ctx := context.Background()
					f := newPasskeyFixture(t)
					obs := &recordingObserver{}
					emitter := &recordingAuditEmitter{}
					o := newPasskeyOrchestrators(t, f.auth, obs, emitter)[dispatcher]

					st, step, err := o.Tick(ctx, passkeyState(), authn.Input{Now: fakeNow()})
					if err != nil {
						t.Fatalf("prompt Tick: %v", err)
					}
					challenge := passkeyChallenge(t, step.Prompt)

					_, retry, err := o.Tick(ctx, st, authn.Input{
						Submission: &interaction.FormSubmission{
							StateRef: step.Prompt.StateRef,
							Values:   map[string]string{passkey.ResponseFieldName: submission(t, f, challenge)},
						},
						Now: fakeNow(),
					})
					if err != nil {
						t.Fatalf("submission Tick err = %v; a rejected assertion must re-prompt, not surface "+
							"as a chain-fatal error the HTTP layer renders as 500", err)
					}
					if retry.Prompt == nil {
						t.Fatalf("submission Tick returned %+v, want a fresh passkey prompt", retry)
					}
					if fresh := passkeyChallenge(t, retry.Prompt); string(fresh) == string(challenge) {
						t.Error("the retry re-issued the same challenge; a rejected ceremony must not stay replayable")
					}

					if attempts := obs.snapshot(); len(attempts) != 1 {
						t.Errorf("observer saw %d attempt(s), want 1: passkey guessing invisible to the feed "+
							"an embedder drives lockout from", len(attempts))
					} else if attempts[0].Outcome != authn.AttemptFailure {
						t.Errorf("observed Outcome = %v, want AttemptFailure", attempts[0].Outcome)
					}
					assertAuditEvents(t, emitter.snapshot(), []wantAuditEvent{{
						name:   auditevent.AuditLoginFailed,
						level:  opaudit.LevelWarn,
						actor:  passkeySubject,
						factor: op.FactorPasskey,
					}})
				})
			}
		})
	}
}

// TestPasskeyCloneDetectionAbortsWithoutAServerError covers the terminal
// half of the same rule. A signature counter that failed to advance is
// the WebAuthn Level 3 §7.2 step 17 clone signal: retrying cannot help,
// so the chain stops — but it stops as a rejected submission the HTTP
// layer renders as a 4xx, not as an unexplained server fault.
func TestPasskeyCloneDetectionAbortsWithoutAServerError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newPasskeyFixture(t)
	obs := &recordingObserver{}
	emitter := &recordingAuditEmitter{}
	o := newPasskeyOrchestrators(t, f.auth, obs, emitter)["legacy-chain"]

	// One good assertion to move the stored counter, then rewind the
	// authenticator so the next one repeats a counter already seen.
	st, step, err := o.Tick(ctx, passkeyState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("prompt Tick: %v", err)
	}
	if _, _, err := o.Tick(ctx, st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{passkey.ResponseFieldName: f.assert(t, passkeyChallenge(t, step.Prompt))},
		},
		Now: fakeNow(),
	}); err != nil {
		t.Fatalf("successful assertion Tick: %v", err)
	}

	f.key.SetSignCount(f.key.SignCount() - 1)
	st, step, err = o.Tick(ctx, passkeyState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("second prompt Tick: %v", err)
	}
	_, _, err = o.Tick(ctx, st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{passkey.ResponseFieldName: f.assert(t, passkeyChallenge(t, step.Prompt))},
		},
		Now: fakeNow(),
	})
	if !errors.Is(err, passkey.ErrCloneDetected) {
		t.Fatalf("err = %v, want ErrCloneDetected", err)
	}
	if !errors.Is(err, authn.ErrFactorAbort) {
		t.Fatalf("err = %v, want it to carry ErrFactorAbort so the HTTP layer renders a 4xx rather than a 500", err)
	}
}
