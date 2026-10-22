package authn_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// lockoutClock is a settable clock shared by the counter, the store and
// the factor under test.
type lockoutClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *lockoutClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *lockoutClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const lockoutSubject = "user-1"

// lockoutFactor builds one lockout-aware factor over st and returns it
// with the submission that drives it from its first prompt to the
// code-entry prompt (nil when the first prompt already asks for the
// code) and a wrong code for that prompt.
type lockoutFactor struct {
	name  string
	build func(t *testing.T, st *inmem.Store, clock *lockoutClock, counter *lockout.Counter) (op.Authenticator, map[string]string, map[string]string)
}

func lockoutFactors() []lockoutFactor {
	return []lockoutFactor{
		{name: "totp", build: buildLockoutTOTP},
		{name: "recovery", build: buildLockoutRecovery},
		{name: "emailotp", build: buildLockoutEmailOTP},
	}
}

func buildLockoutTOTP(t *testing.T, st *inmem.Store, clock *lockoutClock, counter *lockout.Counter) (op.Authenticator, map[string]string, map[string]string) { //nolint:ireturn // the table holds builders of different authenticator types.
	t.Helper()
	codec, err := totp.NewCodec(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	blob, err := codec.Seal(secret, []byte(lockoutSubject))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := st.TOTPs().Put(context.Background(), &store.TOTPRecord{
		Subject:          lockoutSubject,
		SecretCiphertext: blob,
		ConfirmedAt:      clock.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	auth, err := totp.NewAuthenticator(&totp.Verifier{Codec: codec, Clock: clock}, st.TOTPs())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	// Pick a code no step near any instant the test reaches can produce.
	var live []string
	for step := -100; step <= 200; step++ {
		live = append(live, totp.Code(secret, clock.Now().Add(time.Duration(step)*30*time.Second)))
	}
	wrong := ""
	for i := range 1000000 {
		if c := fmt.Sprintf("%06d", i); !slices.Contains(live, c) {
			wrong = c
			break
		}
	}
	return auth.WithLockout(counter), nil, map[string]string{totp.CodeFieldName: wrong}
}

func buildLockoutRecovery(t *testing.T, st *inmem.Store, clock *lockoutClock, counter *lockout.Counter) (op.Authenticator, map[string]string, map[string]string) { //nolint:ireturn // the table holds builders of different authenticator types.
	t.Helper()
	verifier := &recovery.Verifier{Clock: clock}
	res, err := verifier.Generate(context.Background(), lockoutSubject)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := st.RecoveryCodes().Put(context.Background(), res.Batch); err != nil {
		t.Fatalf("Put: %v", err)
	}
	auth, err := recovery.NewAuthenticator(verifier, st.RecoveryCodes())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth.WithLockout(counter), nil, map[string]string{recovery.CodeFieldName: "00000-00000"}
}

func buildLockoutEmailOTP(t *testing.T, st *inmem.Store, clock *lockoutClock, counter *lockout.Counter) (op.Authenticator, map[string]string, map[string]string) { //nolint:ireturn // the table holds builders of different authenticator types.
	t.Helper()
	const addr = "user-1@example.com"
	st.PutUser(context.Background(), &store.User{Subject: lockoutSubject, Claims: map[string]any{"email": addr}})
	var sent string
	auth, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer: emailotp.MailerFunc(func(_ context.Context, msg emailotp.Message) error {
			sent = msg.Code
			return nil
		}),
		Store:          st.EmailOTPs(),
		Users:          st.Users(),
		Clock:          clock,
		SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	wrong := map[string]string{emailotp.CodeFieldName: "000000"}
	return wrongEmailOTP{Authenticator: auth.WithLockout(counter), sent: &sent, wrong: wrong},
		map[string]string{emailotp.EmailFieldName: addr}, wrong
}

// wrongEmailOTP rewrites the wrong code so it never equals the code the
// send step delivered.
type wrongEmailOTP struct {
	*emailotp.Authenticator
	sent  *string
	wrong map[string]string
}

func (w wrongEmailOTP) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if code, ok := in.Submission.Values[emailotp.CodeFieldName]; ok && code == *w.sent {
		in.Submission.Values[emailotp.CodeFieldName] = "111111"
		if *w.sent == "111111" {
			in.Submission.Values[emailotp.CodeFieldName] = "222222"
		}
	}
	return w.Authenticator.Continue(ctx, in)
}

// TestAuditLockoutOutcomes pins, per lockout-aware factor, what reaches
// the audit stream and the observer feed when the shared brute-force
// gate is involved: the counted wrong guess that engages the lock and
// the one that makes a reset required are each one credential failure
// on both feeds, while a refusal the gate issues before anything is
// evaluated is an observer lock event only.
func TestAuditLockoutOutcomes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// seed is the number of failures recorded on the shared counter
		// before the code prompt; advance is applied after seeding.
		seed    int
		advance time.Duration
		// lockBeforeSubmit records one more failure after the prompt is
		// shown, so the submission meets an active lock.
		lockBeforeSubmit bool
		wantErr          error
		wantAudit        []auditevent.Name
		wantObserver     op.AttemptOutcome
	}{
		{name: "guess-engages-lock", seed: 29, wantErr: authn.ErrFactorLocked, wantAudit: []auditevent.Name{auditevent.AuditLoginFailed}, wantObserver: op.AttemptFailure},
		{name: "guard-refusal", seed: 29, lockBeforeSubmit: true, wantErr: authn.ErrFactorLocked, wantObserver: op.AttemptLocked},
		{name: "guess-requires-reset", seed: 89, advance: 2 * time.Hour, wantErr: authn.ErrFactorAbort, wantAudit: []auditevent.Name{auditevent.AuditLoginFailed}, wantObserver: op.AttemptFailure},
	}
	for _, f := range lockoutFactors() {
		for _, tc := range cases {
			t.Run(f.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				clock := &lockoutClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
				st := inmem.New(inmem.WithClock(clock))
				counter, err := lockout.New(st.AuthnLockouts(), clock)
				if err != nil {
					t.Fatalf("lockout.New: %v", err)
				}
				for i := range tc.seed {
					if _, err := counter.RecordFailure(ctx, lockoutSubject); err != nil {
						t.Fatalf("RecordFailure %d: %v", i+1, err)
					}
				}
				clock.advance(tc.advance)

				auth, toCode, wrong := f.build(t, st, clock, counter)
				emitter := &recordingAuditEmitter{}
				observer := &recordingObserver{}
				o, err := authn.New(authn.Config{
					Authenticators: []op.Authenticator{auth},
					AuditEmitter:   emitter,
					Observers:      []op.LoginAttemptObserver{observer},
					StateRefSigner: newSigner(t),
				})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				state := initialState()
				state.Subject = lockoutSubject
				state, step, err := o.Tick(ctx, state, authn.Input{Now: clock.Now()})
				if err != nil {
					t.Fatalf("first Tick: %v", err)
				}
				if toCode != nil {
					state, step, err = o.Tick(ctx, state, authn.Input{
						Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: toCode},
						Now:        clock.Now(),
					})
					if err != nil {
						t.Fatalf("send Tick: %v", err)
					}
				}
				if step.Prompt == nil {
					t.Fatalf("no code prompt: %+v", step)
				}
				if tc.lockBeforeSubmit {
					if _, err := counter.RecordFailure(ctx, lockoutSubject); err != nil {
						t.Fatalf("RecordFailure: %v", err)
					}
				}
				_, _, err = o.Tick(ctx, state, authn.Input{
					Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: wrong},
					Now:        clock.Now(),
				})
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("submit err = %v, want %v", err, tc.wantErr)
				}

				evs := emitter.snapshot()
				names := make([]auditevent.Name, 0, len(evs))
				for _, ev := range evs {
					names = append(names, auditevent.Name(ev.Name))
				}
				if !slices.Equal(names, tc.wantAudit) {
					t.Errorf("audit events = %v, want %v", names, tc.wantAudit)
				}
				events := observer.snapshot()
				if len(events) != 1 || events[0].Outcome != tc.wantObserver {
					t.Errorf("observer events = %+v, want exactly one %v", events, tc.wantObserver)
				}
			})
		}
	}
}
