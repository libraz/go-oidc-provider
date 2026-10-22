package authn_test

import (
	"context"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

var errPasskeyStoreDown = errors.New("passkey credential store unreachable")

// faultablePasskeyStore fails ListBySubject on demand, standing in for a
// credential-store outage that strikes between the prompt and the
// assertion.
type faultablePasskeyStore struct {
	store.PasskeyStore
	down atomic.Bool
}

func (s *faultablePasskeyStore) ListBySubject(ctx context.Context, subject string) ([]*store.PasskeyRecord, error) {
	if s.down.Load() {
		return nil, errPasskeyStoreDown
	}
	return s.PasskeyStore.ListBySubject(ctx, subject)
}

// newFaultablePasskeyFixture is newPasskeyFixture over a credential store
// whose reads can be failed.
func newFaultablePasskeyFixture(t *testing.T) (*passkeyFixture, *faultablePasskeyStore) {
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
	credentials := &faultablePasskeyStore{PasskeyStore: inmem.New().Passkeys()}

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
	return &passkeyFixture{auth: auth, key: key, clock: clock}, credentials
}

func submitPasskey(stateRef, response string) authn.Input {
	return authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: stateRef,
			Values:   map[string]string{passkey.ResponseFieldName: response},
		},
		Now: fakeNow(),
	}
}

// TestPasskeyChallengeIsSingleUseAfterSoftFailure rejects one assertion,
// then replays a genuine assertion over the challenge of the rejected
// ceremony against the retry state. The retry runs on a fresh challenge,
// so the replay must be refused again without producing a Result, the
// superseded StateRef must no longer be accepted, and the fresh
// challenge must still be redeemable.
//
// Tracks: CVE-2026-55167 (LDAP Account Manager — the WebAuthn challenge stayed in the session after processing and could be reused)
func TestPasskeyChallengeIsSingleUseAfterSoftFailure(t *testing.T) {
	t.Parallel()

	for _, dispatcher := range []string{"legacy-chain", "login-flow"} {
		t.Run(dispatcher, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			f := newPasskeyFixture(t)
			o := newPasskeyOrchestrators(t, f.auth, &recordingObserver{}, &recordingAuditEmitter{})[dispatcher]

			st0, prompt0, err := o.Tick(ctx, passkeyState(), authn.Input{Now: fakeNow()})
			if err != nil {
				t.Fatalf("prompt Tick: %v", err)
			}
			original := passkeyChallenge(t, prompt0.Prompt)
			originalRef := prompt0.Prompt.StateRef
			replayable := f.assert(t, original)

			unrelated := make([]byte, 32)
			if _, err := rand.Read(unrelated); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			st1, prompt1, err := o.Tick(ctx, st0, submitPasskey(originalRef, f.assert(t, unrelated)))
			if err != nil || prompt1.Prompt == nil {
				t.Fatalf("rejected assertion: err=%v step=%+v, want a retry prompt", err, prompt1)
			}
			fresh := passkeyChallenge(t, prompt1.Prompt)

			st2, replay, err := o.Tick(ctx, st1, submitPasskey(prompt1.Prompt.StateRef, replayable))
			if err != nil {
				t.Fatalf("replayed assertion err = %v, want a soft re-prompt", err)
			}
			if replay.Result != nil {
				t.Fatalf("an assertion over the rejected ceremony's challenge produced %+v", replay.Result)
			}
			if replay.Prompt == nil {
				t.Fatal("replayed assertion yielded neither a Result nor a retry prompt")
			}
			latest := passkeyChallenge(t, replay.Prompt)
			if string(latest) == string(original) || string(latest) == string(fresh) {
				t.Error("a retry re-issued a challenge that was already consumed")
			}

			// The StateRef of the rejected ceremony addressed an earlier step.
			if _, stale, err := o.Tick(ctx, st2, submitPasskey(originalRef, f.assert(t, latest))); !errors.Is(err, authn.ErrInvalidStateRef) || stale.Result != nil {
				t.Errorf("superseded StateRef: err=%v step=%+v, want ErrInvalidStateRef and no Result", err, stale)
			}

			// Control: the live challenge still completes the factor.
			_, done, err := o.Tick(ctx, st2, submitPasskey(replay.Prompt.StateRef, f.assert(t, latest)))
			if err != nil || done.Result == nil {
				t.Fatalf("assertion over the live challenge: err=%v step=%+v, want a Result", err, done)
			}
		})
	}
}

// TestPasskeyChallengeRetiredAfterHardFailure fails the credential store
// while an assertion is being verified. The chain aborts with the store
// error, the returned state carries no in-flight ceremony, and the
// StateRef that addressed it is refused even after the store recovers
// and a genuine assertion over the original challenge is posted.
//
// Tracks: CVE-2026-55167 (LDAP Account Manager — the WebAuthn challenge stayed in the session after processing and could be reused)
func TestPasskeyChallengeRetiredAfterHardFailure(t *testing.T) {
	t.Parallel()

	for _, dispatcher := range []string{"legacy-chain", "login-flow"} {
		t.Run(dispatcher, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			f, credentials := newFaultablePasskeyFixture(t)
			o := newPasskeyOrchestrators(t, f.auth, &recordingObserver{}, &recordingAuditEmitter{})[dispatcher]

			st0, prompt0, err := o.Tick(ctx, passkeyState(), authn.Input{Now: fakeNow()})
			if err != nil {
				t.Fatalf("prompt Tick: %v", err)
			}
			if len(st0.FactorScratch) == 0 {
				t.Fatal("the prompt left no ceremony state; the case would pass vacuously")
			}
			original := passkeyChallenge(t, prompt0.Prompt)
			ref := prompt0.Prompt.StateRef
			response := f.assert(t, original)

			credentials.down.Store(true)
			st1, step, err := o.Tick(ctx, st0, submitPasskey(ref, response))
			if !errors.Is(err, errPasskeyStoreDown) {
				t.Fatalf("hard failure err = %v, want the store error", err)
			}
			if step.Result != nil {
				t.Fatalf("hard failure produced a Result: %+v", step.Result)
			}
			if len(st1.FactorScratch) != 0 {
				t.Error("FactorScratch still holds the ceremony after a hard failure")
			}

			credentials.down.Store(false)
			_, again, err := o.Tick(ctx, st1, submitPasskey(ref, response))
			if !errors.Is(err, authn.ErrInvalidStateRef) {
				t.Errorf("old StateRef after hard failure: err = %v, want ErrInvalidStateRef", err)
			}
			if again.Result != nil {
				t.Errorf("old StateRef after hard failure produced a Result: %+v", again.Result)
			}
		})
	}
}
