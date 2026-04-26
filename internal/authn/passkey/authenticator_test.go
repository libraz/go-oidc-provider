package passkey_test

// The Continue happy-path is intentionally NOT exercised here: a real
// round-trip requires a virtual authenticator able to mint a valid
// assertion signature. Existing FinishLogin tests in
// authenticate_test.go cover the verifier-side error paths; this file
// covers the orchestrator-facing wiring (Type/AAL/AMR/Prompts metadata,
// Begin scratch encoding, Continue input validation, NewAuthenticator
// rejection rules).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const adapterTestSubject = "user-alice"

type adapterFixture struct {
	verifier *passkey.Verifier
	store    store.PasskeyStore
	adapter  *passkey.Authenticator
	now      time.Time
}

func newAdapterFixture(t *testing.T) *adapterFixture {
	t.Helper()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := newTestVerifier(t, now)
	pkstore := inmem.New().Passkeys()
	if err := pkstore.Put(context.Background(), &store.PasskeyRecord{
		CredentialID:    []byte{0x01, 0x02, 0x03},
		Subject:         adapterTestSubject,
		PublicKey:       []byte{0xaa, 0xbb, 0xcc},
		AAGUID:          make([]byte, 16),
		SignCount:       1,
		AttestationType: "none",
		Transports:      []string{"internal"},
		CreatedAt:       now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
	adapter, err := passkey.NewAuthenticator(verifier, pkstore)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return &adapterFixture{
		verifier: verifier,
		store:    pkstore,
		adapter:  adapter,
		now:      now,
	}
}

func TestAuthenticator_Metadata(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	if got := f.adapter.Type(); got != op.FactorPasskey {
		t.Errorf("Type() = %v, want %v", got, op.FactorPasskey)
	}
	if got := f.adapter.AAL(); got != op.AAL2 {
		t.Errorf("AAL() = %v, want AAL2", got)
	}
	if got := f.adapter.AMR(); got != "hwk" {
		t.Errorf("AMR() = %q, want hwk", got)
	}
	prompts := f.adapter.Prompts()
	if len(prompts) != 1 || prompts[0] != passkey.PromptType {
		t.Errorf("Prompts() = %v, want [%s]", prompts, passkey.PromptType)
	}
}

func TestAuthenticator_BeginEmitsPromptAndScratch(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	step, err := f.adapter.Begin(context.Background(), op.BeginInput{
		Subject:  adapterTestSubject,
		AuthTime: f.now,
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("Begin returned no Prompt: %+v", step)
	}
	if step.Prompt.Type != passkey.PromptType {
		t.Errorf("Prompt.Type = %q, want %q", step.Prompt.Type, passkey.PromptType)
	}
	data, ok := step.Prompt.Data.(interaction.PasskeyPromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want PasskeyPromptData", step.Prompt.Data)
	}
	if len(data.Challenge) == 0 {
		t.Error("Challenge is empty")
	}
	if len(data.AllowCredentials) != 1 {
		t.Fatalf("AllowCredentials len = %d, want 1", len(data.AllowCredentials))
	}
	if data.AllowCredentials[0].Type != "public-key" {
		t.Errorf("Descriptor.Type = %q, want public-key", data.AllowCredentials[0].Type)
	}
	if len(step.Prompt.Inputs) != 1 || step.Prompt.Inputs[0].Name != passkey.ResponseFieldName {
		t.Errorf("Inputs = %+v, want one entry named %q", step.Prompt.Inputs, passkey.ResponseFieldName)
	}
	if len(step.Scratch) == 0 {
		t.Fatal("Scratch is empty; orchestrator cannot ferry session to Continue")
	}
	var session passkey.Session
	if err := json.Unmarshal(step.Scratch, &session); err != nil {
		t.Fatalf("Scratch is not a JSON-encoded Session: %v", err)
	}
	if session.Challenge == "" {
		t.Error("encoded Session.Challenge is empty")
	}
	if !session.Expires.Equal(f.now.Add(passkey.DefaultSessionTTLForTest)) {
		t.Errorf("Session.Expires = %v, want %v", session.Expires, f.now.Add(passkey.DefaultSessionTTLForTest))
	}
}

func TestAuthenticator_BeginRequiresSubject(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Begin(context.Background(), op.BeginInput{AuthTime: f.now})
	if !errors.Is(err, passkey.ErrSubjectRequired) {
		t.Fatalf("err = %v, want ErrSubjectRequired", err)
	}
}

func TestAuthenticator_BeginRejectsSubjectWithoutCredentials(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Begin(context.Background(), op.BeginInput{
		Subject:  "no-such-user",
		AuthTime: f.now,
	})
	if !errors.Is(err, passkey.ErrCredentialNotRegistered) {
		t.Fatalf("err = %v, want ErrCredentialNotRegistered", err)
	}
}

func TestAuthenticator_ContinueRequiresSubject(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		AuthTime: f.now,
		Submission: interaction.FormSubmission{
			Values: map[string]string{passkey.ResponseFieldName: "{}"},
		},
		Scratch: []byte(`{"challenge":"x","expires":"2026-04-26T13:00:00Z"}`),
	})
	if !errors.Is(err, passkey.ErrSubjectRequired) {
		t.Fatalf("err = %v, want ErrSubjectRequired", err)
	}
}

func TestAuthenticator_ContinueRequiresScratch(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:  adapterTestSubject,
		AuthTime: f.now,
		Submission: interaction.FormSubmission{
			Values: map[string]string{passkey.ResponseFieldName: "{}"},
		},
	})
	if !errors.Is(err, passkey.ErrSessionMissing) {
		t.Fatalf("err = %v, want ErrSessionMissing", err)
	}
}

func TestAuthenticator_ContinueRequiresResponseField(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    adapterTestSubject,
		AuthTime:   f.now,
		Submission: interaction.FormSubmission{Values: map[string]string{}},
		Scratch:    []byte(`{"challenge":"x","expires":"2026-04-26T13:00:00Z"}`),
	})
	if !errors.Is(err, passkey.ErrResponseMissing) {
		t.Fatalf("err = %v, want ErrResponseMissing", err)
	}
}

func TestAuthenticator_ContinueRejectsCorruptScratch(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:  adapterTestSubject,
		AuthTime: f.now,
		Submission: interaction.FormSubmission{
			Values: map[string]string{passkey.ResponseFieldName: "{}"},
		},
		Scratch: []byte("not-json"),
	})
	if err == nil {
		t.Fatal("expected error decoding bad scratch")
	}
}

func TestAuthenticator_ContinueRejectsExpiredSession(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	expired := passkey.Session{
		Challenge: "abc",
		UserID:    []byte(adapterTestSubject),
		Expires:   f.now.Add(-time.Minute),
	}
	scratch, err := json.Marshal(expired)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	_, err = f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:  adapterTestSubject,
		AuthTime: f.now,
		Submission: interaction.FormSubmission{
			Values: map[string]string{passkey.ResponseFieldName: "{}"},
		},
		Scratch: scratch,
	})
	if !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Fatalf("err = %v, want ErrChallengeExpired", err)
	}
}

func TestAuthenticator_ContinueRejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	huge := make([]byte, 32*1024)
	for i := range huge {
		huge[i] = 'a'
	}
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:  adapterTestSubject,
		AuthTime: f.now,
		Submission: interaction.FormSubmission{
			Values: map[string]string{passkey.ResponseFieldName: string(huge)},
		},
		Scratch: []byte(`{"challenge":"x","expires":"2026-04-26T13:00:00Z"}`),
	})
	if !errors.Is(err, passkey.ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse", err)
	}
}

func TestNewAuthenticator_RejectsNilArgs(t *testing.T) {
	t.Parallel()

	t.Run("nil verifier", func(t *testing.T) {
		t.Parallel()
		_, err := passkey.NewAuthenticator(nil, inmem.New().Passkeys())
		if !errors.Is(err, passkey.ErrVerifierRequired) {
			t.Fatalf("err = %v, want ErrVerifierRequired", err)
		}
	})

	t.Run("nil store", func(t *testing.T) {
		t.Parallel()
		now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
		_, err := passkey.NewAuthenticator(newTestVerifier(t, now), nil)
		if !errors.Is(err, passkey.ErrStoreRequired) {
			t.Fatalf("err = %v, want ErrStoreRequired", err)
		}
	})
}

// silence "unused import" if the test build picks the wrong path.
var _ = timex.SystemClock
