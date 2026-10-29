package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey/passkeytest"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	discRPID    = "id.example.com"
	discOrigin  = "https://id.example.com"
	discSubject = "user-alice"
)

type discFixture struct {
	adapter *passkey.Authenticator
	store   store.PasskeyStore
	now     time.Time
}

// newDiscFixture builds an adapter over an empty inmem store. The verifier
// keeps UV at "preferred" so the discoverable path has to impose UV itself.
func newDiscFixture(t *testing.T, allowDiscoverable bool) *discFixture {
	t.Helper()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	v, err := passkey.New(passkey.Config{
		RPID:              discRPID,
		RPDisplayName:     "Example Identity",
		RPOrigins:         []string{discOrigin},
		SessionTTL:        5 * time.Minute,
		AllowDiscoverable: allowDiscoverable,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.Clock = timex.ClockFunc(func() time.Time { return now })
	st := inmem.New().Passkeys()
	a, err := passkey.NewAuthenticator(v, st)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return &discFixture{adapter: a, store: st, now: now}
}

func (f *discFixture) seed(t *testing.T, rec store.PasskeyRecord) {
	t.Helper()
	if err := f.store.Put(context.Background(), &rec); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
}

// begin runs Begin for subject and returns the prompt data and scratch.
func (f *discFixture) begin(t *testing.T, subject string) (interaction.PasskeyPromptData, []byte) {
	t.Helper()
	step, err := f.adapter.Begin(context.Background(), authn.BeginInput{Subject: subject, AuthTime: f.now})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatal("Begin returned no prompt")
	}
	data, ok := step.Prompt.Data.(interaction.PasskeyPromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want PasskeyPromptData", step.Prompt.Data)
	}
	return data, step.Scratch
}

func (f *discFixture) submit(t *testing.T, subject string, scratch, response []byte) (interaction.Step, error) {
	t.Helper()
	return f.adapter.Continue(context.Background(), authn.ContinueInput{
		Subject:  subject,
		AuthTime: f.now,
		Submission: interaction.FormSubmission{
			Values: map[string]string{passkey.ResponseFieldName: string(response)},
		},
		Scratch: scratch,
	})
}

// discoverableAttempt seeds the records, runs one discoverable ceremony
// with key signing for userHandle, and returns the Continue outcome.
func discoverableAttempt(t *testing.T, key *passkeytest.Authenticator, userHandle string, uv bool, records ...store.PasskeyRecord) (interaction.Step, error) {
	t.Helper()
	f := newDiscFixture(t, true)
	for _, r := range records {
		f.seed(t, r)
	}
	data, scratch := f.begin(t, "")
	resp := key.Assert(t, data.Challenge, discOrigin, []byte(userHandle), uv)
	return f.submit(t, "", scratch, resp)
}

// requireRetry asserts a soft reprompt that names only the generic
// assertion failure.
func requireRetry(t *testing.T, step interaction.Step, err error) {
	t.Helper()
	if !errors.Is(err, authn.ErrFactorRetry) {
		t.Fatalf("err = %v, want ErrFactorRetry", err)
	}
	if !errors.Is(err, passkey.ErrAssertionInvalid) {
		t.Errorf("err = %v, want ErrAssertionInvalid", err)
	}
	if errors.Is(err, passkey.ErrCredentialNotRegistered) {
		t.Errorf("err = %v reveals that the credential is unknown", err)
	}
	if step.Result != nil {
		t.Errorf("rejected assertion produced a Result: %+v", step.Result)
	}
}

func TestDiscoverable_SubjectComesFromRecord(t *testing.T) {
	t.Parallel()

	f := newDiscFixture(t, true)
	key := passkeytest.New(t, discRPID)
	rec := key.Record(discSubject)
	f.seed(t, rec)

	data, scratch := f.begin(t, "")
	if len(data.AllowCredentials) != 0 {
		t.Errorf("AllowCredentials = %+v, want empty", data.AllowCredentials)
	}
	var session passkey.Session
	if err := json.Unmarshal(scratch, &session); err != nil {
		t.Fatalf("decode scratch: %v", err)
	}
	if len(session.UserID) != 0 {
		t.Errorf("session UserID = %q, want empty", session.UserID)
	}
	if session.UserVerification != "required" {
		t.Errorf("session UserVerification = %q, want required", session.UserVerification)
	}

	resp := key.Assert(t, data.Challenge, discOrigin, []byte(discSubject), true)
	step, err := f.submit(t, "", scratch, resp)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Result == nil || step.Result.Subject != discSubject {
		t.Fatalf("Result = %+v, want subject %q", step.Result, discSubject)
	}
	if !step.Result.UserVerified {
		t.Error("Result.UserVerified = false, want true")
	}
	stored, err := f.store.Get(context.Background(), rec.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.SignCount != 1 {
		t.Errorf("SignCount = %d, want 1", stored.SignCount)
	}
}

func TestDiscoverable_UnknownCredentialReprompts(t *testing.T) {
	t.Parallel()

	key := passkeytest.New(t, discRPID)
	other := passkeytest.New(t, discRPID)
	step, err := discoverableAttempt(t, key, discSubject, true, other.Record(discSubject))
	requireRetry(t, step, err)
}

func TestDiscoverable_UserHandleMismatchReprompts(t *testing.T) {
	t.Parallel()

	key := passkeytest.New(t, discRPID)
	mallory := passkeytest.New(t, discRPID)
	step, err := discoverableAttempt(t, key, "user-mallory", true,
		key.Record(discSubject), mallory.Record("user-mallory"))
	requireRetry(t, step, err)
}

func TestDiscoverable_NoUserVerificationReprompts(t *testing.T) {
	t.Parallel()

	key := passkeytest.New(t, discRPID)
	step, err := discoverableAttempt(t, key, discSubject, false, key.Record(discSubject))
	requireRetry(t, step, err)
}

func TestDiscoverable_BadSignatureReprompts(t *testing.T) {
	t.Parallel()

	key := passkeytest.New(t, discRPID)
	rec := key.Record(discSubject)
	rec.PublicKey = passkeytest.New(t, discRPID).Record(discSubject).PublicKey
	step, err := discoverableAttempt(t, key, discSubject, true, rec)
	requireRetry(t, step, err)
}

func TestDiscoverable_RejectionsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	key := passkeytest.New(t, discRPID)
	other := passkeytest.New(t, discRPID)
	badKey := key.Record(discSubject)
	badKey.PublicKey = other.Record(discSubject).PublicKey

	_, unknown := discoverableAttempt(t, key, discSubject, true, other.Record(discSubject))
	_, mismatch := discoverableAttempt(t, key, "user-mallory", true, key.Record(discSubject))
	_, noUV := discoverableAttempt(t, key, discSubject, false, key.Record(discSubject))
	_, badSig := discoverableAttempt(t, key, discSubject, true, badKey)

	for name, err := range map[string]error{"mismatch": mismatch, "noUV": noUV, "badSig": badSig} {
		if err == nil || unknown == nil || err.Error() != unknown.Error() {
			t.Errorf("%s err = %v, unknown-credential err = %v; want identical", name, err, unknown)
		}
	}
}

func TestDiscoverable_DisabledKeepsSubjectRequired(t *testing.T) {
	t.Parallel()

	f := newDiscFixture(t, false)
	f.seed(t, passkeytest.New(t, discRPID).Record(discSubject))

	if _, err := f.adapter.Begin(context.Background(), authn.BeginInput{AuthTime: f.now}); !errors.Is(err, passkey.ErrSubjectRequired) {
		t.Fatalf("Begin err = %v, want ErrSubjectRequired", err)
	}
	_, scratch := f.begin(t, discSubject)
	if _, err := f.submit(t, "", scratch, []byte("{}")); !errors.Is(err, passkey.ErrSubjectRequired) {
		t.Fatalf("Continue err = %v, want ErrSubjectRequired", err)
	}
}

func TestFinishLogin_Success(t *testing.T) {
	t.Parallel()

	f := newDiscFixture(t, false)
	key := passkeytest.New(t, discRPID)
	rec := key.Record(discSubject)
	f.seed(t, rec)

	data, scratch := f.begin(t, discSubject)
	if len(data.AllowCredentials) != 1 {
		t.Fatalf("AllowCredentials len = %d, want 1", len(data.AllowCredentials))
	}
	resp := key.Assert(t, data.Challenge, discOrigin, []byte(discSubject), true)
	step, err := f.submit(t, discSubject, scratch, resp)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Result == nil || step.Result.Subject != discSubject {
		t.Fatalf("Result = %+v, want subject %q", step.Result, discSubject)
	}
	if !step.Result.UserVerified {
		t.Error("Result.UserVerified = false, want true")
	}
	stored, err := f.store.Get(context.Background(), rec.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.SignCount != 1 {
		t.Errorf("SignCount = %d, want 1", stored.SignCount)
	}
}

// TestFinishLogin_UserVerifiedReflectsAssertion pins that the UV bit on
// the Result is this assertion's flag, not the one latched on the record
// by an earlier ceremony.
func TestFinishLogin_UserVerifiedReflectsAssertion(t *testing.T) {
	t.Parallel()

	f := newDiscFixture(t, false)
	key := passkeytest.New(t, discRPID)
	rec := key.Record(discSubject)
	rec.UserVerified = true
	f.seed(t, rec)

	data, scratch := f.begin(t, discSubject)
	resp := key.Assert(t, data.Challenge, discOrigin, []byte(discSubject), false)
	step, err := f.submit(t, discSubject, scratch, resp)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Result == nil || step.Result.UserVerified {
		t.Fatalf("Result = %+v, want UserVerified false for a presence-only assertion", step.Result)
	}
}

func TestEnrolled(t *testing.T) {
	t.Parallel()

	f := newDiscFixture(t, false)
	ctx := context.Background()

	if got, err := f.adapter.Enrolled(ctx, discSubject); err != nil || got {
		t.Fatalf("Enrolled before registration = %v, %v; want false, nil", got, err)
	}
	f.seed(t, passkeytest.New(t, discRPID).Record(discSubject))
	if got, err := f.adapter.Enrolled(ctx, discSubject); err != nil || !got {
		t.Fatalf("Enrolled after registration = %v, %v; want true, nil", got, err)
	}
	if got, err := f.adapter.Enrolled(ctx, "user-bob"); err != nil || got {
		t.Fatalf("Enrolled for another subject = %v, %v; want false, nil", got, err)
	}
}
