package passkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// reverseAssertionStore blocks the lower counter until the higher
// counter has committed. This models two assertions that verified
// against the same snapshot but completed persistence in the adverse
// order that used to rewind the record through blind Put.
type reverseAssertionStore struct {
	store.PasskeyStore
	lowArrived chan struct{}
	highDone   chan struct{}
}

func (s *reverseAssertionStore) UpdateAssertion(
	ctx context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	if update.SignCount == 8 {
		close(s.lowArrived)
		<-s.highDone
	}
	rec, err := s.PasskeyStore.UpdateAssertion(ctx, credentialID, update)
	if update.SignCount == 9 {
		close(s.highDone)
	}
	return rec, err
}

func TestPersistCredentialReverseCompletionDoesNotRewind(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := inmem.New().Passkeys()
	if err := base.Put(ctx, &store.PasskeyRecord{
		CredentialID: []byte("credential"),
		Subject:      "subject",
		PublicKey:    []byte("public-key"),
		SignCount:    7,
	}); err != nil {
		t.Fatalf("Put seed: %v", err)
	}
	gated := &reverseAssertionStore{
		PasskeyStore: base,
		lowArrived:   make(chan struct{}),
		highDone:     make(chan struct{}),
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	a, err := passkey.NewAuthenticator(newTestVerifier(t, now), gated)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	low := passkey.Credential{
		ID: []byte("credential"),
		Flags: passkey.CredentialFlags{
			UserPresent:  false,
			UserVerified: false,
			BackupState:  false,
		},
		Authenticator: passkey.AuthenticatorData{
			SignCount:    8,
			CloneWarning: false,
		},
	}
	high := passkey.Credential{
		ID: []byte("credential"),
		Flags: passkey.CredentialFlags{
			UserPresent:  true,
			UserVerified: true,
			BackupState:  true,
		},
		Authenticator: passkey.AuthenticatorData{
			SignCount:    9,
			CloneWarning: true,
		},
	}
	passkey.SetExpectedSignCountForTest(&low, 7)
	passkey.SetExpectedSignCountForTest(&high, 7)

	done := make(chan struct{}, 2)
	go func() {
		a.ContinueResultForTest(ctx, "subject", now, &low)
		done <- struct{}{}
	}()
	<-gated.lowArrived
	go func() {
		a.ContinueResultForTest(ctx, "subject", now, &high)
		done <- struct{}{}
	}()
	for range 2 {
		<-done
	}

	got, err := base.Get(ctx, []byte("credential"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SignCount != 9 {
		t.Errorf("SignCount = %d, want 9", got.SignCount)
	}
	if !got.CloneWarning {
		t.Error("CloneWarning = false, want true")
	}
	if !got.UserPresent || !got.UserVerified || !got.BackupState {
		t.Errorf("assertion flags rewound: %+v", got)
	}
}
