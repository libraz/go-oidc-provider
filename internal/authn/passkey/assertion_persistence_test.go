package passkey_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// reverseAssertionStore blocks the lower counter until the higher
// counter has committed. This models two assertions that verified
// against the same snapshot but completed persistence in the adverse
// order that used to rewind the record through blind Put. The lower
// counter is written a second time when it is found stale, so only its
// first arrival is gated.
type reverseAssertionStore struct {
	store.PasskeyStore
	lowArrived chan struct{}
	highDone   chan struct{}
	lowOnce    sync.Once
}

func (s *reverseAssertionStore) UpdateAssertion(
	ctx context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	if update.SignCount == 8 {
		s.lowOnce.Do(func() {
			close(s.lowArrived)
			<-s.highDone
		})
	}
	rec, err := s.PasskeyStore.UpdateAssertion(ctx, credentialID, update)
	if update.SignCount == 9 {
		close(s.highDone)
	}
	return rec, err
}

// TestPersistCredentialReverseCompletionDoesNotRewind pins that a
// passkey's persisted SignCount can never move backward, even when two
// concurrent assertions verify against the same snapshot and complete
// persistence out of order.
//
// Tracks: CVE-2026-72780 — an authenticator's sign counter (and, on the
// sibling surface, its UV bit) was not durably persisted across
// concurrent completions, letting a later, stale write erase state a
// previous verification had already recorded. The UV-loss half of the
// same class is pinned by TestAuthenticator_UVBitTravelsOnResult.
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

// TestPersistCredentialStaleConcurrentAssertionIsClone pins that of two
// assertions verified against the same stored counter, the one whose
// counter the other already went past is a clone: it fails with
// ErrCloneDetected, the warning is persisted and the clone hook runs.
func TestPersistCredentialStaleConcurrentAssertionIsClone(t *testing.T) {
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
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	a, err := passkey.NewAuthenticator(newTestVerifier(t, now), base)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	var hooked []uint32
	a = a.WithCloneDetectionHandler(passkey.CloneDetectionHandlerFunc(func(_ context.Context, _ string, c *passkey.Credential) error {
		hooked = append(hooked, c.Authenticator.SignCount)
		return nil
	}))
	assertion := func(count uint32) *passkey.Credential {
		c := &passkey.Credential{ID: []byte("credential"), Authenticator: passkey.AuthenticatorData{SignCount: count}}
		passkey.SetExpectedSignCountForTest(c, 7)
		return c
	}

	if _, err := a.ContinueResultErrForTest(ctx, "subject", now, assertion(9)); err != nil {
		t.Fatalf("first assertion: %v", err)
	}
	step, err := a.ContinueResultErrForTest(ctx, "subject", now, assertion(8))
	if !errors.Is(err, passkey.ErrCloneDetected) || step.Result != nil {
		t.Fatalf("stale assertion: result=%+v err=%v, want ErrCloneDetected and no result", step.Result, err)
	}
	got, err := base.Get(ctx, []byte("credential"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.CloneWarning || got.SignCount != 9 {
		t.Errorf("stored record = %+v, want CloneWarning set and SignCount 9", got)
	}
	if len(hooked) != 1 {
		t.Errorf("clone hook ran %d times, want 1", len(hooked))
	}
}
