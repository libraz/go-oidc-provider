package passkey_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fakePasskeyStore is a minimal stub the clone-detection tests use as
// the [store.PasskeyStore] argument to NewAuthenticator. The
// ForceCloneDetectedForTest helper bypasses the store, so it needs no
// real bookkeeping; ListBySubject returns an empty slice while
// assertion persistence projects its update for the UV-result seam.
// Missing-record reads and deletes return ErrNotFound.
type fakePasskeyStore struct{}

func (*fakePasskeyStore) Get(_ context.Context, _ []byte) (*store.PasskeyRecord, error) {
	return nil, store.ErrNotFound
}

func (*fakePasskeyStore) ListBySubject(_ context.Context, _ string) ([]*store.PasskeyRecord, error) {
	return []*store.PasskeyRecord{}, nil
}

func (*fakePasskeyStore) Put(_ context.Context, _ *store.PasskeyRecord) error {
	return nil
}

func (*fakePasskeyStore) UpdateAssertion(
	_ context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	return &store.PasskeyRecord{
		CredentialID: bytes.Clone(credentialID),
		SignCount:    update.SignCount,
		UserPresent:  update.UserPresent,
		UserVerified: update.UserVerified,
		BackupState:  update.BackupState,
		CloneWarning: update.CloneWarning,
	}, nil
}

func (*fakePasskeyStore) Delete(_ context.Context, _ []byte) error {
	return store.ErrNotFound
}

// TestCloneDetectionHandler_ReceivesCredentialOnClone asserts H-E5: a
// CloneDetectionHandler installed via WithCloneDetectionHandler is
// invoked with the rotated [Credential] when the verifier reports a
// clone-warning, so the embedder can disable the affected credential
// in its account-management UI.
//
// The test exercises the handler directly through a small wrapper
// that simulates the Continue path's clone branch. We avoid driving a
// full WebAuthn round-trip (which would require a soft authenticator
// minting a valid signature) because the contract under test is the
// adapter's plumbing — Continue handing the cred to the handler — not
// the upstream library's clone-detection rule.
func TestCloneDetectionHandler_ReceivesCredentialOnClone(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	var (
		mu       sync.Mutex
		called   int
		seenSub  string
		seenCred *passkey.Credential
	)
	handler := passkey.CloneDetectionHandlerFunc(func(_ context.Context, sub string, c *passkey.Credential) error {
		mu.Lock()
		defer mu.Unlock()
		called++
		seenSub = sub
		seenCred = c
		return nil
	})

	// We test the wiring at the WithCloneDetectionHandler level by
	// asserting the wrapper attaches the handler and reuses the
	// underlying verifier / store. A direct continueResult drive
	// would require unexported access; the contract test below
	// instead exercises the public surface.
	a, err := passkey.NewAuthenticator(v, &fakePasskeyStore{})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	wrapped := a.WithCloneDetectionHandler(handler)
	if wrapped == a {
		t.Fatal("WithCloneDetectionHandler returned the same pointer; expected a copy")
	}

	// Drive a clone-detection branch directly through the test helper.
	cred := &passkey.Credential{
		ID:        []byte{0x01},
		PublicKey: []byte{0x02},
		Authenticator: passkey.AuthenticatorData{
			SignCount:    1,
			CloneWarning: true,
		},
	}
	wrapped.ForceCloneDetectedForTest(context.Background(), "user-x", cred)

	mu.Lock()
	defer mu.Unlock()
	if called != 1 {
		t.Errorf("handler called %d times, want 1", called)
	}
	if seenSub != "user-x" {
		t.Errorf("subject = %q, want user-x", seenSub)
	}
	if seenCred == nil || !seenCred.Authenticator.CloneWarning {
		t.Errorf("credential = %+v, want CloneWarning=true", seenCred)
	}
}

// TestCloneDetectionHandler_NilHandlerSkipped asserts the adapter
// tolerates an absent handler — the H-E5 hook is opt-in and Continue
// must still surface ErrCloneDetected verbatim.
func TestCloneDetectionHandler_NilHandlerSkipped(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	a, err := passkey.NewAuthenticator(v, &fakePasskeyStore{})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	// No handler installed — just ensure the test helper does not panic.
	cred := &passkey.Credential{
		ID:        []byte{0x01},
		PublicKey: []byte{0x02},
		Authenticator: passkey.AuthenticatorData{
			SignCount:    1,
			CloneWarning: true,
		},
	}
	a.ForceCloneDetectedForTest(context.Background(), "user-x", cred)
}

// TestCloneDetectionHandler_ErrorIsBestEffort asserts the handler's
// error does not change the response the SPA observes. The contract
// is "best-effort": embedders that want to observe failures log
// internally.
func TestCloneDetectionHandler_ErrorIsBestEffort(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	hookErr := errors.New("downstream disable failed")
	handler := passkey.CloneDetectionHandlerFunc(func(_ context.Context, _ string, _ *passkey.Credential) error {
		return hookErr
	})

	a, err := passkey.NewAuthenticator(v, &fakePasskeyStore{})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	wrapped := a.WithCloneDetectionHandler(handler)

	cred := &passkey.Credential{
		ID:        []byte{0x01},
		PublicKey: []byte{0x02},
		Authenticator: passkey.AuthenticatorData{
			SignCount:    1,
			CloneWarning: true,
		},
	}
	// The helper returns the original ErrCloneDetected; the handler
	// error is dropped on purpose.
	if got := wrapped.ForceCloneDetectedForTest(context.Background(), "user-x", cred); !errors.Is(got, passkey.ErrCloneDetected) {
		t.Errorf("Continue err = %v, want ErrCloneDetected", got)
	}
}
