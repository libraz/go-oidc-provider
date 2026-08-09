package contract

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// PasskeyFactory builds a fresh standalone [store.PasskeyStore] for a
// single contract sub-test. Passkeys are intentionally separate from
// [Backend] because they are supplied directly to the passkey
// authenticator rather than through the aggregate [store.Store].
type PasskeyFactory func(t *testing.T) store.PasskeyStore

// RunPasskeys exercises the atomic assertion-update guarantees of
// [store.PasskeyStore]. Adapter authors should call it from their
// black-box test suite in addition to any backend-specific tests.
func RunPasskeys(t *testing.T, f PasskeyFactory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, store.PasskeyStore)
	}{
		{"UpdateAssertionReverseOrderIsMonotonic", passkeyReverseOrder},
		{"StaleCloneWarningRemainsSticky", passkeyStaleCloneWarning},
		{"CounterlessAssertionUpdatesFlags", passkeyCounterless},
		{"UpdateAssertionPreservesRegistrationFields", passkeyPreservesRegistration},
		{"UpdateAssertionReturnsClone", passkeyReturnsClone},
		{"UpdateAssertionNotFound", passkeyUpdateNotFound},
		{"PutRefusesCrossSubjectCredential", passkeyCrossSubjectPut},
		{"PutRewritesOwnCredential", passkeyOwnCredentialPut},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, f(t))
		})
	}
}

func passkeyReverseOrder(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	seedPasskey(t, ctx, s)

	high := store.PasskeyAssertionUpdate{
		ExpectedSignCount: 7,
		SignCount:         9,
		UserPresent:       true,
		UserVerified:      true,
		BackupState:       true,
		CloneWarning:      true,
	}
	low := store.PasskeyAssertionUpdate{
		ExpectedSignCount: 7,
		SignCount:         8,
	}

	// Model two assertions that both verified against counter 7, then
	// force the newer counter to persist before the older request.
	highDone := make(chan struct{})
	errs := make(chan error, 2)
	results := make(chan *store.PasskeyRecord, 1)
	go func() {
		_, err := s.UpdateAssertion(ctx, []byte("credential"), high)
		errs <- err
		close(highDone)
	}()
	go func() {
		<-highDone
		got, err := s.UpdateAssertion(ctx, []byte("credential"), low)
		errs <- err
		results <- got
	}()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("UpdateAssertion: %v", err)
		}
	}
	got := <-results
	if got == nil {
		t.Fatal("UpdateAssertion returned nil record")
	}
	if got.SignCount != high.SignCount {
		t.Errorf("SignCount = %d, want %d", got.SignCount, high.SignCount)
	}
	if !got.UserPresent || !got.UserVerified || !got.BackupState {
		t.Errorf("assertion flags rewound: %+v", got)
	}
	if !got.CloneWarning {
		t.Error("CloneWarning rewound to false")
	}
}

func passkeyStaleCloneWarning(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	seedPasskey(t, ctx, s)

	if _, err := s.UpdateAssertion(ctx, []byte("credential"), store.PasskeyAssertionUpdate{
		ExpectedSignCount: 7,
		SignCount:         9,
		UserPresent:       true,
		UserVerified:      true,
	}); err != nil {
		t.Fatalf("UpdateAssertion fresh: %v", err)
	}
	got, err := s.UpdateAssertion(ctx, []byte("credential"), store.PasskeyAssertionUpdate{
		ExpectedSignCount: 7,
		SignCount:         7,
		CloneWarning:      true,
	})
	if err != nil {
		t.Fatalf("UpdateAssertion stale clone: %v", err)
	}
	if got.SignCount != 9 {
		t.Errorf("SignCount = %d, want 9", got.SignCount)
	}
	if !got.CloneWarning {
		t.Error("CloneWarning = false, want true")
	}

	got, err = s.UpdateAssertion(ctx, []byte("credential"), store.PasskeyAssertionUpdate{
		ExpectedSignCount: 9,
		SignCount:         10,
		UserPresent:       true,
		UserVerified:      true,
		CloneWarning:      false,
	})
	if err != nil {
		t.Fatalf("UpdateAssertion after clone warning: %v", err)
	}
	if !got.CloneWarning {
		t.Error("newer assertion cleared CloneWarning")
	}
}

func passkeyCounterless(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	seed := passkeyContractRecord()
	seed.SignCount = 0
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put seed: %v", err)
	}

	got, err := s.UpdateAssertion(ctx, seed.CredentialID, store.PasskeyAssertionUpdate{
		UserPresent:  true,
		UserVerified: true,
		BackupState:  true,
	})
	if err != nil {
		t.Fatalf("UpdateAssertion: %v", err)
	}
	if !got.UserPresent || !got.UserVerified || !got.BackupState {
		t.Errorf("assertion flags not updated: %+v", got)
	}
}

func passkeyPreservesRegistration(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	want := passkeyContractRecord()
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put seed: %v", err)
	}

	got, err := s.UpdateAssertion(ctx, want.CredentialID, store.PasskeyAssertionUpdate{
		ExpectedSignCount: 7,
		SignCount:         8,
	})
	if err != nil {
		t.Fatalf("UpdateAssertion: %v", err)
	}
	if got.Subject != want.Subject ||
		!bytes.Equal(got.PublicKey, want.PublicKey) ||
		!bytes.Equal(got.AAGUID, want.AAGUID) ||
		got.BackupEligible != want.BackupEligible ||
		!got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("registration fields changed: got=%+v want=%+v", got, want)
	}
}

func passkeyReturnsClone(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	seedPasskey(t, ctx, s)

	got, err := s.UpdateAssertion(ctx, []byte("credential"), store.PasskeyAssertionUpdate{
		ExpectedSignCount: 7,
		SignCount:         8,
	})
	if err != nil {
		t.Fatalf("UpdateAssertion: %v", err)
	}
	got.PublicKey[0] ^= 0xff

	again, err := s.Get(ctx, []byte("credential"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if again.PublicKey[0] == got.PublicKey[0] {
		t.Error("returned record mutation changed stored PublicKey")
	}
}

func passkeyUpdateNotFound(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	_, err := s.UpdateAssertion(
		context.Background(),
		[]byte("missing"),
		store.PasskeyAssertionUpdate{},
	)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

// passkeyCrossSubjectPut drives the takeover a credential ID makes
// possible. The record is keyed on the credential ID alone, so an upsert
// that accepted a different Subject would not add a credential — it
// would move one, and the subject that held it would lose the
// authenticator it logs in with, with nothing in the account-management
// surface to undo it (W3C WebAuthn Level 3 §7.1 step 27).
func passkeyCrossSubjectPut(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	victim := passkeyContractRecord()
	seedPasskey(t, ctx, s)

	stolen := passkeyContractRecord()
	stolen.Subject = "other-subject"
	stolen.PublicKey = []byte("attacker-public-key")
	stolen.SignCount = 0
	if err := s.Put(ctx, stolen); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("Put err=%v want ErrAlreadyExists", err)
	}

	got, err := s.Get(ctx, victim.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Subject != victim.Subject {
		t.Errorf("Subject=%q want %q — the credential changed hands", got.Subject, victim.Subject)
	}
	if !bytes.Equal(got.PublicKey, victim.PublicKey) {
		t.Errorf("PublicKey=%x want %x — the refused write still landed", got.PublicKey, victim.PublicKey)
	}

	held, err := s.ListBySubject(ctx, victim.Subject)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(held) != 1 {
		t.Fatalf("victim holds %d credentials, want 1 — the passkey was unlinked", len(held))
	}
	taken, err := s.ListBySubject(ctx, stolen.Subject)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(taken) != 0 {
		t.Errorf("other subject holds %d credentials, want 0", len(taken))
	}
}

// passkeyOwnCredentialPut is the regression guard on the check above:
// re-writing a record under the subject that already holds it is the
// ordinary account-management update and must still be an upsert.
func passkeyOwnCredentialPut(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	seedPasskey(t, ctx, s)

	updated := passkeyContractRecord()
	updated.SignCount = 11
	updated.Attachment = "platform"
	updated.Transports = []string{"hybrid"}
	if err := s.Put(ctx, updated); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, updated.CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SignCount != updated.SignCount {
		t.Errorf("SignCount=%d want %d", got.SignCount, updated.SignCount)
	}
	if got.Attachment != updated.Attachment {
		t.Errorf("Attachment=%q want %q", got.Attachment, updated.Attachment)
	}
}

func seedPasskey(t *testing.T, ctx context.Context, s store.PasskeyStore) {
	t.Helper()
	if err := s.Put(ctx, passkeyContractRecord()); err != nil {
		t.Fatalf("Put seed: %v", err)
	}
}

func passkeyContractRecord() *store.PasskeyRecord {
	return &store.PasskeyRecord{
		CredentialID:   []byte("credential"),
		Subject:        "subject",
		PublicKey:      []byte("public-key"),
		AAGUID:         bytes.Repeat([]byte{0x01}, 16),
		SignCount:      7,
		UserPresent:    true,
		UserVerified:   false,
		BackupEligible: true,
		CreatedAt:      Reference,
	}
}
