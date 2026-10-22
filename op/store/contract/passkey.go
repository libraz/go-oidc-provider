package contract

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// PasskeyFactory builds a fresh standalone [store.PasskeyStore] for a
// single contract sub-test. Passkeys are intentionally separate from
// [Backend] because they are supplied directly to the passkey
// authenticator rather than through the aggregate [store.Store].
type PasskeyFactory func(t *testing.T) store.PasskeyStore

//nolint:gochecknoglobals // sub-test table; declared once so the Run* entry point and the coverage check can iterate.
var passkeyCases = []factorCase[store.PasskeyStore]{
	{"UpdateAssertionReverseOrderIsMonotonic", passkeyReverseOrder},
	{"StaleCloneWarningRemainsSticky", passkeyStaleCloneWarning},
	{"CounterlessAssertionUpdatesFlags", passkeyCounterless},
	{"UpdateAssertionPreservesRegistrationFields", passkeyPreservesRegistration},
	{"UpdateAssertionReturnsClone", passkeyReturnsClone},
	{"UpdateAssertionNotFound", passkeyUpdateNotFound},
	{"PutRefusesCrossSubjectCredential", passkeyCrossSubjectPut},
	{"PutRewritesOwnCredential", passkeyOwnCredentialPut},
	{"ConcurrentCrossSubjectPutHasOneOwner", passkeyConcurrentCrossSubjectPut},
	{"ConcurrentUpdateAssertionKeepsHighestSignCount", passkeyConcurrentUpdateAssertion},
}

// RunPasskeys exercises the atomic assertion-update guarantees of
// [store.PasskeyStore]. Adapter authors should call it from their
// black-box test suite in addition to any backend-specific tests.
func RunPasskeys(t *testing.T, f PasskeyFactory) {
	t.Helper()
	for _, tc := range passkeyCases {
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

	// Model two assertions that both verified against counter 7 and
	// reach the store newest first.
	if _, err := s.UpdateAssertion(ctx, []byte("credential"), high); err != nil {
		t.Fatalf("UpdateAssertion high: %v", err)
	}
	got, err := s.UpdateAssertion(ctx, []byte("credential"), low)
	if err != nil {
		t.Fatalf("UpdateAssertion low: %v", err)
	}
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

// passkeyConcurrentCrossSubjectPut is [passkeyCrossSubjectPut] under
// the traffic the atomicity rule on [store.PasskeyStore.Put] exists for:
// several subjects registering one credential ID at once. Exactly one
// may own it and the rest MUST get [store.ErrAlreadyExists]. A backend
// that checks the owner and then writes lets every racer find the ID
// free, tells each of them it succeeded, and leaves the credential with
// whichever subject wrote last.
func passkeyConcurrentCrossSubjectPut(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	id := []byte("credential-put-race")
	subject := func(i int) string { return "subject-put-race-" + strconv.Itoa(i) }

	errs := race(
		func() { _, _ = s.Get(ctx, []byte("credential-race-warmup")) },
		everyRacer(func(i int) error {
			rec := passkeyContractRecord()
			rec.CredentialID = id
			rec.Subject = subject(i)
			return s.Put(ctx, rec)
		})...,
	)
	winner := assertOneWinner(t, "Passkeys().Put", errs)
	for i, err := range errs {
		if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("losing Put %d: want ErrAlreadyExists, got %v", i, err)
		}
	}

	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after the race: %v", err)
	}
	if got.Subject != subject(winner) {
		t.Fatalf("Subject=%q want %q — the credential belongs to a subject whose Put was refused",
			got.Subject, subject(winner))
	}
	for i := range concurrentRacers {
		held, err := s.ListBySubject(ctx, subject(i))
		if err != nil {
			t.Fatalf("ListBySubject %d: %v", i, err)
		}
		want := 0
		if i == winner {
			want = 1
		}
		if len(held) != want {
			t.Fatalf("subject %q holds %d credentials after the race, want %d", subject(i), len(held), want)
		}
	}
}

// passkeyUpdateRaceRounds is how many fresh credentials
// [passkeyConcurrentUpdateAssertion] races. Which racer writes last is
// down to scheduling, so a read-modify-write backend keeps the highest
// counter by luck once in [concurrentRacers] rounds; repeating makes the
// rewind certain rather than likely.
const passkeyUpdateRaceRounds = 4

// passkeyConcurrentUpdateAssertion drives the monotonicity
// [store.PasskeyStore.UpdateAssertion] declares under concurrent
// assertions that all verified against the same counter. Whatever order
// they land in, SignCount MUST end at the highest value presented and a
// CloneWarning any of them carried MUST stick. A backend that reads the
// record, applies the rules in application code and writes it back
// keeps whichever write landed last, rewinding the counter clone
// detection compares the next assertion against.
func passkeyConcurrentUpdateAssertion(t *testing.T, s store.PasskeyStore) {
	t.Helper()
	ctx := context.Background()
	expected := passkeyContractRecord().SignCount
	counts := make([]uint32, concurrentRacers)
	highest := expected
	for i := range counts {
		highest++
		counts[i] = highest
	}

	for round := range passkeyUpdateRaceRounds {
		rec := passkeyContractRecord()
		rec.CredentialID = []byte("credential-update-race-" + strconv.Itoa(round))
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("Put round %d: %v", round, err)
		}

		errs := race(
			func() { _, _ = s.Get(ctx, []byte("credential-race-warmup")) },
			everyRacer(func(i int) error {
				_, err := s.UpdateAssertion(ctx, rec.CredentialID, store.PasskeyAssertionUpdate{
					ExpectedSignCount: expected,
					SignCount:         counts[i],
					UserPresent:       true,
					CloneWarning:      i == 0,
				})
				return err
			})...,
		)
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: concurrent UpdateAssertion %d: %v", round, i, err)
			}
		}

		got, err := s.Get(ctx, rec.CredentialID)
		if err != nil {
			t.Fatalf("Get round %d: %v", round, err)
		}
		if got.SignCount != highest {
			t.Fatalf("round %d: SignCount = %d after the race, want the highest presented %d — "+
				"a later write rewound the counter", round, got.SignCount, highest)
		}
		if !got.CloneWarning {
			t.Fatalf("round %d: CloneWarning = false after the race — a later write cleared it", round)
		}
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
