package passkey_test

// A credential ID identifies one credential across the whole Relying
// Party, not one per account, and the record it names is stored under
// that ID alone. A registration that is allowed to name a credential
// somebody else holds therefore does not add a credential — it moves
// one, and the subject that held it loses the authenticator it logs in
// with. WebAuthn Level 3 §7.1 step 27 is the requirement; these tests
// are the enforcement.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
	"github.com/libraz/go-oidc-provider/op/store"
)

const attackerSubject = "user-mallory"

// enrolInto registers key to subject and persists the resulting record,
// leaving the store in the state a completed enrolment produces.
func enrolInto(
	t *testing.T,
	v *passkey.Verifier,
	credentials store.PasskeyStore,
	key *softkey.Key,
	subject string,
) *passkey.Credential {
	t.Helper()
	cred, err := registerAs(t, v, credentials, key, subject, nil)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	rec := passkey.RecordFromCredential(subject, *cred)
	if err := credentials.Put(context.Background(), &rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return cred
}

// TestFinishRegistration_RefusesCredentialHeldByAnotherSubject drives
// the takeover: an authenticator under the attacker's control presents
// the credential ID of a passkey already registered to somebody else.
// The ceremony must refuse, and the victim's credential must still be
// theirs afterwards.
func TestFinishRegistration_RefusesCredentialHeldByAnotherSubject(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	v := newTestVerifier(t, time.Now())
	credentials := newEmptyPasskeyStore(t)
	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}
	victim := enrolInto(t, v, credentials, key, roundTripSubject)

	// The attacker replays the victim's credential ID from an
	// authenticator they control — the exclude list Begin sends is
	// built from the attacker's own credentials and names nothing.
	if _, err := registerAs(t, v, credentials, key, attackerSubject, nil); !errors.Is(err, passkey.ErrCredentialAlreadyExists) {
		t.Fatalf("err=%v want ErrCredentialAlreadyExists", err)
	}

	stored, err := credentials.Get(ctx, victim.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Subject != roundTripSubject {
		t.Errorf("stored Subject=%q want %q — the credential changed hands", stored.Subject, roundTripSubject)
	}
	held, err := credentials.ListBySubject(ctx, roundTripSubject)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(held) != 1 {
		t.Fatalf("victim holds %d credentials, want 1 — the passkey was unlinked", len(held))
	}
	attacker, err := credentials.ListBySubject(ctx, attackerSubject)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(attacker) != 0 {
		t.Errorf("attacker holds %d credentials, want 0", len(attacker))
	}
}

// TestFinishRegistration_AcceptsOwnCredentialRewrite is the regression
// guard on the check above: the owner of a credential re-running the
// ceremony for it is an update, not a takeover, and must still be
// accepted.
func TestFinishRegistration_AcceptsOwnCredentialRewrite(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Now())
	credentials := newEmptyPasskeyStore(t)
	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}
	first := enrolInto(t, v, credentials, key, roundTripSubject)

	again, err := registerAs(t, v, credentials, key, roundTripSubject, nil)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if string(again.ID) != string(first.ID) {
		t.Errorf("credential ID=%x want %x", again.ID, first.ID)
	}
}

// TestFinishRegistration_ReportsStoreFaultRatherThanAdmitting pins the
// fail-closed direction: a store that cannot answer who holds the
// credential is not evidence that nobody does.
func TestFinishRegistration_ReportsStoreFaultRatherThanAdmitting(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Now())
	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}
	_, err = registerAs(t, v, &brokenLookupStore{}, key, roundTripSubject, nil)
	if !errors.Is(err, errLookupUnavailable) {
		t.Fatalf("err=%v want the store fault to surface", err)
	}
}

// errLookupUnavailable stands in for a backend outage during the owner
// lookup.
var errLookupUnavailable = errors.New("passkey store unavailable")

// brokenLookupStore fails every read. Only Get is reached by the
// registration ceremony; the rest report the same fault so a future
// call site cannot mistake silence for success.
type brokenLookupStore struct{}

func (*brokenLookupStore) Get(context.Context, []byte) (*store.PasskeyRecord, error) {
	return nil, errLookupUnavailable
}

func (*brokenLookupStore) ListBySubject(context.Context, string) ([]*store.PasskeyRecord, error) {
	return nil, errLookupUnavailable
}

func (*brokenLookupStore) Put(context.Context, *store.PasskeyRecord) error {
	return errLookupUnavailable
}

func (*brokenLookupStore) UpdateAssertion(
	context.Context,
	[]byte,
	store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	return nil, errLookupUnavailable
}

func (*brokenLookupStore) Delete(context.Context, []byte) error { return errLookupUnavailable }
