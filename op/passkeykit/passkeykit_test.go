package passkeykit_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/passkeykit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	testRPID    = "localhost"
	testOrigin  = "http://localhost:9090"
	testSubject = "user-alice"
)

func testUser() passkeykit.User {
	return passkeykit.User{
		Subject:     testSubject,
		Name:        "alice@example.com",
		DisplayName: "Alice Example",
	}
}

// newRegistrar builds a registrar over a fresh in-memory store and
// returns both, so a test can assert what enrolment actually wrote.
func newRegistrar(t *testing.T) (*passkeykit.Registrar, store.PasskeyStore) {
	t.Helper()
	st := inmem.New()
	step := op.PrimaryPasskey{
		Store:         st.Passkeys(),
		RPID:          testRPID,
		RPDisplayName: "Example Identity",
		RPOrigins:     []string{testOrigin},
		SessionTTL:    5 * time.Minute,
	}
	reg, err := passkeykit.New(step)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return reg, st.Passkeys()
}

// enrol runs one complete ceremony against a soft authenticator and
// returns the persisted record.
func enrol(t *testing.T, reg *passkeykit.Registrar, key *softkey.Key) *store.PasskeyRecord {
	t.Helper()
	ctx := t.Context()

	opts, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(testRPID, testOrigin, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec, err := reg.Register(ctx, session, testUser(), response)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return rec
}

func newKey(t *testing.T) *softkey.Key {
	t.Helper()
	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}
	return key
}

// TestRegister_PersistsUsableRecord is the happy path: a ceremony driven
// end to end against a real ES256 authenticator produces a stored record
// bound to the subject and keyed by the credential the authenticator
// minted.
func TestRegister_PersistsUsableRecord(t *testing.T) {
	t.Parallel()

	reg, passkeys := newRegistrar(t)
	key := newKey(t)
	rec := enrol(t, reg, key)

	if rec.Subject != testSubject {
		t.Errorf("Subject=%q want %q", rec.Subject, testSubject)
	}
	if string(rec.CredentialID) != string(key.CredentialID()) {
		t.Errorf("CredentialID=%x want %x", rec.CredentialID, key.CredentialID())
	}
	if len(rec.PublicKey) == 0 {
		t.Error("PublicKey is empty; the verifier would have nothing to check assertions against")
	}
	if rec.AttestationType != "none" {
		t.Errorf("AttestationType=%q want none", rec.AttestationType)
	}
	if rec.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if !rec.UserPresent {
		t.Error("UserPresent is false; the ceremony required user presence")
	}

	stored, err := passkeys.Get(t.Context(), key.CredentialID())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Subject != testSubject {
		t.Errorf("stored Subject=%q want %q", stored.Subject, testSubject)
	}
}

// TestBegin_ExcludesAlreadyRegisteredCredentials pins the round trip
// between the two calls: a credential enrolment persisted has to come
// back as an exclusion on the next ceremony, or the authenticator holding
// it is never told to decline.
func TestBegin_ExcludesAlreadyRegisteredCredentials(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistrar(t)
	first := newKey(t)
	enrol(t, reg, first)

	opts, _, err := reg.Begin(t.Context(), testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	var doc struct {
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	}
	if err := json.Unmarshal(opts.PublicKey, &doc); err != nil {
		t.Fatalf("Unmarshal options: %v", err)
	}
	if len(doc.ExcludeCredentials) != 1 {
		t.Fatalf("excludeCredentials has %d entries, want 1: %s", len(doc.ExcludeCredentials), opts.PublicKey)
	}
}

// TestRegister_RejectsDuplicateCredential covers the server-side half of
// the exclude list: an authenticator that ignored excludeCredentials and
// re-registered the same credential is refused rather than silently
// overwriting the stored record.
func TestRegister_RejectsDuplicateCredential(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, _ := newRegistrar(t)
	key := newKey(t)
	enrol(t, reg, key)

	opts, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(testRPID, testOrigin, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := reg.Register(ctx, session, testUser(), response); !errors.Is(err, passkeykit.ErrCredentialAlreadyExists) {
		t.Fatalf("err=%v want ErrCredentialAlreadyExists", err)
	}
}

// TestFinish_RejectsForeignOrigin asserts the ceremony is bound to the
// origins the Relying Party declared. A response produced on another
// page must not register, whatever else about it is well-formed.
func TestFinish_RejectsForeignOrigin(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, _ := newRegistrar(t)
	key := newKey(t)

	opts, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(testRPID, "https://evil.example.com", challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := reg.Finish(ctx, session, testUser(), response); !errors.Is(err, passkeykit.ErrAttestationInvalid) {
		t.Fatalf("err=%v want ErrAttestationInvalid", err)
	}
}

// TestFinish_RejectsForeignChallenge asserts the challenge is what binds
// the two halves of the ceremony: a response the authenticator produced
// for some other challenge does not complete this one.
func TestFinish_RejectsForeignChallenge(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, _ := newRegistrar(t)
	key := newKey(t)

	_, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// A challenge from a different ceremony, of the same shape.
	other, _, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(other.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(testRPID, testOrigin, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := reg.Finish(ctx, session, testUser(), response); !errors.Is(err, passkeykit.ErrAttestationInvalid) {
		t.Fatalf("err=%v want ErrAttestationInvalid", err)
	}
}

// TestFinish_RejectsSubjectMismatch covers the guard that stops one
// account's challenge being redeemed into another account's credential
// list.
func TestFinish_RejectsSubjectMismatch(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, _ := newRegistrar(t)
	key := newKey(t)

	opts, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(testRPID, testOrigin, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	victim := passkeykit.User{Subject: "user-bob", Name: "bob@example.com"}
	if _, err := reg.Finish(ctx, session, victim, response); !errors.Is(err, passkeykit.ErrSubjectMismatch) {
		t.Fatalf("err=%v want ErrSubjectMismatch", err)
	}
}

// TestFinish_RejectsExpiredSession asserts the challenge window closes.
// The session is round-tripped through JSON first, because that is how an
// embedder ferries it and it is the shape an expired one arrives in.
func TestFinish_RejectsExpiredSession(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	st := inmem.New()
	reg, err := passkeykit.New(op.PrimaryPasskey{
		Store:         st.Passkeys(),
		RPID:          testRPID,
		RPDisplayName: "Example Identity",
		RPOrigins:     []string{testOrigin},
		// The shortest window the package accepts still has to elapse
		// for the check to fire, so the session is rewritten below
		// rather than waited out.
		SessionTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	opts, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := newKey(t).Create(testRPID, testOrigin, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	expired := backdateSession(t, session, -2*time.Minute)
	if _, err := reg.Finish(ctx, expired, testUser(), response); !errors.Is(err, passkeykit.ErrChallengeExpired) {
		t.Fatalf("err=%v want ErrChallengeExpired", err)
	}
}

// TestFinish_RejectsMalformedResponse covers the bodies a handler gets
// when the SPA posts something other than a credential.
func TestFinish_RejectsMalformedResponse(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, _ := newRegistrar(t)
	_, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "empty", body: nil},
		{name: "not-json", body: []byte("not-json")},
		{name: "empty-object", body: []byte(`{}`)},
		{name: "wrong-type", body: []byte(`{"id":"YWJj","rawId":"YWJj","type":"password","response":{}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := reg.Finish(ctx, session, testUser(), tc.body); !errors.Is(err, passkeykit.ErrInvalidResponse) {
				t.Fatalf("err=%v want ErrInvalidResponse", err)
			}
		})
	}
}

// TestSession_RoundTripsThroughJSON asserts a session survives the trip
// an embedder puts it through — marshalled into a cookie or a row and
// read back — because a session that only works in-process would make
// the two-request shape of the ceremony unimplementable.
func TestSession_RoundTripsThroughJSON(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, _ := newRegistrar(t)
	key := newKey(t)

	opts, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if session.ExpiresAt().IsZero() {
		t.Error("ExpiresAt is zero; an embedder has nothing to size the cookie from")
	}

	blob, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Marshal session: %v", err)
	}
	var restored passkeykit.Session
	if err := json.Unmarshal(blob, &restored); err != nil {
		t.Fatalf("Unmarshal session: %v", err)
	}
	if !restored.ExpiresAt().Equal(session.ExpiresAt()) {
		t.Errorf("ExpiresAt=%v want %v", restored.ExpiresAt(), session.ExpiresAt())
	}

	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(testRPID, testOrigin, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := reg.Register(ctx, &restored, testUser(), response); err != nil {
		t.Fatalf("Register with restored session: %v", err)
	}
}

// TestFinish_DoesNotPersist separates the two write modes: Finish hands
// back a record for a caller that owns the transaction, and must not
// have written it already.
func TestFinish_DoesNotPersist(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, passkeys := newRegistrar(t)
	key := newKey(t)

	opts, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(testRPID, testOrigin, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := reg.Finish(ctx, session, testUser(), response); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	if _, err := passkeys.Get(ctx, key.CredentialID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get err=%v want ErrNotFound; Finish must not write", err)
	}
}

// TestNew_RejectsUnusableConfiguration pins that a configuration the
// login step would refuse is refused here too, so an embedder cannot
// build an enrolment screen against settings op.New will reject at
// startup.
func TestNew_RejectsUnusableConfiguration(t *testing.T) {
	t.Parallel()

	base := func() op.PrimaryPasskey {
		return op.PrimaryPasskey{
			Store:         inmem.New().Passkeys(),
			RPID:          testRPID,
			RPDisplayName: "Example Identity",
			RPOrigins:     []string{testOrigin},
		}
	}

	for _, tc := range []struct {
		name string
		mut  func(*op.PrimaryPasskey)
		want error
	}{
		{
			name: "nil-store",
			mut:  func(s *op.PrimaryPasskey) { s.Store = nil },
			want: passkeykit.ErrStoreRequired,
		},
		{
			name: "typed-nil-store",
			mut:  func(s *op.PrimaryPasskey) { s.Store = (*nilStore)(nil) },
			want: passkeykit.ErrStoreRequired,
		},
		{
			name: "no-rpid",
			mut:  func(s *op.PrimaryPasskey) { s.RPID = "" },
		},
		{
			name: "no-display-name",
			mut:  func(s *op.PrimaryPasskey) { s.RPDisplayName = "" },
		},
		{
			name: "no-origins",
			mut:  func(s *op.PrimaryPasskey) { s.RPOrigins = nil },
		},
		{
			name: "origin-outside-rpid",
			mut:  func(s *op.PrimaryPasskey) { s.RPOrigins = []string{"https://other.example.net"} },
		},
		{
			name: "malformed-aaguid",
			mut:  func(s *op.PrimaryPasskey) { s.AAGUIDAllowlist = []string{"not-a-uuid"} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step := base()
			tc.mut(&step)
			_, err := passkeykit.New(step)
			if err == nil {
				t.Fatal("New accepted a configuration the login step rejects")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}
}

// TestCallShapeGuards covers the argument checks that report a caller
// mistake as a sentinel rather than as a ceremony failure.
func TestCallShapeGuards(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg, _ := newRegistrar(t)

	if _, _, err := reg.Begin(ctx, passkeykit.User{}); !errors.Is(err, passkeykit.ErrSubjectRequired) {
		t.Errorf("Begin err=%v want ErrSubjectRequired", err)
	}
	if _, err := reg.Finish(ctx, nil, testUser(), []byte(`{}`)); !errors.Is(err, passkeykit.ErrSessionRequired) {
		t.Errorf("Finish err=%v want ErrSessionRequired", err)
	}
	_, session, err := reg.Begin(ctx, testUser())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := reg.Finish(ctx, session, passkeykit.User{}, []byte(`{}`)); !errors.Is(err, passkeykit.ErrSubjectRequired) {
		t.Errorf("Finish err=%v want ErrSubjectRequired", err)
	}
}

// backdateSession shifts a session's expiry by rewriting its serialised
// form. The field is not settable through the public surface — which is
// the point of the type — so the test reaches it the same way a tampered
// cookie would.
func backdateSession(t *testing.T, s *passkeykit.Session, delta time.Duration) *passkeykit.Session {
	t.Helper()
	blob, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal session: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatalf("Unmarshal session: %v", err)
	}
	shifted, err := json.Marshal(s.ExpiresAt().Add(delta))
	if err != nil {
		t.Fatalf("Marshal expiry: %v", err)
	}
	raw["expires"] = shifted
	blob, err = json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal session: %v", err)
	}
	var out passkeykit.Session
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("Unmarshal session: %v", err)
	}
	return &out
}

// nilStore exists only so a typed-nil interface value can be built. Its
// methods are never reached — reaching one would mean the typed-nil
// guard let a store through that panics on first use, so they say so.
type nilStore struct{}

var errNilStoreCalled = errors.New("nilStore method called: the typed-nil guard did not fire")

func (*nilStore) Get(context.Context, []byte) (*store.PasskeyRecord, error) {
	return nil, errNilStoreCalled
}

func (*nilStore) ListBySubject(context.Context, string) ([]*store.PasskeyRecord, error) {
	return nil, errNilStoreCalled
}

func (*nilStore) Put(context.Context, *store.PasskeyRecord) error { return errNilStoreCalled }

func (*nilStore) UpdateAssertion(context.Context, []byte, store.PasskeyAssertionUpdate) (*store.PasskeyRecord, error) {
	return nil, errNilStoreCalled
}

func (*nilStore) Delete(context.Context, []byte) error { return errNilStoreCalled }
