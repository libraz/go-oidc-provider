package op_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	erasedSubject = "alice"
	keptSubject   = "bob"
	sharedGroup   = "chooser-shared"
)

var erasureNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// erasureUsers is a user directory whose live subjects the test fixes, so
// a test can present a subject the directory has already deleted.
type erasureUsers struct {
	mu   sync.Mutex
	live map[string]bool
}

func newErasureUsers(subjects ...string) *erasureUsers {
	u := &erasureUsers{live: map[string]bool{}}
	for _, s := range subjects {
		u.live[s] = true
	}
	return u
}

func (u *erasureUsers) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.live[sub] {
		return nil, store.ErrNotFound
	}
	return &store.User{Subject: sub}, nil
}

func (*erasureUsers) FindByUsername(context.Context, string) (*store.User, error) {
	return nil, store.ErrNotFound
}

func (*erasureUsers) ReadPasswordHash(context.Context, string) ([]byte, error) {
	return nil, store.ErrNotFound
}

// erasureSessionsOnly hides every method of the wrapped session store but
// the core [store.SessionStore] ones, so it lacks DeleteBySubject.
type erasureSessionsOnly struct{ store.SessionStore }

// erasureLockoutsOnly hides the wrapped lockout store's Delete.
type erasureLockoutsOnly struct{ store.AuthnLockoutStore }

// erasureNoSubjectDeleteStore is the inmem store with its session store
// stripped of [store.SessionSubjectDeleter].
type erasureNoSubjectDeleteStore struct{ *inmem.Store }

func (s erasureNoSubjectDeleteStore) Sessions() store.SessionStore {
	return erasureSessionsOnly{s.Store.Sessions()}
}

// erasureFactors selects the login flow of one pairwise row: the primary
// step (passkey or password) and which second factors run as rules.
type erasureFactors struct {
	passkey, totp, recovery, emailOTP bool
}

func erasureLoginFlow(st *inmem.Store, users store.UserPasswordStore, f erasureFactors) op.LoginFlow {
	var flow op.LoginFlow
	if f.passkey {
		flow.Primary = op.PrimaryPasskey{
			Store:                   st.Passkeys(),
			RPID:                    "id.example.com",
			RPDisplayName:           "Example",
			RPOrigins:               []string{"https://id.example.com"},
			RequireUserVerification: true,
		}
	} else {
		flow.Primary = op.PrimaryPassword{Store: users}
	}
	if f.totp {
		flow.Rules = append(flow.Rules, op.RuleAlways(op.StepTOTP{
			Store: st.TOTPs(), EncryptionKey: bytes32("totp-encryption-key-32-bytes-aaa"),
		}))
	}
	if f.recovery {
		flow.Rules = append(flow.Rules, op.RuleAlways(op.StepRecoveryCode{Store: st.RecoveryCodes()}))
	}
	if f.emailOTP {
		flow.Rules = append(flow.Rules, op.RuleAlways(op.StepEmailOTP{
			Store: st.EmailOTPs(), Sender: stubMailer{}, Users: users,
		}))
	}
	return flow
}

// newErasureOP builds a Provider over backing (st, or a wrapper of it)
// with claims as the claim source and flow as the login flow.
func newErasureOP(t *testing.T, st *inmem.Store, backing store.Store, claims store.UserStore, flow op.LoginFlow, extra ...op.Option) *op.Provider {
	t.Helper()
	opts := append(validBaseOptsWithStoreNoAuthn(t, st),
		op.WithStore(backing),
		op.WithUserStore(claims),
		op.WithLoginFlow(flow),
		// The passkey rows need a UI that can run the WebAuthn ceremony.
		op.WithUI(op.SPAUI{LoginMount: "/login"}),
		op.WithClock(revokeSubjectClock{now: erasureNow}),
	)
	p, err := op.New(append(opts, extra...)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	return p
}

func newErasureStore() *inmem.Store {
	return inmem.New(inmem.WithClock(revokeSubjectClock{now: erasureNow}))
}

// sessionIDs are the sessions seeded per subject: alice holds one in the
// chooser group she shares with bob and one in a group of her own.
var sessionIDs = map[string][]string{
	erasedSubject: {"sess-alice-shared", "sess-alice-own"},
	keptSubject:   {"sess-bob-shared"},
}

// seedSubjectRecords writes one of every per-subject record for subject:
// a grant with its refresh token, sessions, a lockout counter, a TOTP
// enrolment, a recovery batch, an email OTP challenge and two passkeys.
func seedSubjectRecords(t *testing.T, st *inmem.Store, subject string) {
	t.Helper()
	ctx := context.Background()
	seedSubjectGrant(t, &testkit.Provider{Store: st}, erasureNow, "grant-"+subject, subject, "client-a")
	for _, id := range sessionIDs[subject] {
		group := sharedGroup
		if strings.HasSuffix(id, "-own") {
			group = "chooser-" + subject
		}
		if err := st.Sessions().Save(ctx, &store.Session{
			ID: id, Subject: subject, ChooserGroupID: group, AuthTime: erasureNow,
			CreatedAt: erasureNow, UpdatedAt: erasureNow, ExpiresAt: erasureNow.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Sessions.Save: %v", err)
		}
	}
	if ok, err := st.AuthnLockouts().CompareAndSwap(ctx, 0, &store.AuthnLockoutRecord{
		Subject: subject, FailedCount: 1, FirstFailureAt: erasureNow,
	}); err != nil || !ok {
		t.Fatalf("AuthnLockouts.CompareAndSwap = %v, %v", ok, err)
	}
	if err := st.TOTPs().Put(ctx, &store.TOTPRecord{
		Subject: subject, SecretCiphertext: []byte("sealed"), ConfirmedAt: erasureNow,
	}); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	if err := st.RecoveryCodes().Put(ctx, &store.RecoveryBatch{
		Subject: subject, Codes: []store.RecoveryCode{{Hash: "$argon2id$stub"}}, GeneratedAt: erasureNow,
	}); err != nil {
		t.Fatalf("RecoveryCodes.Put: %v", err)
	}
	if err := st.EmailOTPs().Put(ctx, &store.EmailOTPRecord{
		Subject: subject, CodeSalt: []byte("salt"), CodeHash: []byte("hash"),
		SentAt: erasureNow, ExpiresAt: erasureNow.Add(time.Hour),
	}); err != nil {
		t.Fatalf("EmailOTPs.Put: %v", err)
	}
	for _, n := range []string{"1", "2"} {
		if err := st.Passkeys().Put(ctx, &store.PasskeyRecord{
			CredentialID: []byte("cred-" + subject + "-" + n), Subject: subject,
			PublicKey: []byte("cose"), CreatedAt: erasureNow,
		}); err != nil {
			t.Fatalf("Passkeys.Put: %v", err)
		}
	}
}

// presence reports whether err from a lookup means the record is there.
func presence(t *testing.T, what string, err error) bool {
	t.Helper()
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	default:
		t.Fatalf("%s: %v", what, err)
		return false
	}
}

// assertSubjectRecords checks subject's sessions and lockout counter
// against present, and each factor record against whether the flow
// configured its store: a store the flow does not reference is not
// reached, so its record stays.
func assertSubjectRecords(t *testing.T, st *inmem.Store, subject string, present bool, f erasureFactors) {
	t.Helper()
	ctx := context.Background()
	assertGrantRevoked(t, &testkit.Provider{Store: st}, erasureNow.Add(-time.Second), "grant-"+subject, !present)
	for _, id := range sessionIDs[subject] {
		_, err := st.Sessions().Find(ctx, id)
		if got := presence(t, "Sessions.Find", err); got != present {
			t.Errorf("session %s present=%v, want %v", id, got, present)
		}
	}
	_, err := st.AuthnLockouts().Get(ctx, subject)
	if got := presence(t, "AuthnLockouts.Get", err); got != present {
		t.Errorf("%s lockout record present=%v, want %v", subject, got, present)
	}
	want := func(configured bool) bool { return present || !configured }
	_, err = st.TOTPs().Get(ctx, subject)
	if got := presence(t, "TOTPs.Get", err); got != want(f.totp) {
		t.Errorf("%s TOTP present=%v, want %v", subject, got, want(f.totp))
	}
	_, err = st.RecoveryCodes().Get(ctx, subject)
	if got := presence(t, "RecoveryCodes.Get", err); got != want(f.recovery) {
		t.Errorf("%s recovery batch present=%v, want %v", subject, got, want(f.recovery))
	}
	_, err = st.EmailOTPs().Get(ctx, subject)
	if got := presence(t, "EmailOTPs.Get", err); got != want(f.emailOTP) {
		t.Errorf("%s email OTP present=%v, want %v", subject, got, want(f.emailOTP))
	}
	creds, err := st.Passkeys().ListBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("Passkeys.ListBySubject: %v", err)
	}
	wantCreds := 0
	if want(f.passkey) {
		wantCreds = 2
	}
	if len(creds) != wantCreds {
		t.Errorf("%s passkeys = %d, want %d", subject, len(creds), wantCreds)
	}
}

// assertConfigurationError fails unless err is a configuration_error
// *op.Error whose message contains every want.
func assertConfigurationError(t *testing.T, err error, want ...string) {
	t.Helper()
	var opErr *op.Error
	if !errors.As(err, &opErr) || opErr.Code != "configuration_error" {
		t.Fatalf("ForgetSubject = %v, want a configuration_error *op.Error", err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("ForgetSubject error %q does not contain %q", err.Error(), w)
		}
	}
}

// TestProvider_ForgetSubject_ErasesOnlyThatSubject runs the factor
// configurations of a pairwise covering array over (primary=passkey,
// TOTP, recovery, email OTP): every pair of factor choices appears in
// some row.
func TestProvider_ForgetSubject_ErasesOnlyThatSubject(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name string
		f    erasureFactors
	}{
		{"password", erasureFactors{}},
		{"passkey+totp+recovery", erasureFactors{passkey: true, totp: true, recovery: true}},
		{"passkey+totp+emailotp", erasureFactors{passkey: true, totp: true, emailOTP: true}},
		{"passkey+recovery", erasureFactors{passkey: true, recovery: true}},
		{"password+totp+emailotp", erasureFactors{totp: true, emailOTP: true}},
		{"password+recovery+emailotp", erasureFactors{recovery: true, emailOTP: true}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			st := newErasureStore()
			// alice's user record is already deleted; bob's remains.
			users := newErasureUsers(keptSubject)
			p := newErasureOP(t, st, st, users, erasureLoginFlow(st, users, row.f))
			seedSubjectRecords(t, st, erasedSubject)
			seedSubjectRecords(t, st, keptSubject)

			ctx := context.Background()
			if err := p.ForgetSubject(ctx, erasedSubject); err != nil {
				t.Fatalf("ForgetSubject: %v", err)
			}
			assertSubjectRecords(t, st, erasedSubject, false, row.f)
			assertSubjectRecords(t, st, keptSubject, true, row.f)

			shared, err := st.Sessions().ListByChooserGroup(ctx, sharedGroup)
			if err != nil {
				t.Fatalf("ListByChooserGroup: %v", err)
			}
			if len(shared) != 1 || shared[0].Subject != keptSubject {
				t.Errorf("shared chooser group = %v, want only %s's session", shared, keptSubject)
			}

			if err := p.ForgetSubject(ctx, erasedSubject); err != nil {
				t.Fatalf("second ForgetSubject: %v", err)
			}
		})
	}
}

// TestProvider_ForgetSubject_RefusesWhileAUserStoreResolves pins that
// every user store the configuration reads, not only the claim source,
// must stop resolving the subject before anything is erased.
func TestProvider_ForgetSubject_RefusesWhileAUserStoreResolves(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		flow      func(st *inmem.Store, gone, live *erasureUsers) op.LoginFlow
		claims    func(gone, live *erasureUsers) store.UserStore
		wantLabel string
	}{
		{
			name: "claim store",
			flow: func(_ *inmem.Store, _, live *erasureUsers) op.LoginFlow {
				return op.LoginFlow{Primary: op.PrimaryPassword{Store: live}}
			},
			claims:    func(_, live *erasureUsers) store.UserStore { return live },
			wantLabel: "WithUserStore",
		},
		{
			name: "PrimaryPassword store only",
			flow: func(_ *inmem.Store, _, live *erasureUsers) op.LoginFlow {
				return op.LoginFlow{Primary: op.PrimaryPassword{Store: live}}
			},
			claims:    func(gone, _ *erasureUsers) store.UserStore { return gone },
			wantLabel: "LoginFlow PrimaryPassword.Store",
		},
		{
			name: "StepEmailOTP users only",
			flow: func(st *inmem.Store, gone, live *erasureUsers) op.LoginFlow {
				return op.LoginFlow{
					Primary: op.PrimaryPassword{Store: gone},
					Rules: []op.Rule{op.RuleAlways(op.StepEmailOTP{
						Store: st.EmailOTPs(), Sender: stubMailer{}, Users: live,
					})},
				}
			},
			claims:    func(gone, _ *erasureUsers) store.UserStore { return gone },
			wantLabel: "LoginFlow StepEmailOTP.Users",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newErasureStore()
			gone := newErasureUsers(keptSubject)
			live := newErasureUsers(erasedSubject, keptSubject)
			p := newErasureOP(t, st, st, tc.claims(gone, live), tc.flow(st, gone, live))
			seedSubjectRecords(t, st, erasedSubject)

			err := p.ForgetSubject(context.Background(), erasedSubject)
			assertConfigurationError(t, err, tc.wantLabel, "still resolves the subject")
			assertSubjectRecords(t, st, erasedSubject, true, erasureFactors{})
		})
	}
}

// TestProvider_ForgetSubject_RefusesWithoutStoreExtensions pins that a
// store lacking an extension ForgetSubject needs fails the call before
// any write, and that one error names every missing interface.
func TestProvider_ForgetSubject_RefusesWithoutStoreExtensions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		extra      func(st *inmem.Store) []op.Option
		want       []string
		wantAbsent string
	}{
		{
			name:       "session store",
			extra:      func(*inmem.Store) []op.Option { return nil },
			want:       []string{"store.SessionSubjectDeleter"},
			wantAbsent: "store.AuthnLockoutDeleter",
		},
		{
			name: "session and lockout stores",
			extra: func(st *inmem.Store) []op.Option {
				return []op.Option{op.WithAuthnLockoutStore(erasureLockoutsOnly{st.AuthnLockouts()})}
			},
			want: []string{"store.SessionSubjectDeleter", "store.AuthnLockoutDeleter"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newErasureStore()
			users := newErasureUsers(keptSubject)
			p := newErasureOP(t, st, erasureNoSubjectDeleteStore{st}, users,
				op.LoginFlow{Primary: op.PrimaryPassword{Store: users}}, tc.extra(st)...)
			seedSubjectRecords(t, st, erasedSubject)

			err := p.ForgetSubject(context.Background(), erasedSubject)
			assertConfigurationError(t, err, tc.want...)
			if tc.wantAbsent != "" && strings.Contains(err.Error(), tc.wantAbsent) {
				t.Errorf("ForgetSubject error %q names %q, which the store implements", err.Error(), tc.wantAbsent)
			}
			assertSubjectRecords(t, st, erasedSubject, true, erasureFactors{})
		})
	}
}

func TestProvider_ForgetSubject_EmptySubjectIsConfigurationError(t *testing.T) {
	t.Parallel()
	st := newErasureStore()
	users := newErasureUsers()
	p := newErasureOP(t, st, st, users, op.LoginFlow{Primary: op.PrimaryPassword{Store: users}})
	assertConfigurationError(t, p.ForgetSubject(context.Background(), ""), "subject must not be empty")
}
