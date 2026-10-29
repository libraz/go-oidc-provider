package password_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	lockoutNoHashUsername = "nohash@example.com"
	lockoutNoHashSubject  = "sub-nohash"
	lockoutWrongPassword  = "not the password"
)

// lockoutClock is a pinned clock the store and the counter share.
type lockoutClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *lockoutClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *lockoutClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// lockoutFixture is a password authenticator with a user that has a
// password, a user that has none, and a counter on a pinned clock.
type lockoutFixture struct {
	auth    *password.Authenticator
	counter *lockout.Counter
	locks   store.AuthnLockoutStore
	clock   *lockoutClock
}

func newLockoutFixture(t *testing.T, wrap func(store.AuthnLockoutStore) store.AuthnLockoutStore) *lockoutFixture {
	t.Helper()
	clock := &lockoutClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	st := inmem.New(inmem.WithClock(clock))
	hash := hashWith(t, testPassword, 64*1024, 3, 1, []byte("0123456789abcdef"))
	ctx := context.Background()
	st.PutUserWithPassword(ctx, &store.User{Subject: testSubject}, testUsername, hash)
	st.PutUserWithPassword(ctx, &store.User{Subject: lockoutNoHashSubject}, lockoutNoHashUsername, nil)

	locks := st.AuthnLockouts()
	if wrap != nil {
		locks = wrap(locks)
	}
	counter, err := lockout.New(locks, clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	base, err := password.NewAuthenticator(st.UserPasswords())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return &lockoutFixture{auth: base.WithLockout(counter), counter: counter, locks: st.AuthnLockouts(), clock: clock}
}

func (f *lockoutFixture) try(username, candidate string) error {
	_, err := f.auth.Continue(context.Background(), authn.ContinueInput{
		Submission: interaction.FormSubmission{Values: map[string]string{
			password.UsernameFieldName: username,
			password.PasswordFieldName: candidate,
		}},
	})
	return err
}

func (f *lockoutFixture) record(t *testing.T, subject string) *store.AuthnLockoutRecord {
	t.Helper()
	rec, err := f.locks.Get(context.Background(), subject)
	if err != nil {
		t.Fatalf("lockout Get(%q): %v", subject, err)
	}
	return rec
}

func (f *lockoutFixture) failWrong(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		if err := f.try(testUsername, lockoutWrongPassword); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password #%d: err=%v want ErrInvalidCredentials", i+1, err)
		}
	}
}

// failingLockoutStore injects backend faults in front of the in-memory
// store.
type failingLockoutStore struct {
	store.AuthnLockoutStore
	getErr   error
	swapLost bool
}

func (s failingLockoutStore) Get(ctx context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.AuthnLockoutStore.Get(ctx, subject)
}

func (s failingLockoutStore) CompareAndSwap(ctx context.Context, expected uint64, next *store.AuthnLockoutRecord) (bool, error) {
	if s.swapLost {
		return false, nil
	}
	return s.AuthnLockoutStore.CompareAndSwap(ctx, expected, next)
}

func TestPasswordLockout_LockedRefusesCorrectPassword(t *testing.T) {
	t.Parallel()
	f := newLockoutFixture(t, nil)

	f.failWrong(t, 29)
	if err := f.try(testUsername, testPassword); err != nil {
		t.Fatalf("correct password before the threshold: %v", err)
	}
	f.failWrong(t, 1)

	if err := f.try(testUsername, testPassword); !errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("correct password while locked: err=%v want ErrInvalidCredentials", err)
	}
	rec := f.record(t, testSubject)
	if want := f.clock.Now().Add(time.Hour); !rec.LockedUntil.Equal(want) {
		t.Errorf("LockedUntil=%v want %v", rec.LockedUntil, want)
	}

	f.clock.Advance(time.Hour + time.Second)
	if err := f.try(testUsername, testPassword); err != nil {
		t.Fatalf("correct password after the lock expired: %v", err)
	}
}

func TestPasswordLockout_LockedAttemptsAreNotRecorded(t *testing.T) {
	t.Parallel()
	f := newLockoutFixture(t, nil)

	f.failWrong(t, 30)
	lockedUntil := f.record(t, testSubject).LockedUntil
	f.failWrong(t, 3)
	if err := f.try(testUsername, testPassword); !errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("correct password while locked: err=%v", err)
	}

	rec := f.record(t, testSubject)
	if rec.FailedCount != 30 {
		t.Errorf("FailedCount=%d want 30: attempts while locked must not be recorded", rec.FailedCount)
	}
	if !rec.LockedUntil.Equal(lockedUntil) {
		t.Errorf("LockedUntil moved from %v to %v: the lock must not be extended", lockedUntil, rec.LockedUntil)
	}
}

func TestPasswordLockout_UnknownUsernameAndNoHashLeaveCounterUntouched(t *testing.T) {
	t.Parallel()
	f := newLockoutFixture(t, nil)

	for range 35 {
		if err := f.try("nobody@example.com", lockoutWrongPassword); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("unknown username: err=%v", err)
		}
		if err := f.try(lockoutNoHashUsername, lockoutWrongPassword); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("user without a hash: err=%v", err)
		}
	}

	if _, err := f.locks.Get(context.Background(), lockoutNoHashSubject); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("counter for the user without a hash: err=%v want ErrNotFound", err)
	}
	if _, err := f.locks.Get(context.Background(), "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("counter for an unknown username: err=%v want ErrNotFound", err)
	}
}

func TestPasswordLockout_SuccessDoesNotReset(t *testing.T) {
	t.Parallel()
	f := newLockoutFixture(t, nil)

	f.failWrong(t, 5)
	if err := f.try(testUsername, testPassword); err != nil {
		t.Fatalf("correct password: %v", err)
	}
	if got := f.record(t, testSubject).FailedCount; got != 5 {
		t.Errorf("FailedCount=%d want 5: a successful password login must not reset the shared counter", got)
	}
}

func TestPasswordLockout_LongLockAnswersAsInvalidCredentials(t *testing.T) {
	t.Parallel()
	f := newLockoutFixture(t, nil)

	// Failures from other factors, which do not check the lock, bring the
	// shared count to 89; the short lock they stamped runs out before the
	// password attempt that reaches 90.
	for i := range 89 {
		if _, err := f.counter.RecordFailure(context.Background(), testSubject); err != nil {
			t.Fatalf("RecordFailure #%d: %v", i+1, err)
		}
	}
	f.clock.Advance(time.Hour + time.Second)
	f.failWrong(t, 1)

	rec := f.record(t, testSubject)
	if rec.FailedCount != 90 {
		t.Fatalf("FailedCount=%d want 90", rec.FailedCount)
	}
	if want := f.clock.Now().Add(24 * time.Hour); !rec.LockedUntil.Equal(want) {
		t.Errorf("LockedUntil=%v want %v", rec.LockedUntil, want)
	}
	if err := f.try(testUsername, testPassword); !errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("correct password under the 24h lock: err=%v want ErrInvalidCredentials", err)
	}
}

func TestPasswordLockout_StoreErrorsFailClosed(t *testing.T) {
	t.Parallel()
	boom := errors.New("lockout backend down")

	cases := []struct {
		name      string
		wrap      func(store.AuthnLockoutStore) store.AuthnLockoutStore
		candidate string
		want      error
	}{
		{
			name: "guard read fails",
			wrap: func(s store.AuthnLockoutStore) store.AuthnLockoutStore {
				return failingLockoutStore{AuthnLockoutStore: s, getErr: boom}
			},
			candidate: testPassword,
			want:      boom,
		},
		{
			name: "swap contention",
			wrap: func(s store.AuthnLockoutStore) store.AuthnLockoutStore {
				return failingLockoutStore{AuthnLockoutStore: s, swapLost: true}
			},
			candidate: lockoutWrongPassword,
			want:      lockout.ErrSwapContention,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newLockoutFixture(t, tc.wrap)
			err := f.try(testUsername, tc.candidate)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want it to wrap %v", err, tc.want)
			}
			if errors.Is(err, password.ErrInvalidCredentials) || errors.Is(err, authn.ErrFactorRetry) {
				t.Fatalf("err=%v must not read as a wrong password", err)
			}
		})
	}
}
