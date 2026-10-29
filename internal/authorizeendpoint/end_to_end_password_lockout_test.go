package authorizeendpoint_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	lockoutE2EUsername = "lockout-user"
	lockoutE2EPassword = "correct horse battery staple"
	lockoutE2EWrong    = "not the password"
)

// lazyPasswordStore lets the login flow be declared before the fixture's
// own store exists; the embedded store is set right after the Provider
// is built and before any request is made.
type lazyPasswordStore struct{ store.UserPasswordStore }

// passwordLockoutSession is one browser walking a single password
// interaction, carrying the rotating CSRF token and state reference
// between submissions.
type passwordLockoutSession struct {
	t        *testing.T
	fix      *flowFixture
	d        *reauthDriver
	path     string
	csrf     string
	stateRef string
}

func newPasswordLockoutSession(t *testing.T, extra ...op.Option) *passwordLockoutSession {
	t.Helper()
	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	lazy := &lazyPasswordStore{}
	fix := buildFlowFixture(t, "password-lockout", clock,
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: lazy}}), extra...)
	lazy.UserPasswordStore = fix.store.UserPasswords()

	d := newReauthDriver(t, fix)
	hash, err := op.HashPassword(lockoutE2EPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	fix.store.PutUserWithPassword(context.Background(), &store.User{Subject: reauthSubject}, lockoutE2EUsername, hash)

	loc := d.authorize(nil)
	env, csrf := d.firstPrompt(loc.Path)
	if got, _ := env["type"].(string); got != password.PromptType {
		t.Fatalf("first prompt type=%q want %q", got, password.PromptType)
	}
	stateRef, _ := env["state_ref"].(string)
	return &passwordLockoutSession{t: t, fix: fix, d: d, path: loc.Path, csrf: csrf, stateRef: stateRef}
}

// attempt submits a password and returns the status and the decoded body
// with the per-response nonces removed, so two responses compare equal
// exactly when a client could not tell them apart.
func (s *passwordLockoutSession) attempt(candidate string) (int, map[string]any) {
	s.t.Helper()
	resp := s.d.submit(s.path, s.csrf, s.stateRef, map[string]string{
		password.UsernameFieldName: lockoutE2EUsername,
		password.PasswordFieldName: candidate,
	})
	defer resp.Body.Close()
	if rotated := findCookie(resp.Cookies(), "__Host-oidc_csrf"); rotated != nil {
		s.csrf = rotated.Value
	}
	body := decodeMap(s.t, resp)
	if ref, _ := body["state_ref"].(string); ref != "" {
		s.stateRef = ref
	}
	delete(body, "state_ref")
	delete(body, "csrf_token")
	return resp.StatusCode, body
}

func (s *passwordLockoutSession) failWrong(n int) (int, map[string]any) {
	s.t.Helper()
	var (
		status int
		body   map[string]any
	)
	for range n {
		status, body = s.attempt(lockoutE2EWrong)
		if status != http.StatusOK {
			s.t.Fatalf("wrong password: status=%d body=%v", status, body)
		}
	}
	return status, body
}

// TestEndToEnd_PasswordLockout_LockedMatchesWrongPassword drives a
// subject past the failure threshold and requires that a locked subject
// is refused even with the right password, with a response a client
// cannot tell from an ordinary wrong password.
func TestEndToEnd_PasswordLockout_LockedMatchesWrongPassword(t *testing.T) {
	t.Parallel()
	s := newPasswordLockoutSession(t)

	// The 30th failure is the one that stamps the lock.
	wrongStatus, wrongBody := s.failWrong(30)
	if got, _ := wrongBody["type"].(string); got != password.PromptType {
		t.Fatalf("wrong password prompt type=%q want %q", got, password.PromptType)
	}

	lockedStatus, lockedBody := s.attempt(lockoutE2EPassword)
	if lockedStatus != wrongStatus || !reflect.DeepEqual(lockedBody, wrongBody) {
		t.Errorf("locked + correct password: status=%d body=%v; wrong password: status=%d body=%v",
			lockedStatus, lockedBody, wrongStatus, wrongBody)
	}
	lockedWrongStatus, lockedWrongBody := s.attempt(lockoutE2EWrong)
	if lockedWrongStatus != wrongStatus || !reflect.DeepEqual(lockedWrongBody, wrongBody) {
		t.Errorf("locked + wrong password: status=%d body=%v; wrong password: status=%d body=%v",
			lockedWrongStatus, lockedWrongBody, wrongStatus, wrongBody)
	}

	rec, err := s.fix.store.AuthnLockouts().Get(context.Background(), reauthSubject)
	if err != nil {
		t.Fatalf("lockout Get: %v", err)
	}
	if rec.FailedCount != 30 {
		t.Errorf("FailedCount=%d want 30: attempts while locked must not be recorded", rec.FailedCount)
	}
}

// TestEndToEnd_PasswordLockout_AutowiredFromStore requires the counter
// to be live with no WithAuthnLockoutStore: the in-memory store behind
// WithStore exposes AuthnLockouts and the Provider picks it up.
func TestEndToEnd_PasswordLockout_AutowiredFromStore(t *testing.T) {
	t.Parallel()
	s := newPasswordLockoutSession(t)

	s.failWrong(3)

	rec, err := s.fix.store.AuthnLockouts().Get(context.Background(), reauthSubject)
	if err != nil {
		t.Fatalf("lockout Get: %v", err)
	}
	if rec.FailedCount != 3 {
		t.Errorf("FailedCount=%d want 3", rec.FailedCount)
	}
}

// TestEndToEnd_PasswordLockout_ExplicitStoreWins requires an explicit
// WithAuthnLockoutStore to take the failures instead of the WithStore
// accessor.
func TestEndToEnd_PasswordLockout_ExplicitStoreWins(t *testing.T) {
	t.Parallel()
	explicit := inmem.New()
	s := newPasswordLockoutSession(t, op.WithAuthnLockoutStore(explicit.AuthnLockouts()))

	s.failWrong(3)

	rec, err := explicit.AuthnLockouts().Get(context.Background(), reauthSubject)
	if err != nil {
		t.Fatalf("explicit lockout Get: %v", err)
	}
	if rec.FailedCount != 3 {
		t.Errorf("explicit store FailedCount=%d want 3", rec.FailedCount)
	}
	if _, err := s.fix.store.AuthnLockouts().Get(context.Background(), reauthSubject); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("WithStore accessor was used despite the explicit store: err=%v", err)
	}
}
