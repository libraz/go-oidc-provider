package password_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fakeScheme recognizes "legacy:<password>" encodings and counts calls.
type fakeScheme struct {
	verifies atomic.Int32
}

func (*fakeScheme) Recognizes(enc []byte) bool { return bytes.HasPrefix(enc, []byte("legacy:")) }

func (f *fakeScheme) Verify(_ context.Context, enc []byte, pw string) (bool, error) {
	f.verifies.Add(1)
	return string(enc) == "legacy:"+pw, nil
}

// recordingUpdater wraps the inmem store's updater.
type recordingUpdater struct {
	inner store.UserPasswordHashUpdater
	err   error
	calls atomic.Int32
}

func (u *recordingUpdater) UpdatePasswordHash(ctx context.Context, sub string, enc []byte) error {
	u.calls.Add(1)
	if u.err != nil {
		return u.err
	}
	return u.inner.UpdatePasswordHash(ctx, sub, enc)
}

type legacyFixture struct {
	auth    *password.Authenticator
	st      *inmem.Store
	scheme  *fakeScheme
	updater *recordingUpdater
	counter *lockout.Counter
	locks   store.AuthnLockoutStore
	logs    *bytes.Buffer
}

func newLegacyFixture(t *testing.T, stored string, updaterErr error, withUpdater bool) *legacyFixture {
	t.Helper()
	clock := &lockoutClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	st := inmem.New(inmem.WithClock(clock))
	st.PutUserWithPassword(context.Background(), &store.User{Subject: testSubject}, testUsername, []byte(stored))

	counter, err := lockout.New(st.AuthnLockouts(), clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	base, err := password.NewAuthenticator(st.UserPasswords())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	f := &legacyFixture{st: st, scheme: &fakeScheme{}, counter: counter, locks: st.AuthnLockouts(), logs: &bytes.Buffer{}}
	cfg := password.Config{
		LegacySchemes: []password.LegacyScheme{f.scheme},
		Logger:        slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if withUpdater {
		f.updater = &recordingUpdater{inner: st.UserPasswords().(store.UserPasswordHashUpdater), err: updaterErr}
		cfg.HashUpdater = f.updater
	}
	f.auth = base.WithLockout(counter).WithConfig(cfg)
	return f
}

func (f *legacyFixture) try(candidate string) (string, error) {
	step, err := f.auth.Continue(context.Background(), authn.ContinueInput{
		Submission: interaction.FormSubmission{Values: map[string]string{
			password.UsernameFieldName: testUsername,
			password.PasswordFieldName: candidate,
		}},
	})
	if err != nil {
		return "", err
	}
	return step.Result.Subject, nil
}

func (f *legacyFixture) storedHash(t *testing.T) string {
	t.Helper()
	h, err := f.st.UserPasswords().ReadPasswordHash(context.Background(), testSubject)
	if err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
	return string(h)
}

func TestLegacy_MatchLogsIn(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "legacy:"+testPassword, nil, false)
	sub, err := f.try(testPassword)
	if err != nil || sub != testSubject {
		t.Fatalf("try = (%q, %v), want (%q, nil)", sub, err, testSubject)
	}
	if f.storedHash(t) != "legacy:"+testPassword {
		t.Error("hash changed without an updater")
	}
}

func TestLegacy_MismatchCountsLikeNormalFailure(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "legacy:"+testPassword, nil, true)
	if _, err := f.try("wrong"); !errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	rec, err := f.locks.Get(context.Background(), testSubject)
	if err != nil {
		t.Fatalf("lockout Get: %v", err)
	}
	if rec.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", rec.FailedCount)
	}
	if f.updater.calls.Load() != 0 {
		t.Error("rehash ran after a failed verify")
	}
}

func TestLegacy_LockedSubjectSkipsSchemeAndRefuses(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "legacy:"+testPassword, nil, true)
	for range 30 {
		_, _ = f.try("wrong")
	}
	before := f.scheme.verifies.Load()
	if _, err := f.try(testPassword); !errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("locked login err = %v, want ErrInvalidCredentials", err)
	}
	if f.scheme.verifies.Load() != before {
		t.Error("legacy scheme consulted for a locked subject")
	}
	if f.updater.calls.Load() != 0 {
		t.Error("rehash ran for a locked subject")
	}
}

func TestLegacy_UnrecognizedHashIsMismatch(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "$unknown$whatever", nil, true)
	if _, err := f.try(testPassword); !errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if f.scheme.verifies.Load() != 0 {
		t.Error("scheme verified a hash it does not recognize")
	}
	if f.updater.calls.Load() != 0 {
		t.Error("rehash ran for an unusable hash")
	}
}

func TestLegacy_UnrecognizedHashWarnsOnceWithoutIdentifiers(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "$unknown$secrethashvalue", nil, true)
	for range 3 {
		if _, err := f.try(testPassword); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	}
	logs := f.logs.String()
	if n := strings.Count(logs, "level=WARN"); n != 1 {
		t.Fatalf("WARN count = %d, want 1; logs=%q", n, logs)
	}
	if !strings.Contains(logs, "LegacySchemes") {
		t.Errorf("warning does not name PrimaryPassword.LegacySchemes: %q", logs)
	}
	for _, secret := range []string{testSubject, testUsername, "secrethashvalue", testPassword} {
		if strings.Contains(logs, secret) {
			t.Errorf("log leaks %q: %q", secret, logs)
		}
	}
}

func TestLegacy_RecognizedAndArgon2idHashesDoNotWarn(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "legacy:"+testPassword, nil, true)
	if _, err := f.try(testPassword); err != nil {
		t.Fatalf("try: %v", err)
	}
	g := newLegacyFixture(t, string(hashWith(t, testPassword, 64*1024, 3, 1, []byte("0123456789abcdef"))), nil, true)
	if _, err := g.try(testPassword); err != nil {
		t.Fatalf("try: %v", err)
	}
	for _, l := range []string{f.logs.String(), g.logs.String()} {
		if strings.Contains(l, "level=WARN") {
			t.Errorf("unexpected WARN: %q", l)
		}
	}
}

func TestLegacy_Argon2idBypassesSchemes(t *testing.T) {
	t.Parallel()
	hash := string(hashWith(t, testPassword, 64*1024, 3, 1, []byte("0123456789abcdef")))
	f := newLegacyFixture(t, hash, nil, true)
	if _, err := f.try(testPassword); err != nil {
		t.Fatalf("try: %v", err)
	}
	if f.scheme.verifies.Load() != 0 || f.updater.calls.Load() != 0 {
		t.Error("argon2id hash went through the legacy path")
	}
}

func TestRehash_WritesArgon2id(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "legacy:"+testPassword, nil, true)
	if _, err := f.try(testPassword); err != nil {
		t.Fatalf("try: %v", err)
	}
	got := f.storedHash(t)
	if !strings.HasPrefix(got, "$argon2id$") {
		t.Fatalf("stored hash = %q, want argon2id PHC", got)
	}
	if err := password.Verify([]byte(got), testPassword); err != nil {
		t.Fatalf("rehashed value does not verify: %v", err)
	}
	// The next login takes the argon2id path.
	if _, err := f.try(testPassword); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if f.scheme.verifies.Load() != 1 {
		t.Errorf("legacy verifies = %d, want 1", f.scheme.verifies.Load())
	}
}

func TestRehash_UpdaterErrorStillSucceeds(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "legacy:"+testPassword, errors.New("db down"), true)
	sub, err := f.try(testPassword)
	if err != nil || sub != testSubject {
		t.Fatalf("try = (%q, %v), want success", sub, err)
	}
	if f.storedHash(t) != "legacy:"+testPassword {
		t.Error("hash changed despite updater error")
	}
	if !strings.Contains(f.logs.String(), "level=WARN") {
		t.Errorf("expected WARN log, got %q", f.logs.String())
	}
}

func TestRehash_UnsupportedLogsInfoOnceNoWarn(t *testing.T) {
	t.Parallel()
	f := newLegacyFixture(t, "legacy:"+testPassword, store.ErrPasswordHashUpdateUnsupported, true)
	for range 3 {
		if _, err := f.try(testPassword); err != nil {
			t.Fatalf("try: %v", err)
		}
	}
	logs := f.logs.String()
	if strings.Contains(logs, "level=WARN") {
		t.Errorf("unexpected WARN: %q", logs)
	}
	if n := strings.Count(logs, "level=INFO"); n != 1 {
		t.Errorf("INFO count = %d, want 1; logs=%q", n, logs)
	}
	if f.storedHash(t) != "legacy:"+testPassword {
		t.Error("legacy hash was replaced")
	}
}
