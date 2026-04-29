package sessions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fixedClock returns the supplied time on every call. The test bias is
// "the OP just decided this is the wall clock"; randomising would make
// failures harder to reproduce.
func fixedClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

func newSessionStore(tb testing.TB) store.SessionStore {
	tb.Helper()
	return inmem.New().Sessions()
}

func newManager(tb testing.TB, now time.Time) *sessions.Manager {
	tb.Helper()
	codec := newSessionCodec(tb)
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: newSessionStore(tb),
		Clock: fixedClock(now),
	})
	if err != nil {
		tb.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func TestNewManager_RejectsMissingDeps(t *testing.T) {
	t.Parallel()

	if _, err := sessions.NewManager(sessions.Config{}); err == nil {
		t.Error("NewManager accepted empty config")
	}
	if _, err := sessions.NewManager(sessions.Config{
		Codec: newSessionCodec(t),
	}); err == nil {
		t.Error("NewManager accepted missing Store")
	}
}

func TestManager_Issue_AndResolveRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr := newManager(t, now)

	out, err := mgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: now.Add(-time.Minute),
		AMR:      []string{"pwd"},
		ACR:      "urn:mace:incommon:iap:silver",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if out.Cookie == "" || out.SessionID == "" || out.ChooserGroupID == "" {
		t.Fatalf("Outcome incomplete: %+v", out)
	}

	active, err := mgr.Resolve(context.Background(), out.Cookie)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if active.Session.Subject != "user-1" {
		t.Errorf("subject=%q want user-1", active.Session.Subject)
	}
	if active.Session.ID != out.SessionID {
		t.Errorf("session id mismatch: %q vs %q", active.Session.ID, out.SessionID)
	}
	if active.Payload.ChooserGroupID != out.ChooserGroupID {
		t.Errorf("chooser group mismatch")
	}
	if !active.Session.ExpiresAt.After(now) {
		t.Errorf("ExpiresAt=%v not in future", active.Session.ExpiresAt)
	}
}

func TestManager_Issue_RejectsEmptySubject(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, time.Now())
	_, err := mgr.Issue(context.Background(), sessions.Login{})
	if err == nil {
		t.Error("Issue accepted empty Subject")
	}
}

func TestManager_Resolve_RejectsInvalidCookie(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, time.Now())
	if _, err := mgr.Resolve(context.Background(), "not-a-cookie"); !errors.Is(err, sessions.ErrCookieInvalid) {
		t.Errorf("err=%v want ErrCookieInvalid", err)
	}
}

func TestManager_Resolve_DetectsExpiredSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr := newManager(t, now)

	out, err := mgr.Issue(context.Background(), sessions.Login{Subject: "user", AuthTime: now})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Delete the underlying session — the cookie is still valid but the
	// store no longer has the record.
	if err := mgr.Logout(context.Background(), out.SessionID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := mgr.Resolve(context.Background(), out.Cookie); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired", err)
	}
}

func TestManager_Touch_ExtendsExpiry(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	st := newSessionStore(t)

	// Manager observes a moving clock so we can verify Touch advances
	// ExpiresAt relative to the new "now".
	cur := t0
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: func() time.Time { return cur },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out, err := mgr.Issue(context.Background(), sessions.Login{Subject: "user", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance clock by one hour, touch the session.
	cur = t0.Add(time.Hour)
	if err := mgr.Touch(context.Background(), out.SessionID); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	got, err := st.Find(context.Background(), out.SessionID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	want := cur.Add(sessions.IdleTTLDefault)
	if !got.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt=%v want %v", got.ExpiresAt, want)
	}
}

func TestManager_Touch_OnMissingSession(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, time.Now())
	if err := mgr.Touch(context.Background(), "no-such-session"); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired", err)
	}
}

func TestManager_Logout_Idempotent(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, time.Now())
	out, err := mgr.Issue(context.Background(), sessions.Login{
		Subject:  "user",
		AuthTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// First logout: succeeds.
	if err := mgr.Logout(context.Background(), out.SessionID); err != nil {
		t.Errorf("first Logout: %v", err)
	}
	// Second logout on the same ID: must be a nil error (idempotent).
	if err := mgr.Logout(context.Background(), out.SessionID); err != nil {
		t.Errorf("second Logout: %v", err)
	}
}

func TestManager_Rotate_IssuesFreshIDPreservingChooserGroup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	st := newSessionStore(t)
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: fixedClock(now),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out, err := mgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: now,
		AMR:      []string{"pwd", "otp"},
		ACR:      "level-2",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rotated, err := mgr.Rotate(context.Background(), out.SessionID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.SessionID == out.SessionID {
		t.Errorf("Rotate returned identical SessionID")
	}
	if rotated.ChooserGroupID != out.ChooserGroupID {
		t.Errorf("ChooserGroupID changed: %q -> %q", out.ChooserGroupID, rotated.ChooserGroupID)
	}
	// Old ID must miss.
	if _, err := st.Find(context.Background(), out.SessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("old session still resolvable: %v", err)
	}
	// New ID must hit and carry the same subject + AMR + ACR.
	got, err := st.Find(context.Background(), rotated.SessionID)
	if err != nil {
		t.Fatalf("Find rotated: %v", err)
	}
	if got.Subject != "user-1" {
		t.Errorf("subject=%q want user-1", got.Subject)
	}
	if len(got.AMR) != 2 || got.AMR[0] != "pwd" || got.AMR[1] != "otp" {
		t.Errorf("AMR=%v want [pwd otp]", got.AMR)
	}
	if got.ACR != "level-2" {
		t.Errorf("ACR=%q want level-2", got.ACR)
	}
}

func TestManager_Rotate_PreservesCreatedAt(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	st := newSessionStore(t)
	cur := t0
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: func() time.Time { return cur },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out, err := mgr.Issue(context.Background(), sessions.Login{Subject: "u", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cur = t0.Add(2 * time.Hour)
	rotated, err := mgr.Rotate(context.Background(), out.SessionID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	got, err := st.Find(context.Background(), rotated.SessionID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if !got.CreatedAt.Equal(t0) {
		t.Errorf("CreatedAt=%v want %v (must not reset on rotate)", got.CreatedAt, t0)
	}
}

func TestManager_Rotate_OnMissingSession(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, time.Now())
	if _, err := mgr.Rotate(context.Background(), "nope"); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired", err)
	}
}

func TestManager_Rotate_EmptyIDRejected(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, time.Now())
	if _, err := mgr.Rotate(context.Background(), ""); err == nil {
		t.Error("Rotate accepted empty oldSessionID")
	}
}

// movableClock is a Clock implementation whose Now() reads a *time.Time
// the test owns. It lets the session store and the manager share a single
// virtual clock so synthetic timestamps in 2026-01 do not collide with
// the real wall clock used by the inmem expiry sweep.
type movableClock struct{ now *time.Time }

func (m *movableClock) Now() time.Time { return *m.now }

func TestManager_Touch_AbsoluteTTLExpiresSession(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cur := t0
	store0 := inmem.New(inmem.WithClock(&movableClock{now: &cur}))
	codec := newSessionCodec(t)
	mgr, err := sessions.NewManager(sessions.Config{
		Codec:       codec,
		Store:       store0.Sessions(),
		Clock:       func() time.Time { return cur },
		AbsoluteTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out, err := mgr.Issue(context.Background(), sessions.Login{Subject: "u", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Within the cap: Touch keeps the session alive.
	cur = t0.Add(12 * time.Hour)
	if err := mgr.Touch(context.Background(), out.SessionID); err != nil {
		t.Errorf("Touch within cap rejected: %v", err)
	}

	// At the boundary (delta == cap): still alive (strict greater-than).
	cur = t0.Add(24 * time.Hour)
	if err := mgr.Touch(context.Background(), out.SessionID); err != nil {
		t.Errorf("Touch at boundary rejected: %v", err)
	}

	// One nanosecond past the cap: expired and tear down.
	cur = t0.Add(24*time.Hour + time.Nanosecond)
	if err := mgr.Touch(context.Background(), out.SessionID); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired past cap", err)
	}
	if _, err := store0.Sessions().Find(context.Background(), out.SessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session still in store after absolute-TTL expiry: %v", err)
	}
}

func TestManager_Touch_NegativeAbsoluteTTLDisablesCap(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cur := t0
	store0 := inmem.New(inmem.WithClock(&movableClock{now: &cur}))
	codec := newSessionCodec(t)
	mgr, err := sessions.NewManager(sessions.Config{
		Codec:       codec,
		Store:       store0.Sessions(),
		Clock:       func() time.Time { return cur },
		AbsoluteTTL: -1,                         // explicitly disabled
		IdleTTL:     200 * 365 * 24 * time.Hour, // ~200 yr; well under int64 ns overflow
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out, err := mgr.Issue(context.Background(), sessions.Login{Subject: "u", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cur = t0.Add(100 * 365 * 24 * time.Hour)
	if err := mgr.Touch(context.Background(), out.SessionID); err != nil {
		t.Errorf("Touch with cap disabled rejected: %v", err)
	}
}

func TestManager_Resolve_RejectsChooserGroupMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	st := newSessionStore(t)
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: fixedClock(now),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out, err := mgr.Issue(context.Background(), sessions.Login{Subject: "user", AuthTime: now})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Mutate the stored session so its ChooserGroupID no longer matches
	// the one baked into the cookie.
	sess, err := st.Find(context.Background(), out.SessionID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	sess.ChooserGroupID = "different-group"
	if err := st.Save(context.Background(), sess); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := mgr.Resolve(context.Background(), out.Cookie); !errors.Is(err, sessions.ErrCookieInvalid) {
		t.Errorf("err=%v want ErrCookieInvalid (chooser group mismatch)", err)
	}
}
