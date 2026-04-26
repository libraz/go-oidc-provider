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
