package sessions_test

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
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

type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }

func newSessionStore(tb testing.TB, opts ...inmem.Option) store.SessionStore {
	tb.Helper()
	return inmem.New(opts...).Sessions()
}

func newManager(tb testing.TB, now time.Time) *sessions.Manager {
	tb.Helper()
	codec := newSessionCodec(tb)
	clock := fixedClock(now)
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: newSessionStore(tb, inmem.WithClock(clockFunc(clock))),
		Clock: clock,
	})
	if err != nil {
		tb.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// stableIDSeq backs nextStableID.
var stableIDSeq atomic.Uint64

// nextStableID mints the kind of caller-decided identifier the authorization
// endpoint derives from its interaction record before it persists a
// completion intent. Only uniqueness within the test binary matters here.
func nextStableID(label string) string {
	return label + "-" + strconv.FormatUint(stableIDSeq.Add(1), 10)
}

// establishPlan runs the two-step establishment the authorization endpoint
// performs: PlanEstablishment resolves the mode and the exact record, then
// Establish applies it idempotently.
func establishPlan(tb testing.TB, mgr *sessions.Manager, plan sessions.EstablishPlan) sessions.Outcome {
	tb.Helper()
	ctx := context.Background()
	establishment, err := mgr.PlanEstablishment(ctx, plan)
	if err != nil {
		tb.Fatalf("PlanEstablishment: %v", err)
	}
	out, err := mgr.Establish(ctx, establishment)
	if err != nil {
		tb.Fatalf("Establish: %v", err)
	}
	return out
}

// establishFresh seeds a brand-new chooser group holding a single account.
func establishFresh(tb testing.TB, mgr *sessions.Manager, login sessions.Login, now time.Time) sessions.Outcome {
	tb.Helper()
	return establishPlan(tb, mgr, sessions.EstablishPlan{
		Login:                login,
		StableSessionID:      nextStableID("session"),
		StableChooserGroupID: nextStableID("chooser"),
		Now:                  now,
	})
}

// establishAddAccount joins a further account to the chooser group behind
// cookie, the way the chooser prompt's add-account link does: the current
// cookie is resolved first so the group it names is the one the new account
// lands in.
func establishAddAccount(
	tb testing.TB,
	mgr *sessions.Manager,
	cookie string,
	login sessions.Login,
	now time.Time,
) sessions.Outcome {
	tb.Helper()
	active, err := mgr.Resolve(context.Background(), cookie)
	if err != nil {
		tb.Fatalf("Resolve current cookie: %v", err)
	}
	return establishPlan(tb, mgr, sessions.EstablishPlan{
		Active:                   active,
		Login:                    login,
		StableSessionID:          nextStableID("session"),
		StableChooserGroupID:     nextStableID("chooser"),
		ChooserAddAccount:        true,
		ChooserAddAccountGroupID: active.Payload.ChooserGroupID,
		Now:                      now,
	})
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

func TestManager_Establish_AndResolveRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr := newManager(t, now)

	out := establishFresh(t, mgr, sessions.Login{
		Subject:  "user-1",
		AuthTime: now.Add(-time.Minute),
		AMR:      []string{"pwd"},
		ACR:      "urn:mace:incommon:iap:silver",
	}, now)
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

func TestManager_PlanEstablishment_RejectsEmptySubject(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr := newManager(t, now)
	_, err := mgr.PlanEstablishment(context.Background(), sessions.EstablishPlan{
		StableSessionID:      "stable-session",
		StableChooserGroupID: "stable-chooser",
		Now:                  now,
	})
	if err == nil {
		t.Error("PlanEstablishment accepted empty Subject")
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

	out := establishFresh(t, mgr, sessions.Login{Subject: "user", AuthTime: now}, now)
	// Delete the underlying session — the cookie is still valid but the
	// store no longer has the record.
	if err := mgr.Logout(context.Background(), out.SessionID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := mgr.Resolve(context.Background(), out.Cookie); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired", err)
	}
}

func TestManager_Resolve_RejectsIdleExpiredSession(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cur := t0
	codec := newSessionCodec(t)
	storeClock := t0
	st := newSessionStore(t, inmem.WithClock(clockFunc(func() time.Time { return storeClock })))
	mgr, err := sessions.NewManager(sessions.Config{
		Codec:   codec,
		Store:   st,
		Clock:   func() time.Time { return cur },
		IdleTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out := establishFresh(t, mgr, sessions.Login{Subject: "user", AuthTime: t0}, t0)

	cur = t0.Add(time.Hour + time.Nanosecond)
	if _, err := mgr.Resolve(context.Background(), out.Cookie); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired", err)
	}
}

func TestManager_Touch_ExtendsExpiry(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	cur := t0
	st := newSessionStore(t, inmem.WithClock(clockFunc(func() time.Time { return cur })))

	// Manager observes a moving clock so we can verify Touch advances
	// ExpiresAt relative to the new "now".
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: func() time.Time { return cur },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out := establishFresh(t, mgr, sessions.Login{Subject: "user", AuthTime: t0}, t0)

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

func TestManager_TouchAndReissue_CapsIdleCookieAtAbsoluteExpiry(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	st := newSessionStore(t, inmem.WithClock(clockFunc(func() time.Time { return cur })))
	mgr, err := sessions.NewManager(sessions.Config{
		Codec:       newSessionCodec(t),
		Store:       st,
		Clock:       func() time.Time { return cur },
		IdleTTL:     24 * time.Hour,
		AbsoluteTTL: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out := establishFresh(t, mgr, sessions.Login{Subject: "user", AuthTime: t0}, t0)
	active, err := mgr.Resolve(context.Background(), out.Cookie)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cur = t0.Add(90 * time.Minute)
	touch, err := mgr.TouchAndReissue(context.Background(), active)
	if err != nil {
		t.Fatalf("TouchAndReissue: %v", err)
	}
	wantExpiry := t0.Add(2 * time.Hour)
	if !touch.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt=%v want absolute cap %v", touch.ExpiresAt, wantExpiry)
	}
	if !touch.UpdatedAt.Equal(cur) {
		t.Errorf("UpdatedAt=%v want touch time %v", touch.UpdatedAt, cur)
	}
	if touch.Cookie == out.Cookie {
		t.Error("TouchAndReissue returned the original cookie instead of re-sealing it")
	}
	reissued, err := mgr.Resolve(context.Background(), touch.Cookie)
	if err != nil {
		t.Fatalf("Resolve reissued cookie: %v", err)
	}
	if reissued.Session.ID != out.SessionID || reissued.Payload.ChooserGroupID != out.ChooserGroupID {
		t.Errorf("reissued payload changed session identity: %+v", reissued)
	}
	got, err := st.Find(context.Background(), out.SessionID)
	if err != nil {
		t.Fatalf("Find stored session: %v", err)
	}
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("stored expiry=%v want %v", got.ExpiresAt, wantExpiry)
	}
	if !got.UpdatedAt.Equal(touch.UpdatedAt) {
		t.Errorf("stored UpdatedAt=%v want TouchOutcome UpdatedAt=%v", got.UpdatedAt, touch.UpdatedAt)
	}
}

func TestManager_TouchAndReissue_RejectsAbsoluteExpired(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	st := newSessionStore(t, inmem.WithClock(clockFunc(func() time.Time { return cur })))
	mgr, err := sessions.NewManager(sessions.Config{
		Codec:       newSessionCodec(t),
		Store:       st,
		Clock:       func() time.Time { return cur },
		AbsoluteTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out := establishFresh(t, mgr, sessions.Login{Subject: "user", AuthTime: t0}, t0)
	active, err := mgr.Resolve(context.Background(), out.Cookie)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cur = t0.Add(time.Hour + time.Nanosecond)
	if _, err := mgr.TouchAndReissue(context.Background(), active); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Fatalf("TouchAndReissue err=%v want ErrCurrentSessionExpired", err)
	}
	if _, err := st.Find(context.Background(), out.SessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("absolute-expired session remains: %v", err)
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

	now := time.Now()
	mgr := newManager(t, now)
	out := establishFresh(t, mgr, sessions.Login{
		Subject:  "user",
		AuthTime: now,
	}, now)
	// First logout: succeeds.
	if err := mgr.Logout(context.Background(), out.SessionID); err != nil {
		t.Errorf("first Logout: %v", err)
	}
	// Second logout on the same ID: must be a nil error (idempotent).
	if err := mgr.Logout(context.Background(), out.SessionID); err != nil {
		t.Errorf("second Logout: %v", err)
	}
}

// TestManager_Rotate_IssuesFreshIDPreservingChooserGroup pins the
// structural session-fixation defence: every re-authentication path
// MUST issue a fresh session ID and immediately invalidate the old
// one, so any pre-fixation cookie value the attacker may have planted
// becomes useless. The chooser group, subject, AMR, and ACR are
// carried over so the rotation is invisible to legitimate callers
// (one chooser group, one logical session) — only the wire ID
// changes.
//
// Tracks:
//   - GHSA-xhpr-465j-7p9q (Keycloak, 2024) — first-login phishing
//     via email verification: a session that pre-existed the trust
//     transition continued to be authoritative after verification,
//     letting an attacker who planted the cookie ride the
//     post-verification trust. CWE-384 "Session Fixation". The fix
//     was to rotate session IDs on the trust boundary.
//
// The companion TestManager_Rotate_PreservesCreatedAt pins the
// second half of the contract: the absolute-TTL clock is NOT reset
// by rotation, so an attacker who triggers a rotate cannot extend
// session lifetime.
func TestManager_Rotate_IssuesFreshIDPreservingChooserGroup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	st := newSessionStore(t, inmem.WithClock(clockFunc(fixedClock(now))))
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: fixedClock(now),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out := establishFresh(t, mgr, sessions.Login{
		Subject:  "user-1",
		AuthTime: now,
		AMR:      []string{"pwd", "otp"},
		ACR:      "level-2",
	}, now)
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

// TestManager_Rotate_PreservesCreatedAt pins that rotation does NOT
// reset the absolute-TTL clock. Combined with the fresh-ID rotation
// from TestManager_Rotate_IssuesFreshIDPreservingChooserGroup this
// closes the second half of the GHSA-xhpr-465j-7p9q class: an
// attacker who manages to trigger a rotation does not gain
// additional session lifetime even if they hold the new ID briefly,
// because the absolute TTL still counts from the original
// establishment.
//
// Tracks: GHSA-xhpr-465j-7p9q — see
// TestManager_Rotate_IssuesFreshIDPreservingChooserGroup for the
// full threat model.
func TestManager_Rotate_PreservesCreatedAt(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	cur := t0
	clock := func() time.Time { return cur }
	st := newSessionStore(t, inmem.WithClock(clockFunc(clock)))
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out := establishFresh(t, mgr, sessions.Login{Subject: "u", AuthTime: t0}, t0)
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
	out := establishFresh(t, mgr, sessions.Login{Subject: "u", AuthTime: t0}, t0)

	// Within the cap: Touch keeps the session alive.
	cur = t0.Add(12 * time.Hour)
	if err := mgr.Touch(context.Background(), out.SessionID); err != nil {
		t.Errorf("Touch within cap rejected: %v", err)
	}

	// At the boundary (delta == cap): expired; the cap is exclusive.
	cur = t0.Add(24 * time.Hour)
	if err := mgr.Touch(context.Background(), out.SessionID); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("Touch at boundary err=%v want ErrCurrentSessionExpired", err)
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
	out := establishFresh(t, mgr, sessions.Login{Subject: "u", AuthTime: t0}, t0)
	cur = t0.Add(100 * 365 * 24 * time.Hour)
	if err := mgr.Touch(context.Background(), out.SessionID); err != nil {
		t.Errorf("Touch with cap disabled rejected: %v", err)
	}
}

func TestManager_Resolve_RejectsChooserGroupMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	codec := newSessionCodec(t)
	st := newSessionStore(t, inmem.WithClock(clockFunc(fixedClock(now))))
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: codec,
		Store: st,
		Clock: fixedClock(now),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	out := establishFresh(t, mgr, sessions.Login{Subject: "user", AuthTime: now}, now)
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
