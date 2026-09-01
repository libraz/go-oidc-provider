package sessions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// chooserManager builds a sessions.Manager with a clock that the test can
// advance through the returned closure. The shared store/manager mirrors
// the production wiring while keeping side-effects under direct test control.
func chooserManager(tb testing.TB, t0 time.Time) (*sessions.Manager, func(time.Duration)) {
	tb.Helper()
	cur := t0
	clock := func() time.Time { return cur }
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: newSessionCodec(tb),
		Store: newSessionStore(tb, inmem.WithClock(clockFunc(clock))),
		Clock: clock,
	})
	if err != nil {
		tb.Fatalf("NewManager: %v", err)
	}
	advance := func(d time.Duration) { cur = cur.Add(d) }
	return mgr, advance
}

func TestManager_EstablishAddAccount_ReusesGroupAndSwitchesCurrent(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	second := establishAddAccount(t, mgr, first.Cookie, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	}, t0)
	if second.ChooserGroupID != first.ChooserGroupID {
		t.Errorf("group ID changed: %q vs %q", second.ChooserGroupID, first.ChooserGroupID)
	}
	if second.SessionID == first.SessionID {
		t.Error("add-account returned the same SessionID")
	}
	// The cookie now points at the second account.
	active, err := mgr.Resolve(ctx, second.Cookie)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if active.Session.Subject != "user-b" {
		t.Errorf("Subject=%q want user-b", active.Session.Subject)
	}
}

func TestManager_PlanEstablishment_RejectsIncompleteAddAccount(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	// No group to join: neither the add-account marker nor the stable
	// fallback names one.
	if _, err := mgr.PlanEstablishment(context.Background(), sessions.EstablishPlan{
		Login:             sessions.Login{Subject: "x"},
		StableSessionID:   "stable-session",
		ChooserAddAccount: true,
		Now:               t0,
	}); err == nil {
		t.Error("PlanEstablishment accepted an add-account plan with no chooser group")
	}
	if _, err := mgr.PlanEstablishment(context.Background(), sessions.EstablishPlan{
		StableSessionID:          "stable-session",
		StableChooserGroupID:     "stable-chooser",
		ChooserAddAccount:        true,
		ChooserAddAccountGroupID: "cg",
		Now:                      t0,
	}); err == nil {
		t.Error("PlanEstablishment accepted an add-account plan with no subject")
	}
}

func TestManager_Switch_RebindsCookie(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	second := establishAddAccount(t, mgr, first.Cookie, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	}, t0)
	switched, err := mgr.Switch(ctx, first.ChooserGroupID, first.SessionID)
	if err != nil {
		t.Fatalf("Switch: %v", err)
	}
	if switched.SessionID != first.SessionID {
		t.Errorf("Switch returned %q want %q", switched.SessionID, first.SessionID)
	}
	// The cookie must now resolve back to user-a.
	active, err := mgr.Resolve(ctx, switched.Cookie)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if active.Session.Subject != "user-a" {
		t.Errorf("Subject=%q want user-a after switch", active.Session.Subject)
	}
	_ = second
}

func TestManager_Switch_RejectsForeignSession(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	groupA := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	groupB := establishFresh(t, mgr, sessions.Login{Subject: "user-b", AuthTime: t0}, t0)
	// Pretend an attacker sends groupA's cookie with groupB's session ID.
	_, err := mgr.Switch(ctx, groupA.ChooserGroupID, groupB.SessionID)
	if !errors.Is(err, sessions.ErrCookieInvalid) {
		t.Errorf("err=%v want ErrCookieInvalid", err)
	}
}

func TestManager_Switch_ReportsExpiredTarget(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	if err := mgr.Logout(ctx, first.SessionID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	_, err := mgr.Switch(ctx, first.ChooserGroupID, first.SessionID)
	if !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired", err)
	}
}

func TestManager_Accounts_ReturnsLiveSessions(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	establishAddAccount(t, mgr, first.Cookie, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	}, t0)
	got, err := mgr.Accounts(ctx, first.ChooserGroupID)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	subjects := map[string]bool{got[0].Subject: true, got[1].Subject: true}
	if !subjects["user-a"] || !subjects["user-b"] {
		t.Errorf("subjects=%v", subjects)
	}
}

func TestManager_Remove_NonCurrentLeavesCookieAlone(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	second := establishAddAccount(t, mgr, first.Cookie, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	}, t0)
	// Cookie is on user-b (the second account); remove the first.
	rem, err := mgr.Remove(ctx, first.ChooserGroupID, second.SessionID, first.SessionID)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if rem.Cookie != "" {
		t.Errorf("Removal.Cookie=%q want empty (current was not removed)", rem.Cookie)
	}
	if len(rem.Remaining) != 1 || rem.Remaining[0] != second.SessionID {
		t.Errorf("Remaining=%v", rem.Remaining)
	}
}

func TestManager_Remove_CurrentRebindsToMostRecent(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, advance := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	advance(time.Minute)
	second := establishAddAccount(t, mgr, first.Cookie, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0.Add(time.Minute),
	}, t0.Add(time.Minute))
	advance(time.Minute)
	third := establishAddAccount(t, mgr, second.Cookie, sessions.Login{
		Subject:  "user-c",
		AuthTime: t0.Add(2 * time.Minute),
	}, t0.Add(2*time.Minute))
	// Cookie is on user-c (most recent); remove user-c. Expect Remove to
	// rebind the cookie to user-b (the next-most-recent).
	rem, err := mgr.Remove(ctx, first.ChooserGroupID, third.SessionID, third.SessionID)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if rem.CurrentSessionID != second.SessionID {
		t.Errorf("CurrentSessionID=%q want %q", rem.CurrentSessionID, second.SessionID)
	}
	active, err := mgr.Resolve(ctx, rem.Cookie)
	if err != nil {
		t.Fatalf("Resolve rebound cookie: %v", err)
	}
	if active.Session.Subject != "user-b" {
		t.Errorf("rebound subject=%q want user-b", active.Session.Subject)
	}
}

// TestManager_Remove_CarriesReboundSessionExpiry pins the expiry that
// travels with a rebound cookie. The HTTP layer may not hand the browser
// a cookie that outlives the session it points at, and the surviving
// sibling's server-side expiry is knowable only here — the caller sees
// the new cookie value and nothing else about the account behind it. A
// Removal that rebinds without reporting the expiry forces the caller to
// either re-read the store or guess, and the profile default is the
// wrong guess.
func TestManager_Remove_CarriesReboundSessionExpiry(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, advance := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	advance(time.Minute)
	second := establishAddAccount(t, mgr, first.Cookie, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0.Add(time.Minute),
	}, t0.Add(time.Minute))
	rem, err := mgr.Remove(ctx, first.ChooserGroupID, second.SessionID, second.SessionID)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if rem.CurrentSessionID != first.SessionID {
		t.Fatalf("CurrentSessionID=%q want %q", rem.CurrentSessionID, first.SessionID)
	}
	active, err := mgr.Resolve(ctx, rem.Cookie)
	if err != nil {
		t.Fatalf("Resolve rebound cookie: %v", err)
	}
	if !rem.ExpiresAt.Equal(active.Session.ExpiresAt) {
		t.Errorf("Removal.ExpiresAt=%v want the surviving session's %v",
			rem.ExpiresAt, active.Session.ExpiresAt)
	}
	if rem.ExpiresAt.IsZero() {
		t.Error("Removal.ExpiresAt is zero, which the caller reads as 'no server-side bound'")
	}
}

func TestManager_Remove_LastSessionLeavesEmpty(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	only := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	rem, err := mgr.Remove(ctx, only.ChooserGroupID, only.SessionID, only.SessionID)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if rem.Cookie != "" || rem.CurrentSessionID != "" {
		t.Errorf("Removal=%+v want empty cookie", rem)
	}
	if len(rem.Remaining) != 0 {
		t.Errorf("Remaining=%v", rem.Remaining)
	}
}

func TestManager_LogoutAllSnapshot_DeletesGroup(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first := establishFresh(t, mgr, sessions.Login{Subject: "user-a", AuthTime: t0}, t0)
	establishAddAccount(t, mgr, first.Cookie, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	}, t0)
	snapshot, err := mgr.SnapshotGroup(ctx, first.ChooserGroupID)
	if err != nil {
		t.Fatalf("SnapshotGroup: %v", err)
	}
	if err := mgr.LogoutAllSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("LogoutAllSnapshot: %v", err)
	}
	got, err := mgr.Accounts(ctx, first.ChooserGroupID)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len=%d want 0 after LogoutAllSnapshot", len(got))
	}
}

func TestManager_LogoutAllSnapshot_IdempotentOnEmptyGroup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := chooserManager(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	snapshot, err := mgr.SnapshotGroup(ctx, "no-such-group")
	if err != nil {
		t.Fatalf("SnapshotGroup: %v", err)
	}
	if err := mgr.LogoutAllSnapshot(ctx, snapshot); err != nil {
		t.Errorf("LogoutAllSnapshot empty: %v", err)
	}
}
