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

func TestManager_AddAccount_ReusesGroupAndSwitchesCurrent(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	second, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	})
	if err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	if second.ChooserGroupID != first.ChooserGroupID {
		t.Errorf("group ID changed: %q vs %q", second.ChooserGroupID, first.ChooserGroupID)
	}
	if second.SessionID == first.SessionID {
		t.Error("AddAccount returned the same SessionID")
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

func TestManager_AddAccount_RejectsBadInput(t *testing.T) {
	t.Parallel()

	mgr, _ := chooserManager(t, time.Now())
	if _, err := mgr.AddAccount(context.Background(), "", sessions.Login{Subject: "x"}); err == nil {
		t.Error("AddAccount accepted empty chooser group")
	}
	if _, err := mgr.AddAccount(context.Background(), "cg", sessions.Login{}); err == nil {
		t.Error("AddAccount accepted empty subject")
	}
}

func TestManager_Switch_RebindsCookie(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	second, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	})
	if err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
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

	groupA, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue groupA: %v", err)
	}
	groupB, err := mgr.Issue(ctx, sessions.Login{Subject: "user-b", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue groupB: %v", err)
	}
	// Pretend an attacker sends groupA's cookie with groupB's session ID.
	_, err = mgr.Switch(ctx, groupA.ChooserGroupID, groupB.SessionID)
	if !errors.Is(err, sessions.ErrCookieInvalid) {
		t.Errorf("err=%v want ErrCookieInvalid", err)
	}
}

func TestManager_Switch_ReportsExpiredTarget(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := mgr.Logout(ctx, first.SessionID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	_, err = mgr.Switch(ctx, first.ChooserGroupID, first.SessionID)
	if !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Errorf("err=%v want ErrCurrentSessionExpired", err)
	}
}

func TestManager_Accounts_ReturnsLiveSessions(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	}); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
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

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	second, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	})
	if err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
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

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue first: %v", err)
	}
	advance(time.Minute)
	second, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("AddAccount second: %v", err)
	}
	advance(time.Minute)
	third, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-c",
		AuthTime: t0.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("AddAccount third: %v", err)
	}
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

func TestManager_Remove_LastSessionLeavesEmpty(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	only, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
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

func TestManager_LogoutAll_DeletesGroup(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	mgr, _ := chooserManager(t, t0)
	ctx := context.Background()

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0,
	}); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	if err := mgr.LogoutAll(ctx, first.ChooserGroupID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	got, err := mgr.Accounts(ctx, first.ChooserGroupID)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len=%d want 0 after LogoutAll", len(got))
	}
}

func TestManager_LogoutAll_IdempotentOnEmptyGroup(t *testing.T) {
	t.Parallel()

	mgr, _ := chooserManager(t, time.Now())
	if err := mgr.LogoutAll(context.Background(), "no-such-group"); err != nil {
		t.Errorf("LogoutAll empty: %v", err)
	}
}
