package sessions_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestManager_EstablishIssueIsIdempotent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	clock := fixedClock(now)
	backing := inmem.New(inmem.WithClock(clockFunc(clock)))
	manager, err := sessions.NewManager(sessions.Config{
		Codec: newSessionCodec(t),
		Store: backing.Sessions(),
		Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	plan, err := manager.PlanEstablishment(context.Background(), sessions.EstablishPlan{
		Login: sessions.Login{
			Subject:  "user-1",
			AuthTime: now.Add(-time.Minute),
			AMR:      []string{"pwd"},
			ACR:      "urn:acr:1",
		},
		StableSessionID:      "stable-session",
		StableChooserGroupID: "stable-group",
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("PlanEstablishment: %v", err)
	}
	first, err := manager.Establish(context.Background(), plan)
	if err != nil {
		t.Fatalf("first Establish: %v", err)
	}
	second, err := manager.Establish(context.Background(), plan)
	if err != nil {
		t.Fatalf("retry Establish: %v", err)
	}
	if first.SessionID != "stable-session" || second.SessionID != first.SessionID {
		t.Fatalf("outcomes differ: first=%+v second=%+v", first, second)
	}
	if first.Cookie == "" || second.Cookie == "" {
		t.Fatalf("retry omitted cookie: first=%q second=%q", first.Cookie, second.Cookie)
	}
	firstActive, err := manager.Resolve(context.Background(), first.Cookie)
	if err != nil {
		t.Fatalf("Resolve first cookie: %v", err)
	}
	secondActive, err := manager.Resolve(context.Background(), second.Cookie)
	if err != nil {
		t.Fatalf("Resolve retry cookie: %v", err)
	}
	if firstActive.Session.ID != secondActive.Session.ID {
		t.Fatalf("cookie sessions differ: first=%q second=%q",
			firstActive.Session.ID, secondActive.Session.ID)
	}
	group, err := backing.Sessions().ListByChooserGroup(context.Background(), "stable-group")
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(group) != 1 || group[0].ID != "stable-session" {
		t.Fatalf("sessions=%v want one stable session", group)
	}
}

type deleteOnceSessionStore struct {
	store.SessionStore
	armed atomic.Bool
}

type corruptSelectedSessionStore struct {
	store.SessionStore
	result *store.Session
}

func (s corruptSelectedSessionStore) Find(context.Context, string) (*store.Session, error) {
	return s.result, nil
}

func TestManager_PlanEstablishmentRejectsCorruptSelectedSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		result *store.Session
	}{
		{
			name: "wrong id",
			result: &store.Session{
				ID:             "other-session",
				Subject:        "user-1",
				ChooserGroupID: "group-1",
			},
		},
		{
			name: "wrong subject",
			result: &store.Session{
				ID:             "selected-session",
				Subject:        "other-user",
				ChooserGroupID: "group-1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			manager, err := sessions.NewManager(sessions.Config{
				Codec: newSessionCodec(t),
				Store: corruptSelectedSessionStore{
					SessionStore: newSessionStore(t),
					result:       tc.result,
				},
				Clock: fixedClock(now),
			})
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			_, err = manager.PlanEstablishment(context.Background(), sessions.EstablishPlan{
				Login:                    sessions.Login{Subject: "user-1"},
				ChooserGroupID:           "group-1",
				ChooserSelectedSessionID: "selected-session",
				Now:                      now,
			})
			if !errors.Is(err, sessions.ErrCookieInvalid) {
				t.Fatalf("PlanEstablishment error=%v want ErrCookieInvalid", err)
			}
		})
	}
}

func (s *deleteOnceSessionStore) Delete(ctx context.Context, id string) error {
	if s.armed.CompareAndSwap(true, false) {
		return errors.New("injected session delete failure")
	}
	return s.SessionStore.Delete(ctx, id)
}

func TestManager_EstablishRotateResumesAfterDeleteFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	clock := fixedClock(now)
	backing := inmem.New(inmem.WithClock(clockFunc(clock)))
	faults := &deleteOnceSessionStore{SessionStore: backing.Sessions()}
	manager, err := sessions.NewManager(sessions.Config{
		Codec: newSessionCodec(t),
		Store: faults,
		Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	issued := establishFresh(t, manager, sessions.Login{
		Subject:  "user-1",
		AuthTime: now.Add(-time.Hour),
		AMR:      []string{"pwd"},
	}, now.Add(-time.Hour))
	active, err := manager.Resolve(context.Background(), issued.Cookie)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	plan, err := manager.PlanEstablishment(context.Background(), sessions.EstablishPlan{
		Active: active,
		Login: sessions.Login{
			Subject:  "user-1",
			AuthTime: now,
			AMR:      []string{"pwd", "otp"},
		},
		FreshAuthn:           true,
		StableSessionID:      "stable-replacement",
		StableChooserGroupID: "unused-stable-group",
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("PlanEstablishment: %v", err)
	}
	faults.armed.Store(true)
	if _, err := manager.Establish(context.Background(), plan); err == nil {
		t.Fatal("first Establish unexpectedly survived delete fault")
	}
	if _, err := backing.Sessions().Find(context.Background(), "stable-replacement"); err != nil {
		t.Fatalf("replacement was not durable before delete: %v", err)
	}
	out, err := manager.Establish(context.Background(), plan)
	if err != nil {
		t.Fatalf("retry Establish: %v", err)
	}
	if out.SessionID != "stable-replacement" {
		t.Fatalf("SessionID=%q want stable-replacement", out.SessionID)
	}
	replacement, err := backing.Sessions().Find(context.Background(), out.SessionID)
	if err != nil {
		t.Fatalf("Find replacement: %v", err)
	}
	if !replacement.AuthTime.Equal(now) {
		t.Errorf("replacement AuthTime=%v want %v", replacement.AuthTime, now)
	}
	if !replacement.CreatedAt.Equal(now) {
		t.Errorf("replacement CreatedAt=%v want %v", replacement.CreatedAt, now)
	}
	if replacement.ACR != "" {
		t.Errorf("replacement ACR=%q want empty fresh-login ACR", replacement.ACR)
	}
	if len(replacement.AMR) != 2 || replacement.AMR[1] != "otp" {
		t.Errorf("replacement AMR=%v want [pwd otp]", replacement.AMR)
	}
	if _, err := backing.Sessions().Find(context.Background(), issued.SessionID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("previous session remains after retry: %v", err)
	}
	group, err := backing.Sessions().ListByChooserGroup(context.Background(), issued.ChooserGroupID)
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(group) != 1 || group[0].ID != "stable-replacement" {
		t.Fatalf("sessions=%v want only stable replacement", group)
	}
}
