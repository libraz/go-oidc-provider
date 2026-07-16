package chooser_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/chooser"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestInteractionMetadataAndSelfSkip(t *testing.T) {
	t.Parallel()

	mgr := newChooserManager(t, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	ix := chooser.New(mgr)
	if got := ix.Name(); got != authn.BuiltinChooserName {
		t.Fatalf("Name() = %q, want %q", got, authn.BuiltinChooserName)
	}
	if got := ix.Trigger(); got != authn.TriggerBeforeAuthn {
		t.Fatalf("Trigger() = %v, want %v", got, authn.TriggerBeforeAuthn)
	}

	step, err := ix.Begin(context.Background(), authn.BeginInput{})
	if err != nil {
		t.Fatalf("Begin without chooser group returned error: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("Begin without chooser group should self-skip with a Result step: %+v", step)
	}
	if step.Prompt != nil {
		t.Fatalf("Begin without chooser group returned prompt: %+v", step.Prompt)
	}
}

func TestInteractionBeginListsLiveAccountsForChooserPrompt(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	mgr := newChooserManager(t, t0)
	first, second := issueTwoAccounts(t, ctx, mgr, t0)
	ix := chooser.New(mgr)

	step, err := ix.Begin(ctx, authn.BeginInput{ChooserGroupID: first.ChooserGroupID})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("Begin returned no prompt: %+v", step)
	}
	if step.Prompt.Type != authn.ChooserPromptType {
		t.Fatalf("Prompt.Type = %q, want %q", step.Prompt.Type, authn.ChooserPromptType)
	}
	if len(step.Prompt.Inputs) != 1 {
		t.Fatalf("len(Prompt.Inputs) = %d, want 1", len(step.Prompt.Inputs))
	}
	input := step.Prompt.Inputs[0]
	if input.Name != authn.ChooserSessionIDField || !input.Required {
		t.Fatalf("input = %+v, want required %q", input, authn.ChooserSessionIDField)
	}
	if input.MaxLen < len(first.SessionID) || input.MaxLen < len(second.SessionID) {
		t.Fatalf("input MaxLen=%d is too small for issued session IDs", input.MaxLen)
	}

	data, ok := step.Prompt.Data.(interaction.ChooserPromptData)
	if !ok {
		t.Fatalf("Prompt.Data = %T, want interaction.ChooserPromptData", step.Prompt.Data)
	}
	got := make(map[string]interaction.ChooserAccount, len(data.Accounts))
	for _, account := range data.Accounts {
		got[account.SessionID] = account
	}
	for _, want := range []struct {
		sessionID string
		subject   string
		authTime  time.Time
	}{
		{sessionID: first.SessionID, subject: "user-a", authTime: t0},
		{sessionID: second.SessionID, subject: "user-b", authTime: t0.Add(time.Minute)},
	} {
		account, ok := got[want.sessionID]
		if !ok {
			t.Fatalf("Prompt.Data missing session %q; accounts=%v", want.sessionID, data.Accounts)
		}
		if account.Subject != want.subject {
			t.Fatalf("account %q Subject = %q, want %q", want.sessionID, account.Subject, want.subject)
		}
		if !account.AuthTime.Equal(want.authTime) {
			t.Fatalf("account %q AuthTime = %v, want %v", want.sessionID, account.AuthTime, want.authTime)
		}
	}
}

func TestInteractionContinueBindsOnlySessionsInActiveChooserGroup(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	mgr := newChooserManager(t, t0)
	first, second := issueTwoAccounts(t, ctx, mgr, t0)
	ix := chooser.New(mgr)

	step, err := ix.Continue(ctx, authn.ContinueInput{
		ChooserGroupID: first.ChooserGroupID,
		Submission: interaction.FormSubmission{Values: map[string]string{
			authn.ChooserSessionIDField: second.SessionID,
		}},
	})
	if err != nil {
		t.Fatalf("Continue valid selection: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("Continue returned no result: %+v", step)
	}
	if step.Result.Subject != "user-b" {
		t.Fatalf("Result.Subject = %q, want user-b", step.Result.Subject)
	}
	if !step.Result.AuthTime.Equal(t0.Add(time.Minute)) {
		t.Fatalf("Result.AuthTime = %v, want %v", step.Result.AuthTime, t0.Add(time.Minute))
	}

	foreign, err := mgr.Issue(ctx, sessions.Login{Subject: "other-group-user", AuthTime: t0})
	if err != nil {
		t.Fatalf("Issue foreign group: %v", err)
	}
	_, err = ix.Continue(ctx, authn.ContinueInput{
		ChooserGroupID: first.ChooserGroupID,
		Submission: interaction.FormSubmission{Values: map[string]string{
			authn.ChooserSessionIDField: foreign.SessionID,
		}},
	})
	if !errors.Is(err, chooser.ErrSessionNotInGroup) {
		t.Fatalf("foreign session err = %v, want ErrSessionNotInGroup", err)
	}
}

func TestInteractionContinueRejectsInvalidSubmissions(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	mgr := newChooserManager(t, t0)
	first, _ := issueTwoAccounts(t, ctx, mgr, t0)
	ix := chooser.New(mgr)

	cases := []struct {
		name string
		in   authn.ContinueInput
		want error
	}{
		{
			name: "missing chooser group",
			in: authn.ContinueInput{
				Submission: interaction.FormSubmission{Values: map[string]string{authn.ChooserSessionIDField: first.SessionID}},
			},
			want: chooser.ErrChooserGroupRequired,
		},
		{
			name: "missing session field",
			in: authn.ContinueInput{
				ChooserGroupID: first.ChooserGroupID,
				Submission:     interaction.FormSubmission{Values: map[string]string{}},
			},
			want: chooser.ErrSessionIDMissing,
		},
		{
			name: "empty session field",
			in: authn.ContinueInput{
				ChooserGroupID: first.ChooserGroupID,
				Submission:     interaction.FormSubmission{Values: map[string]string{authn.ChooserSessionIDField: ""}},
			},
			want: chooser.ErrSessionIDMissing,
		},
		{
			name: "expired selected session",
			in: authn.ContinueInput{
				ChooserGroupID: first.ChooserGroupID,
				Submission:     interaction.FormSubmission{Values: map[string]string{authn.ChooserSessionIDField: first.SessionID}},
			},
			want: chooser.ErrSessionNotInGroup,
		},
	}

	if err := mgr.Logout(ctx, first.SessionID); err != nil {
		t.Fatalf("Logout selected session: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := ix.Continue(ctx, tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Continue err = %v, want %v", err, tc.want)
			}
		})
	}
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time { return time.Time(c) }

func newChooserManager(tb testing.TB, now time.Time) *sessions.Manager {
	tb.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("rand.Read cookie key: %v", err)
	}
	cookieCodec, err := cookie.NewCodec(key)
	if err != nil {
		tb.Fatalf("cookie.NewCodec: %v", err)
	}
	sessionCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		tb.Fatalf("sessions.NewCodec: %v", err)
	}
	clock := func() time.Time { return now }
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: sessionCodec,
		Store: inmem.New(inmem.WithClock(fixedClock(now))).Sessions(),
		Clock: clock,
	})
	if err != nil {
		tb.Fatalf("sessions.NewManager: %v", err)
	}
	return mgr
}

func issueTwoAccounts(tb testing.TB, ctx context.Context, mgr *sessions.Manager, t0 time.Time) (sessions.Outcome, sessions.Outcome) {
	tb.Helper()

	first, err := mgr.Issue(ctx, sessions.Login{Subject: "user-a", AuthTime: t0})
	if err != nil {
		tb.Fatalf("Issue first: %v", err)
	}
	second, err := mgr.AddAccount(ctx, first.ChooserGroupID, sessions.Login{
		Subject:  "user-b",
		AuthTime: t0.Add(time.Minute),
	})
	if err != nil {
		tb.Fatalf("AddAccount second: %v", err)
	}
	if second.ChooserGroupID != first.ChooserGroupID {
		tb.Fatalf("second chooser group = %q, want %q", second.ChooserGroupID, first.ChooserGroupID)
	}
	return first, second
}
