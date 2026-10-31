package op

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestEffectiveUserStore_Inference pins the claim-source resolution order:
// an explicit WithUserStore value, then the primary PrimaryPassword's
// Store, then Store.Users().
func TestEffectiveUserStore_Inference(t *testing.T) {
	t.Parallel()

	backend := inmem.New()
	primary := inmem.New()
	explicit := inmem.New()
	var nilPasswords store.UserPasswordStore

	cases := []struct {
		name     string
		userSt   store.UserStore
		flow     *LoginFlow
		wantSame store.UserStore
	}{
		{
			name:     "WithUserStore wins over the primary store",
			userSt:   explicit.Users(),
			flow:     &LoginFlow{Primary: PrimaryPassword{Store: primary.UserPasswords()}},
			wantSame: explicit.Users(),
		},
		{
			name:     "primary PrimaryPassword",
			flow:     &LoginFlow{Primary: PrimaryPassword{Store: primary.UserPasswords()}},
			wantSame: primary.Users(),
		},
		{
			name: "StepOneOf password and passkey",
			flow: &LoginFlow{Primary: StepOneOf{Steps: []Step{
				PrimaryPasskey{Store: primary.Passkeys(), RequireUserVerification: true},
				PrimaryPassword{Store: primary.UserPasswords()},
			}}},
			wantSame: primary.Users(),
		},
		{
			name: "StepOneOf skips a nil-like password store",
			flow: &LoginFlow{Primary: StepOneOf{Steps: []Step{
				PrimaryPassword{Store: nilPasswords},
				PrimaryPassword{Store: primary.UserPasswords()},
			}}},
			wantSame: primary.Users(),
		},
		{
			name:     "ExternalStep falls back to Store.Users()",
			flow:     &LoginFlow{Primary: ExternalStep{}},
			wantSame: backend.Users(),
		},
		{
			name:     "PrimaryPassword with a nil-like Store falls back to Store.Users()",
			flow:     &LoginFlow{Primary: PrimaryPassword{Store: nilPasswords}},
			wantSame: backend.Users(),
		},
		{
			name:     "no login flow falls back to Store.Users()",
			wantSame: backend.Users(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &config{store: backend, userStore: tc.userSt}
			if tc.flow != nil {
				c.loginFlow = *tc.flow
				c.loginFlowSet = true
			}
			if got := c.effectiveUserStore(); any(got) != any(tc.wantSame) {
				t.Fatalf("effectiveUserStore = %T(%p), want %T(%p)", got, got, tc.wantSame, tc.wantSame)
			}
		})
	}
}

// TestEffectiveUserStore_InfoNamesClaimSource checks the construction
// notice: exactly one INFO naming the claim source, which also says
// Store.Users() goes unread when the source is a different store.
func TestEffectiveUserStore_InfoNamesClaimSource(t *testing.T) {
	t.Parallel()

	backend := inmem.New()
	other := inmem.New()

	cases := []struct {
		name       string
		userSt     store.UserStore
		primary    store.UserPasswordStore
		wantSource string
		wantUnread bool
	}{
		{name: "inferred, different stores", primary: other.UserPasswords(), wantSource: "LoginFlow.Primary PrimaryPassword.Store", wantUnread: true},
		{name: "inferred, identical stores", primary: backend.UserPasswords(), wantSource: "LoginFlow.Primary PrimaryPassword.Store"},
		{name: "explicit WithUserStore", userSt: other.Users(), wantSource: "WithUserStore", wantUnread: true},
		{name: "Store.Users fallback", wantSource: "WithStore(...).Users()"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			c := &config{
				store:     backend,
				userStore: tc.userSt,
				logger:    slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})),
			}
			if tc.primary != nil {
				c.loginFlow = LoginFlow{Primary: PrimaryPassword{Store: tc.primary}}
				c.loginFlowSet = true
			}
			c.warnUserStoreMismatch()
			out := buf.String()
			if got := strings.Count(out, "level=INFO"); got != 1 {
				t.Fatalf("INFO lines = %d, want 1; got:\n%s", got, out)
			}
			if !strings.Contains(out, "claim_source="+tc.wantSource) && !strings.Contains(out, `claim_source="`+tc.wantSource+`"`) {
				t.Fatalf("INFO does not name claim_source %q; got:\n%s", tc.wantSource, out)
			}
			if got := strings.Contains(out, "store_users="); got != tc.wantUnread {
				t.Fatalf("store_users attribute present = %v, want %v; got:\n%s", got, tc.wantUnread, out)
			}
			if strings.Contains(out, "level=WARN") {
				t.Fatalf("resolution must not warn; got:\n%s", out)
			}
		})
	}
}
