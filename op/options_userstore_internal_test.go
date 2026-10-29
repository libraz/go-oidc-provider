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

// TestEffectiveUserStore_InfoOnInference checks the migration notice: one
// INFO when the inferred store differs from Store.Users(), none when they
// are the same value.
func TestEffectiveUserStore_InfoOnInference(t *testing.T) {
	t.Parallel()

	backend := inmem.New()
	other := inmem.New()

	cases := []struct {
		name     string
		primary  store.UserPasswordStore
		wantInfo int
	}{
		{name: "different stores", primary: other.UserPasswords(), wantInfo: 1},
		{name: "identical stores", primary: backend.UserPasswords(), wantInfo: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			c := &config{
				store:        backend,
				logger:       slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})),
				loginFlow:    LoginFlow{Primary: PrimaryPassword{Store: tc.primary}},
				loginFlowSet: true,
			}
			c.warnUserStoreMismatch()
			out := buf.String()
			if got := strings.Count(out, "level=INFO"); got != tc.wantInfo {
				t.Fatalf("INFO lines = %d, want %d; got:\n%s", got, tc.wantInfo, out)
			}
			if strings.Contains(out, "level=WARN") {
				t.Fatalf("inference must not warn; got:\n%s", out)
			}
		})
	}
}
