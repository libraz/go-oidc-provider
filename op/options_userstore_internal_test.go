package op

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestEffectiveUserStore_Inference pins the claim-source resolution order:
// an explicit WithUserStore value, then the primary PrimaryPassword's
// Store, then a WithUserStore value that came from WithDefaults. Nothing
// else is consulted: the aggregate store carries no users.
func TestEffectiveUserStore_Inference(t *testing.T) {
	t.Parallel()

	backend := inmem.New()
	primary := inmem.New()
	explicit := inmem.New()
	var nilPasswords store.UserPasswordStore

	cases := []struct {
		name   string
		userSt store.UserStore
		flow   *LoginFlow
		// defaulted marks userSt as supplied through WithDefaults.
		defaulted bool
		wantSame  store.UserStore
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
			name:     "ExternalStep resolves nothing",
			flow:     &LoginFlow{Primary: ExternalStep{}},
			wantSame: nil,
		},
		{
			name:     "PrimaryPassword with a nil-like Store resolves nothing",
			flow:     &LoginFlow{Primary: PrimaryPassword{Store: nilPasswords}},
			wantSame: nil,
		},
		{
			name:     "no login flow resolves nothing",
			wantSame: nil,
		},
		{
			name:      "defaulted WithUserStore applies when nothing else does",
			userSt:    explicit.Users(),
			defaulted: true,
			wantSame:  explicit.Users(),
		},
		{
			name:      "defaulted WithUserStore yields to the primary store",
			userSt:    explicit.Users(),
			defaulted: true,
			flow:      &LoginFlow{Primary: PrimaryPassword{Store: primary.UserPasswords()}},
			wantSame:  primary.Users(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &config{store: backend, userStore: tc.userSt}
			if tc.defaulted {
				c.claimed = map[string]claim{"WithUserStore": {option: "WithUserStore", fallback: true}}
			}
			if tc.flow != nil {
				c.loginFlow = *tc.flow
				c.loginFlowSet = true
			}
			if got := c.effectiveUserStore(); !nilcheck.IsNil(got) && any(got) != any(tc.wantSame) || nilcheck.IsNil(got) && tc.wantSame != nil {
				t.Fatalf("effectiveUserStore = %T(%p), want %T(%p)", got, got, tc.wantSame, tc.wantSame)
			}
		})
	}
}

// TestEffectiveUserStore_InfoNamesClaimSource checks the construction
// notice: exactly one INFO naming the claim source, which is one of two
// options.
func TestEffectiveUserStore_InfoNamesClaimSource(t *testing.T) {
	t.Parallel()

	other := inmem.New()

	cases := []struct {
		name       string
		userSt     store.UserStore
		primary    store.UserPasswordStore
		wantSource string
	}{
		{name: "inferred", primary: other.UserPasswords(), wantSource: "LoginFlow.Primary PrimaryPassword.Store"},
		{name: "explicit WithUserStore", userSt: other.Users(), wantSource: "WithUserStore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			c := &config{
				store:     inmem.New(),
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
			if strings.Contains(out, "store_users") {
				t.Fatalf("INFO still carries a store_users attribute; got:\n%s", out)
			}
			if strings.Contains(out, "level=WARN") {
				t.Fatalf("resolution must not warn; got:\n%s", out)
			}
		})
	}
}
