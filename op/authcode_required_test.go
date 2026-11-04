package op_test

import (
	"errors"
	"html/template"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// browserSurfaceOptions returns one explicit instance of each browser
// sign-in option, keyed by option name.
func browserSurfaceOptions() map[string]op.Option {
	tmpl := template.Must(template.New("t").Parse("ok"))
	return map[string]op.Option{
		"WithLoginFlow": op.WithLoginFlow(op.LoginFlow{Primary: op.ExternalStep{
			Authenticator: &stubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKind("myorg.password"),
		}}),
		"WithUI":                op.WithUI(op.HTMLUI{Consent: op.PageTemplate{Template: tmpl}}),
		"WithInteractions":      op.WithInteractions(stubInteraction{name: "myorg.kyc.start", trigger: op.TriggerAfterAuthn}),
		"WithFirstPartyClients": op.WithFirstPartyClients("first-party"),
	}
}

// TestNew_RejectsBrowserSurfaceWithoutAuthorizationCode pins that each
// browser sign-in option set explicitly, combined with a grant set that
// has no /authorize endpoint, fails construction and is named.
func TestNew_RejectsBrowserSurfaceWithoutAuthorizationCode(t *testing.T) {
	t.Parallel()

	for name, opt := range browserSurfaceOptions() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOptsNoAuthn(t), opt, op.WithGrants(grant.ClientCredentials))...)
			if !errors.Is(err, op.ErrAuthorizationCodeGrantRequired) {
				t.Fatalf("err = %v, want ErrAuthorizationCodeGrantRequired", err)
			}
			if !op.IsServerError(err) {
				t.Errorf("err = %v, want a configuration error", err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("err = %v, want it to name %s", err, name)
			}
		})
	}
}

// TestNew_LoginFlowAsClaimSourceNeedsNoAuthorizationCode pins the
// device-code exemption: a login flow that is the claim source is
// legitimate without authorization_code, and an explicit WithUserStore
// takes that role away.
func TestNew_LoginFlowAsClaimSourceNeedsNoAuthorizationCode(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, explicitUserStore bool) error {
		t.Helper()
		st := inmem.New()
		opts := []op.Option{
			op.WithDefaults(
				op.WithIssuer(validIssuer),
				op.WithStore(st),
				op.WithKeyset(validKeyset(t)),
				op.WithCookieKeys(newRandomCookieKey(t)),
			),
			op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: st.UserPasswords()}}),
			op.WithGrants(grant.DeviceCode),
		}
		if explicitUserStore {
			opts = append(opts, op.WithUserStore(st.Users()))
		}
		_, err := op.New(opts...)
		return err
	}

	t.Run("login flow is claim source", func(t *testing.T) {
		t.Parallel()
		if err := build(t, false); errors.Is(err, op.ErrAuthorizationCodeGrantRequired) {
			t.Fatalf("err = %v, want the check to pass", err)
		}
	})
	t.Run("explicit WithUserStore", func(t *testing.T) {
		t.Parallel()
		err := build(t, true)
		if !errors.Is(err, op.ErrAuthorizationCodeGrantRequired) {
			t.Fatalf("err = %v, want ErrAuthorizationCodeGrantRequired", err)
		}
		if !strings.Contains(err.Error(), "WithLoginFlow") {
			t.Errorf("err = %v, want it to name WithLoginFlow", err)
		}
	})
}

// TestNew_BrowserSurfaceWithAuthorizationCodeIsAccepted pins that the
// check is silent once authorization_code is listed, with every browser
// sign-in option set at once.
func TestNew_BrowserSurfaceWithAuthorizationCodeIsAccepted(t *testing.T) {
	t.Parallel()

	all := browserSurfaceOptions()
	if len(all) != 4 {
		t.Fatalf("browserSurfaceOptions has %d entries, want 4", len(all))
	}
	opts := validBaseOptsNoAuthn(t)
	for _, opt := range all {
		opts = append(opts, opt)
	}
	opts = append(opts, op.WithGrants(grant.AuthorizationCode, grant.ClientCredentials))
	_, err := op.New(opts...)
	if errors.Is(err, op.ErrAuthorizationCodeGrantRequired) {
		t.Fatalf("err = %v, want no ErrAuthorizationCodeGrantRequired", err)
	}
}

// TestNew_DefaultedLoginFlowWithoutAuthorizationCodeIsAccepted pins that a
// login flow arriving through WithDefaults (the shared harness baseline)
// is not counted.
func TestNew_DefaultedLoginFlowWithoutAuthorizationCodeIsAccepted(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithGrants(grant.ClientCredentials))...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
}
