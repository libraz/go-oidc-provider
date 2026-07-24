package op_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type typedNilCloneHandler struct{}

func (*typedNilCloneHandler) HandleCloneDetected(context.Context, string, []byte, uint32) error {
	return nil
}

type typedNilDecider struct{}

func (*typedNilDecider) Decide(context.Context, op.LoginContext) op.Decision { //nolint:ireturn // test double implements the public interface verbatim.
	return op.Pass{}
}

type typedNilClock struct{}

func (*typedNilClock) Now() time.Time { return time.Time{} }

type typedNilNonceSource struct{}

func (*typedNilNonceSource) IssueNonce() string   { return "" }
func (*typedNilNonceSource) Validate(string) bool { return false }

type typedNilSubjectGenerator struct{}

func (*typedNilSubjectGenerator) Generate(context.Context, op.SubjectGeneratorInput) (op.Subject, error) {
	return "", nil
}

type typedNilTokenExchangePolicy struct{}

func (*typedNilTokenExchangePolicy) Allow(context.Context, op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return &op.TokenExchangeDecision{}, nil
}

// typedNilFrom converts a non-nil interface sample into the same interface
// carrying the concrete type's zero value. Test callers supply pointer-backed
// implementations, so the result is the typed-nil shape that defeats a plain
// interface == nil check.
func typedNilFrom[T any](t *testing.T, sample T) T { //nolint:ireturn // preserving the requested interface type is the purpose of this typed-nil fixture helper.
	t.Helper()

	value := reflect.ValueOf(sample)
	switch value.Kind() {
	case reflect.Ptr, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan, reflect.Interface:
	default:
		t.Fatalf("typedNilFrom requires a nil-able concrete sample, got %T", sample)
	}
	typedNil, ok := reflect.Zero(value.Type()).Interface().(T)
	if !ok {
		t.Fatalf("typedNilFrom cannot convert %T back to the requested interface", sample)
	}
	return typedNil
}

func TestWithLoginFlow_RejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		field     string
		buildFlow func(*testing.T, *inmem.Store) op.LoginFlow
	}
	totpKey := bytes32("typed-nil-totp-key-32-bytes-aa")
	cases := []testCase{
		{
			name:  "primary-step",
			field: "LoginFlow.Primary",
			buildFlow: func(t *testing.T, _ *inmem.Store) op.LoginFlow {
				t.Helper()
				return op.LoginFlow{Primary: typedNilFrom[op.Step](t, &stagedH1DStep{})}
			},
		},
		{
			name:  "primary-password-store",
			field: "Primary.PrimaryPassword.Store",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				store := typedNilFrom[store.UserPasswordStore](t, st.UserPasswords())
				return op.LoginFlow{Primary: op.PrimaryPassword{Store: store}}
			},
		},
		{
			name:  "primary-passkey-store",
			field: "Primary.PrimaryPasskey.Store",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				passkeys := typedNilFrom[store.PasskeyStore](t, st.Passkeys())
				return op.LoginFlow{Primary: op.PrimaryPasskey{
					Store:         passkeys,
					RPID:          "id.example.com",
					RPDisplayName: "Example",
					RPOrigins:     []string{"https://id.example.com"},
				}}
			},
		},
		{
			name:  "primary-passkey-clone-handler",
			field: "Primary.PrimaryPasskey.CloneDetectionHandler",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				hook := typedNilFrom[op.PasskeyCloneDetectionHandler](t, &typedNilCloneHandler{})
				return op.LoginFlow{Primary: op.PrimaryPasskey{
					Store:                 st.Passkeys(),
					RPID:                  "id.example.com",
					RPDisplayName:         "Example",
					RPOrigins:             []string{"https://id.example.com"},
					CloneDetectionHandler: hook,
				}}
			},
		},
		{
			name:  "totp-store",
			field: "Rules[0].Then.StepTOTP.Store",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				totps := typedNilFrom[store.TOTPStore](t, st.TOTPs())
				return flowWithRule(op.StepTOTP{Store: totps, EncryptionKey: totpKey})
			},
		},
		{
			name:  "email-otp-store",
			field: "Rules[0].Then.StepEmailOTP.Store",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				records := typedNilFrom[store.EmailOTPStore](t, st.EmailOTPs())
				return flowWithRule(op.StepEmailOTP{Store: records, Sender: stubMailer{}, Users: st.Users()})
			},
		},
		{
			name:  "email-otp-sender",
			field: "Rules[0].Then.StepEmailOTP.Sender",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				sender := typedNilFrom[op.EmailDelivery](t, &stubMailer{})
				return flowWithRule(op.StepEmailOTP{Store: st.EmailOTPs(), Sender: sender, Users: st.Users()})
			},
		},
		{
			name:  "email-otp-users",
			field: "Rules[0].Then.StepEmailOTP.Users",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				users := typedNilFrom[store.UserStore](t, st.Users())
				return flowWithRule(op.StepEmailOTP{Store: st.EmailOTPs(), Sender: stubMailer{}, Users: users})
			},
		},
		{
			name:  "recovery-store",
			field: "Rules[0].Then.StepRecoveryCode.Store",
			buildFlow: func(t *testing.T, st *inmem.Store) op.LoginFlow {
				t.Helper()
				recovery := typedNilFrom[store.RecoveryStore](t, st.RecoveryCodes())
				return flowWithRule(op.StepRecoveryCode{Store: recovery})
			},
		},
		{
			name:  "captcha-verifier",
			field: "Rules[0].Then.StepCaptcha.Verifier",
			buildFlow: func(t *testing.T, _ *inmem.Store) op.LoginFlow {
				t.Helper()
				verifier := typedNilFrom[op.CaptchaVerifier](t, &stubCaptcha{})
				return flowWithRule(op.StepCaptcha{Verifier: verifier})
			},
		},
		{
			name:  "external-authenticator",
			field: "Primary.ExternalStep.Authenticator",
			buildFlow: func(t *testing.T, _ *inmem.Store) op.LoginFlow {
				t.Helper()
				auth := typedNilFrom[op.Authenticator](t, &h1dStubAuth{})
				return op.LoginFlow{Primary: op.ExternalStep{
					Authenticator: auth,
					KindLabel:     "test.primary",
				}}
			},
		},
		{
			name:  "decider",
			field: "LoginFlow.Decider",
			buildFlow: func(t *testing.T, _ *inmem.Store) op.LoginFlow {
				t.Helper()
				decider := typedNilFrom[op.Decider](t, &typedNilDecider{})
				return op.LoginFlow{Primary: externalPrimary(), Decider: decider}
			},
		},
		{
			name:  "risk",
			field: "LoginFlow.Risk",
			buildFlow: func(t *testing.T, _ *inmem.Store) op.LoginFlow {
				t.Helper()
				risk := typedNilFrom[op.RiskAssessor](t, &stubRisk{})
				return op.LoginFlow{Primary: externalPrimary(), Risk: risk}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			st := inmem.New()
			_, err := op.New(append(validBaseOpts(t), op.WithLoginFlow(tc.buildFlow(t, st)))...)
			if err == nil {
				t.Fatalf("op.New accepted typed-nil %s", tc.field)
			}
			if !op.IsServerError(err) {
				t.Fatalf("error for %s is not a configuration error: %v", tc.field, err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error %q does not identify field %q", err, tc.field)
			}
		})
	}
}

func TestPublicAuthnOptions_RejectTypedNilDependencies(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	cases := []struct {
		name   string
		field  string
		option op.Option
	}{
		{
			name:   "interaction-driver",
			field:  "WithInteractionDriver",
			option: op.WithInteractionDriver(typedNilFrom[interaction.Driver](t, &recordingDriver{})),
		},
		{
			name:   "authn-lockout-store",
			field:  "WithAuthnLockoutStore",
			option: op.WithAuthnLockoutStore(typedNilFrom[store.AuthnLockoutStore](t, st.AuthnLockouts())),
		},
		{
			name:   "authenticator",
			field:  "WithAuthenticators",
			option: op.WithAuthenticators(typedNilFrom[op.Authenticator](t, &h1dStubAuth{})),
		},
		{
			name:   "captcha-verifier",
			field:  "WithCaptchaVerifier",
			option: op.WithCaptchaVerifier(typedNilFrom[op.CaptchaVerifier](t, &stubCaptcha{})),
		},
		{
			name:   "risk-assessor",
			field:  "WithRiskAssessor",
			option: op.WithRiskAssessor(typedNilFrom[op.RiskAssessor](t, &stubRisk{})),
		},
		{
			name:   "login-attempt-observer",
			field:  "WithLoginAttemptObserver",
			option: op.WithLoginAttemptObserver(typedNilFrom[op.LoginAttemptObserver](t, &stubObserver{})),
		},
		{
			name:   "interaction",
			field:  "WithInteractions",
			option: op.WithInteractions(typedNilFrom[op.Interaction](t, &stubInteraction{})),
		},
		{
			name:   "clock",
			field:  "WithClock",
			option: op.WithClock(typedNilFrom[op.Clock](t, &typedNilClock{})),
		},
		{
			name:   "dpop-nonce-source",
			field:  "WithDPoPNonceSource",
			option: op.WithDPoPNonceSource(typedNilFrom[op.DPoPNonceSource](t, &typedNilNonceSource{})),
		},
		{
			name:   "jwks-http-transport",
			field:  "WithJWKSHTTPTransport",
			option: op.WithJWKSHTTPTransport(typedNilFrom[http.RoundTripper](t, &http.Transport{})),
		},
		{
			name:   "subject-generator",
			field:  "WithSubjectGenerator",
			option: op.WithSubjectGenerator(typedNilFrom[op.SubjectGenerator](t, &typedNilSubjectGenerator{})),
		},
		{
			name:   "custom-grant",
			field:  "WithCustomGrant",
			option: op.WithCustomGrant(typedNilFrom[op.CustomGrantHandler](t, &fakeCustomGrant{})),
		},
		{
			name:   "token-exchange-policy",
			field:  "RegisterTokenExchange",
			option: op.RegisterTokenExchange(typedNilFrom[op.TokenExchangePolicy](t, &typedNilTokenExchangePolicy{})),
		},
		{
			name:   "static-client-seed",
			field:  "WithStaticClients[0]",
			option: op.WithStaticClients(typedNilFrom[op.ClientSeed](t, &op.PublicClient{})),
		},
		{
			name:  "ciba-hint-resolver",
			field: "WithCIBAHintResolver",
			option: op.WithCIBA(op.WithCIBAHintResolver(
				typedNilFrom[op.HintResolver](t, &stubHintResolver{}),
			)),
		},
		{
			name:   "ciba-option",
			field:  "WithCIBA",
			option: op.WithCIBA(typedNilFrom[op.CIBAOption](t, op.WithCIBADefaultExpiresIn(time.Minute))),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOpts(t), tc.option)...)
			if err == nil {
				t.Fatalf("op.New accepted typed-nil dependency for %s", tc.field)
			}
			if !op.IsServerError(err) {
				t.Fatalf("error for %s is not a configuration error: %v", tc.field, err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error %q does not identify option %q", err, tc.field)
			}
		})
	}
}

func TestWithACRPolicy_TypedNilRestoresDefault(t *testing.T) {
	t.Parallel()

	policy := typedNilFrom[op.ACRPolicy](t, &stubACRPolicy{})
	if _, err := op.New(append(validBaseOpts(t), op.WithACRPolicy(policy))...); err != nil {
		t.Fatalf("WithACRPolicy typed nil did not restore the documented default: %v", err)
	}
}

func flowWithRule(step op.Step) op.LoginFlow {
	return op.LoginFlow{
		Primary: externalPrimary(),
		Rules: []op.Rule{{
			When: func(op.LoginContext) bool { return true },
			Then: step,
		}},
	}
}
