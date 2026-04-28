package op_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// stubMailer is the [op.EmailDelivery] used in the H1-D2 wiring tests.
// The Send hook is a no-op: the tests exercise the builder path
// (construction + dependency-presence checks), not the delivery
// behaviour.
type stubMailer struct{}

func (stubMailer) Send(_ context.Context, _, _ string) error { return nil }

// stubCaptchaVerifier is the [op.CaptchaVerifier] used in the H1-D2
// wiring tests. Verify always succeeds; the builder path that the
// tests cover does not run the verifier.
type stubCaptchaVerifier struct{}

func (stubCaptchaVerifier) Verify(_ context.Context, _ op.CaptchaInput) error { return nil }

// TestProjectStepToFlow_BuiltinSteps_BuildSuccessfully covers the
// happy path for every built-in [op.Step] H1-D2 wires:
// PrimaryPasskey, StepTOTP, StepEmailOTP, StepRecoveryCode,
// StepCaptcha. The test runs each Step through op.New (which invokes
// projectStepToFlow internally) and asserts the construction succeeds.
//
// PrimaryPassword is intentionally omitted: H1-D2 documents the
// password-credential store contract as deferred and the builder
// returns op.Error wrapping authn.ErrBuiltinStepNotWired.
func TestProjectStepToFlow_BuiltinSteps_BuildSuccessfully(t *testing.T) {
	t.Parallel()

	type buildCase struct {
		name string
		flow func(st *inmem.Store) op.LoginFlow
	}
	totpKey := bytes32("totp-encryption-key-32-bytes-aaa")
	cases := []buildCase{
		{
			name: "PrimaryPasskey",
			flow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{
					Primary: op.PrimaryPasskey{
						Store:         st.Passkeys(),
						RPID:          "id.example.com",
						RPDisplayName: "Example",
						RPOrigins:     []string{"https://id.example.com"},
					},
				}
			},
		},
		{
			name: "StepTOTP",
			flow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{
					Primary: externalPrimary(),
					Rules: []op.Rule{{
						When: func(op.LoginContext) bool { return true },
						Then: op.StepTOTP{Store: st.TOTPs(), EncryptionKey: totpKey},
					}},
				}
			},
		},
		{
			name: "StepEmailOTP",
			flow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{
					Primary: externalPrimary(),
					Rules: []op.Rule{{
						When: func(op.LoginContext) bool { return true },
						Then: op.StepEmailOTP{
							Store:  st.EmailOTPs(),
							Sender: stubMailer{},
							Users:  st.Users(),
						},
					}},
				}
			},
		},
		{
			name: "StepRecoveryCode",
			flow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{
					Primary: externalPrimary(),
					Rules: []op.Rule{{
						When: func(op.LoginContext) bool { return true },
						Then: op.StepRecoveryCode{Store: st.RecoveryCodes()},
					}},
				}
			},
		},
		{
			name: "StepCaptcha",
			flow: func(_ *inmem.Store) op.LoginFlow {
				return op.LoginFlow{
					Primary: externalPrimary(),
					Rules: []op.Rule{{
						When: func(op.LoginContext) bool { return true },
						Then: op.StepCaptcha{Verifier: stubCaptchaVerifier{}},
					}},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := inmem.New()
			opts := append(validBaseOptsWithStore(t, st), op.WithLoginFlow(tc.flow(st)))
			if _, err := op.New(opts...); err != nil {
				t.Fatalf("op.New for %s: unexpected error: %v", tc.name, err)
			}
		})
	}
}

// TestProjectStepToFlow_BuiltinSteps_RejectMissingDeps covers the
// negative path: each builder MUST return a typed *op.Error pointing
// at the offending Step when a required dependency is nil. The
// fixture intentionally constructs each Step with one missing field;
// the test asserts the error chain carries the field-level message
// (so a misconfiguration is actionable from the op.New return alone).
func TestProjectStepToFlow_BuiltinSteps_RejectMissingDeps(t *testing.T) {
	t.Parallel()

	type rejectCase struct {
		name       string
		buildFlow  func(st *inmem.Store) op.LoginFlow
		wantSubstr string
	}
	totpKey := bytes32("totp-encryption-key-32-bytes-aaa")
	cases := []rejectCase{
		{
			name: "PrimaryPasskey/nil-store",
			buildFlow: func(*inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: op.PrimaryPasskey{
					RPID:          "x",
					RPDisplayName: "x",
					RPOrigins:     []string{"https://x"},
				}}
			},
			wantSubstr: "PrimaryPasskey.Store is nil",
		},
		{
			name: "PrimaryPasskey/empty-RPID",
			buildFlow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: op.PrimaryPasskey{
					Store:         st.Passkeys(),
					RPDisplayName: "x",
					RPOrigins:     []string{"https://x"},
				}}
			},
			wantSubstr: "RPID is required",
		},
		{
			name: "StepTOTP/nil-store",
			buildFlow: func(_ *inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: externalPrimary(), Rules: []op.Rule{{
					When: func(op.LoginContext) bool { return true },
					Then: op.StepTOTP{EncryptionKey: totpKey},
				}}}
			},
			wantSubstr: "StepTOTP.Store is nil",
		},
		{
			name: "StepTOTP/missing-key",
			buildFlow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: externalPrimary(), Rules: []op.Rule{{
					When: func(op.LoginContext) bool { return true },
					Then: op.StepTOTP{Store: st.TOTPs()},
				}}}
			},
			wantSubstr: "EncryptionKey is required",
		},
		{
			name: "StepEmailOTP/nil-mailer",
			buildFlow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: externalPrimary(), Rules: []op.Rule{{
					When: func(op.LoginContext) bool { return true },
					Then: op.StepEmailOTP{Store: st.EmailOTPs(), Users: st.Users()},
				}}}
			},
			wantSubstr: "StepEmailOTP.Sender is nil",
		},
		{
			name: "StepEmailOTP/nil-users",
			buildFlow: func(st *inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: externalPrimary(), Rules: []op.Rule{{
					When: func(op.LoginContext) bool { return true },
					Then: op.StepEmailOTP{Store: st.EmailOTPs(), Sender: stubMailer{}},
				}}}
			},
			wantSubstr: "StepEmailOTP.Users is nil",
		},
		{
			name: "StepRecoveryCode/nil-store",
			buildFlow: func(*inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: externalPrimary(), Rules: []op.Rule{{
					When: func(op.LoginContext) bool { return true },
					Then: op.StepRecoveryCode{},
				}}}
			},
			wantSubstr: "StepRecoveryCode.Store is nil",
		},
		{
			name: "StepCaptcha/nil-verifier",
			buildFlow: func(*inmem.Store) op.LoginFlow {
				return op.LoginFlow{Primary: externalPrimary(), Rules: []op.Rule{{
					When: func(op.LoginContext) bool { return true },
					Then: op.StepCaptcha{},
				}}}
			},
			wantSubstr: "StepCaptcha.Verifier is nil",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := inmem.New()
			opts := append(validBaseOptsWithStore(t, st), op.WithLoginFlow(tc.buildFlow(st)))
			_, err := op.New(opts...)
			if err == nil {
				t.Fatalf("op.New: expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("op.New: error %q does not contain %q", err.Error(), tc.wantSubstr)
			}
			var typed *op.Error
			if !errors.As(err, &typed) {
				t.Fatalf("op.New: expected *op.Error, got %T", err)
			}
			if typed.Code != "configuration_error" {
				t.Fatalf("op.Error.Code = %q, want %q", typed.Code, "configuration_error")
			}
		})
	}
}

// TestProjectStepToFlow_PrimaryPasswordDeferred pins the
// PrimaryPassword path returns the documented "wiring deferred"
// message. The test exists to flip red the moment the
// password-credential store contract lands: removing the deferred
// branch silently from projectStepToFlow would otherwise leave
// embedders staring at a nil-Authenticator runtime panic.
func TestProjectStepToFlow_PrimaryPasswordDeferred(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	flow := op.LoginFlow{Primary: op.PrimaryPassword{Store: st.Users()}}
	opts := append(validBaseOptsWithStore(t, st), op.WithLoginFlow(flow))
	_, err := op.New(opts...)
	if err == nil {
		t.Fatalf("op.New: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "PrimaryPassword wiring is deferred") {
		t.Fatalf("op.New: error %q does not contain deferred-message", err.Error())
	}
}

// validBaseOptsWithStore is a thin wrapper over [validBaseOpts] that
// substitutes the inmem [*inmem.Store] the caller has already built
// (so the LoginFlow under test can pull substores off it). The base
// keyset / cookie / issuer come from validBaseOpts; only the store
// changes.
func validBaseOptsWithStore(tb testing.TB, st *inmem.Store) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKey(newRandomCookieKey(tb)),
	}
}

// externalPrimary returns an [op.ExternalStep] suitable for use as a
// LoginFlow.Primary in tests that exercise rule-attached Steps. The
// wrapped authenticator is a minimal stub: the tests do not run the
// chain, only the compile path.
func externalPrimary() op.ExternalStep {
	return op.ExternalStep{
		Authenticator: stubExternalAuthenticator{},
		KindLabel:     op.StepKind("test.primary"),
	}
}

// stubExternalAuthenticator is the [op.Authenticator] wrapped by
// [externalPrimary]. The methods return inert values; the LoginFlow
// compile path never invokes Begin / Continue, so the inert returns
// are never observed.
type stubExternalAuthenticator struct{}

func (stubExternalAuthenticator) Type() op.FactorType { return "test.primary" }
func (stubExternalAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (stubExternalAuthenticator) AMR() string         { return "pwd" }
func (stubExternalAuthenticator) Prompts() []string   { return []string{"test.primary"} }
func (stubExternalAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errors.New("stub")
}

func (stubExternalAuthenticator) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errors.New("stub")
}

// bytes32 returns a 32-byte slice padded from the supplied seed. The
// helper avoids hard-coded byte literals that would lint-trip as
// suspicious credential material.
func bytes32(seed string) []byte {
	out := make([]byte, 32)
	copy(out, seed)
	return out
}
