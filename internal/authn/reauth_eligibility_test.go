package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

// reauthState is a chain started from a live session for a request that
// demands a fresh authentication (prompt=login, a stale max_age).
func reauthState() authn.State {
	st := initialState()
	st.Subject = "user-1"
	st.ReauthRequired = true
	return st
}

// TestTick_ReauthIgnoresInheritedSubjectForEligibility pins, on the
// legacy Authenticators surface, that the session subject does not make
// a possession factor eligible when the request demands a fresh
// authentication: the identifying factor runs instead, and a risk
// directive that names only a possession factor fails closed rather than
// minting a code on that factor alone. The LoginFlow surface holds the
// same line by requiring Primary to complete.
func TestTick_ReauthIgnoresInheritedSubjectForEligibility(t *testing.T) {
	t.Parallel()

	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	password := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")

	t.Run("identifying factor runs first", func(t *testing.T) {
		t.Parallel()
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{totp, password},
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, step, err := o.Tick(context.Background(), reauthState(), authn.Input{Now: fakeNow()})
		if err != nil || step.Prompt == nil {
			t.Fatalf("Tick: step=%+v err=%v", step, err)
		}
		if want := promptForFactor(op.FactorPassword).Type; step.Prompt.Type != want {
			t.Fatalf("first prompt = %q, want the password prompt %q", step.Prompt.Type, want)
		}
	})

	t.Run("risk-required possession factor fails closed", func(t *testing.T) {
		t.Parallel()
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{password, totp},
			StateRefSigner: newSigner(t),
			Risk: &stubRisk{assess: func(context.Context, op.RiskInput) (op.RiskOutcome, error) {
				return op.RiskOutcome{Decision: op.RiskRequire, RequiredFactors: []op.FactorType{op.FactorTOTP}}, nil
			}},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, step, err := o.Tick(context.Background(), reauthState(), authn.Input{Now: fakeNow()})
		if !errors.Is(err, authn.ErrNoEligibleAuthenticator) {
			t.Fatalf("Tick: step=%+v err=%v, want ErrNoEligibleAuthenticator", step, err)
		}
	})

	t.Run("no reauth keeps the session subject bound", func(t *testing.T) {
		t.Parallel()
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{totp, password},
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		st := reauthState()
		st.ReauthRequired = false
		_, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
		if err != nil || step.Prompt == nil {
			t.Fatalf("Tick: step=%+v err=%v", step, err)
		}
		if want := promptForFactor(op.FactorTOTP).Type; step.Prompt.Type != want {
			t.Fatalf("first prompt = %q, want the TOTP prompt %q", step.Prompt.Type, want)
		}
	})
}
