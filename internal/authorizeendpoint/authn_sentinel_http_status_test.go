// Package authorizeendpoint_test — regression tests for the
// factor-sentinel-to-HTTP-status mapping in writeAuthnError.
//
// Each terminal factor sentinel that wraps [authn.ErrFactorAbort] must
// produce HTTP 400; soft retries ([authn.ErrFactorRetry]) must stay at
// HTTP 200 (re-prompt); a genuinely unknown error must still produce
// HTTP 500 via the default branch.
package authorizeendpoint_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// singleSentinelAuthenticator is a test-only authenticator that:
//   - Begin: emits a prompt (simulating the emailotp "send" screen)
//   - Continue: returns continueErr verbatim (simulating the terminal
//     error cases: ErrExpired, ErrLocked, ErrResetRequired, etc.)
//
// This drives the critical path: Begin succeeds (user sees a prompt),
// user posts a submission, Continue returns a sentinel error. The
// orchestrator must decide what to do with that error.
type singleSentinelAuthenticator struct {
	continueErr error
}

const sentinelSinglePromptType = "auth.testkit.sentinel-single"

func (a *singleSentinelAuthenticator) Type() op.FactorType { return "testkit.sentinel-single" }
func (a *singleSentinelAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (a *singleSentinelAuthenticator) AMR() string         { return "" }
func (a *singleSentinelAuthenticator) Prompts() []string {
	return []string{sentinelSinglePromptType}
}

func (a *singleSentinelAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: sentinelSinglePromptType,
		Inputs: []interaction.FieldSpec{{
			Name:     "code",
			Kind:     interaction.FieldText,
			Required: true,
			MinLen:   1,
			MaxLen:   64,
		}},
	}}, nil
}

func (a *singleSentinelAuthenticator) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, a.continueErr
}

var _ op.Authenticator = (*singleSentinelAuthenticator)(nil)

// buildSingleSentinelOrchestrator wires an orchestrator with a single
// singleSentinelAuthenticator factor. Begin emits a prompt; Continue
// returns the supplied sentinel error.
func buildSingleSentinelOrchestrator(t *testing.T, sentinelErr error) *authn.Orchestrator {
	t.Helper()
	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{
			&singleSentinelAuthenticator{continueErr: sentinelErr},
		},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return orch
}

// TestAuthnSentinels_HTTPStatus drives the full /authorize →
// /interaction flow through each emailotp/TOTP/recovery-code terminal
// sentinel and asserts the HTTP status that writeAuthnError emits.
//
// Each sentinel that wraps [authn.ErrFactorAbort] must produce HTTP 400.
// [authn.ErrFactorRetry] must produce HTTP 200 (re-prompt).
// An unrecognised error must produce HTTP 500 via the default branch.
func TestAuthnSentinels_HTTPStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
		// wrapsFacotrAbort documents whether the sentinel must satisfy
		// errors.Is(err, authn.ErrFactorAbort).
		wrapsFactorAbort bool
	}{
		// emailotp sentinels — all wrap ErrFactorAbort → HTTP 400 --------
		{
			name:             "emailotp ErrExpired",
			err:              emailotp.ErrExpired,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		// ErrConsumed wraps ErrFactorAbort directly; note that
		// handleVerify maps ErrConsumed to ErrExpired before returning,
		// so the sentinel reaching writeAuthnError via that path is
		// ErrExpired. Testing ErrConsumed here verifies the sentinel's
		// own wrapping, which also covers the direct-Consume CAS-loss path.
		{
			name:             "emailotp ErrConsumed",
			err:              emailotp.ErrConsumed,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		{
			name:             "emailotp ErrLocked",
			err:              emailotp.ErrLocked,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		{
			name:             "emailotp ErrResetRequired",
			err:              emailotp.ErrResetRequired,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		{
			name:             "emailotp ErrTooManyOutstanding",
			err:              emailotp.ErrTooManyOutstanding,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		// TOTP sentinels — both wrap ErrFactorAbort → HTTP 400 -----------
		{
			name:             "totp ErrLocked",
			err:              totp.ErrLocked,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		{
			name:             "totp ErrResetRequired",
			err:              totp.ErrResetRequired,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		// Recovery-code sentinels — both wrap ErrFactorAbort → HTTP 400 --
		{
			name:             "recovery ErrLocked",
			err:              recovery.ErrLocked,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		{
			name:             "recovery ErrResetRequired",
			err:              recovery.ErrResetRequired,
			wantStatus:       http.StatusBadRequest,
			wrapsFactorAbort: true,
		},
		// Control: ErrFactorRetry is handled by the orchestrator's
		// soft-retry branch and produces HTTP 200 (re-prompt).
		{
			name:             "ErrFactorRetry is re-prompted gracefully",
			err:              authn.ErrFactorRetry,
			wantStatus:       http.StatusOK,
			wrapsFactorAbort: false,
		},
		// Control: an unknown error not wrapping any known sentinel must
		// still fall through to the default → HTTP 500.
		{
			name:             "unknown error stays HTTP 500",
			err:              errors.New("some unknown factor error not in writeAuthnError switch"),
			wantStatus:       http.StatusInternalServerError,
			wrapsFactorAbort: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Assert the sentinel's wrapping property first, before
			// even touching HTTP — this catches a future edit that
			// accidentally changes the sentinel definition.
			if got := errors.Is(tc.err, authn.ErrFactorAbort); got != tc.wrapsFactorAbort {
				t.Fatalf("errors.Is(%q, ErrFactorAbort) = %v, want %v",
					tc.err, got, tc.wrapsFactorAbort)
			}

			h := newHarness(t, func(d *authorizeendpoint.Deps) {
				d.Authn = buildSingleSentinelOrchestrator(t, tc.err)
			})

			// Step 1: GET /authorize → 302 redirect to /interaction/{uid}.
			start := startInteractionFlow(t, h)

			// Step 2: GET /interaction/{uid} → the orchestrator runs the
			// first tick (no submission): Begin is called → sentinel prompt
			// returned → 200 with prompt envelope.
			getResp := doInteractionGet(t, h, start)
			defer func() { _ = getResp.Body.Close() }()
			stateRef, csrfCookie := readPromptStateRef(t, getResp)

			// Step 3: POST /interaction/{uid} with a submission.
			// The orchestrator calls Continue → singleSentinelAuthenticator
			// returns tc.err. The error flows through dispatchTick →
			// writeAuthnError, which must now dispatch on ErrFactorAbort
			// before the default branch.
			sub := interaction.FormSubmission{
				StateRef: stateRef,
				Values:   map[string]string{"code": "123456"},
			}
			rr := postSubmission(t, h, start, csrfCookie, sub)

			if rr.Code != tc.wantStatus {
				t.Errorf("sentinel %q: got HTTP %d, want %d body=%s",
					tc.err.Error(), rr.Code, tc.wantStatus, rr.Body.String())
			}
		})
	}
}

// TestWriteAuthnError_DefaultBranch_Is500 confirms that writeAuthnError's
// default case returns HTTP 500 for any unrecognised error. The shortest
// route to the default branch is a Begin that fails immediately (no CSRF
// dance needed).
func TestWriteAuthnError_DefaultBranch_Is500(t *testing.T) {
	t.Parallel()

	arbitraryErr := errors.New("some unknown factor error not in writeAuthnError switch")

	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xBC}, 32))
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{
			&alwaysErrAuthenticator{err: arbitraryErr},
		},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = orch
	})
	start := startInteractionFlow(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+start.uid, nil)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("default branch: got HTTP %d want 500 body=%s", rr.Code, rr.Body.String())
	}
}

// alwaysErrAuthenticator returns its stored error on Begin. This drives
// writeAuthnError's default branch via the GET /interaction path.
type alwaysErrAuthenticator struct {
	err error
}

func (a *alwaysErrAuthenticator) Type() op.FactorType { return "testkit.always-err" }
func (a *alwaysErrAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (a *alwaysErrAuthenticator) AMR() string         { return "" }
func (a *alwaysErrAuthenticator) Prompts() []string   { return []string{"auth.testkit.always-err"} }
func (a *alwaysErrAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, a.err
}

func (a *alwaysErrAuthenticator) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, a.err
}

var _ op.Authenticator = (*alwaysErrAuthenticator)(nil)
