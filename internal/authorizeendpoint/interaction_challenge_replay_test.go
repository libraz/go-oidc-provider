package authorizeendpoint_test

// Regression coverage for the challenge-replay window at the
// /interaction seam.
//
// [authn.Orchestrator.Tick] returns the updated chain state even when it
// reports an error, precisely so the HTTP layer can save the parts of the
// state that did change before the failure. The hard-failure branch
// clears the active factor's scratch — the slot a WebAuthn assertion
// ceremony keeps its single-use challenge in — and retires the StateRef
// that addressed it. Dropping that write on the floor left the same
// challenge accepting responses for the rest of the StateRef's TTL,
// with no signature counter to catch the replay on the authenticators
// (platform passkeys) that report none.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

const (
	// challengePromptType is the prompt [challengeAuthenticator] emits.
	challengePromptType = "auth.testkit.challenge"

	// challengeResponseField is the field the assertion response would
	// arrive under.
	challengeResponseField = "response"

	// challengeScratch stands in for the encoded ceremony session a
	// real passkey factor round-trips through [interaction.Step.Scratch].
	challengeScratch = "ceremony-session-with-challenge"
)

var (
	// errChallengeMissing mirrors passkey.ErrSessionMissing: Continue
	// was dispatched without the ceremony state its Begin created.
	errChallengeMissing = errors.New("testkit: challenge scratch is missing")

	// errAssertionRejected is a hard (non-retryable) verification
	// failure, the shape a bad WebAuthn signature takes.
	errAssertionRejected = errors.New("testkit: assertion rejected")
)

// challengeAuthenticator models a factor whose Begin mints a one-shot
// challenge into the orchestrator's scratch slot and whose Continue
// always rejects the response. It counts how many Continue calls were
// handed a live challenge, which is the quantity the replay test pins:
// one failed assertion must consume the challenge exactly once.
type challengeAuthenticator struct {
	mu               sync.Mutex
	begins           int
	continuesWithCh  int
	continuesWithout int
}

func (a *challengeAuthenticator) Type() op.FactorType { return "testkit.challenge" }
func (a *challengeAuthenticator) AAL() op.AAL         { return op.AAL2 }
func (a *challengeAuthenticator) AMR() string         { return "" }
func (a *challengeAuthenticator) Prompts() []string   { return []string{challengePromptType} }

func (a *challengeAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	a.mu.Lock()
	a.begins++
	a.mu.Unlock()
	return interaction.Step{
		Prompt: &interaction.Prompt{
			Type: challengePromptType,
			Inputs: []interaction.FieldSpec{{
				Name:     challengeResponseField,
				Kind:     interaction.FieldHidden,
				Required: true,
				MaxLen:   4096,
			}},
		},
		Scratch: []byte(challengeScratch),
	}, nil
}

func (a *challengeAuthenticator) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(in.Scratch) == 0 {
		a.continuesWithout++
		return interaction.Step{}, errChallengeMissing
	}
	a.continuesWithCh++
	return interaction.Step{}, errAssertionRejected
}

func (a *challengeAuthenticator) counts() (begins, withChallenge, withoutChallenge int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.begins, a.continuesWithCh, a.continuesWithout
}

var _ op.Authenticator = (*challengeAuthenticator)(nil)

// TestInteractionPost_FailedAssertionRetiresTheChallenge asserts a
// rejected assertion is not replayable: the second submission carrying
// the same StateRef must be refused, and the factor must never see the
// challenge a second time.
func TestInteractionPost_FailedAssertionRetiresTheChallenge(t *testing.T) {
	t.Parallel()

	factor := &challengeAuthenticator{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = buildChallengeOrchestrator(t, factor)
	})
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	defer func() { _ = getResp.Body.Close() }()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)

	submission := interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{challengeResponseField: "assertion-blob"},
	}

	first := postSubmission(t, h, start, csrfCookie, submission)
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("first assertion status=%d want 500 body=%s", first.Code, first.Body.String())
	}

	// The failure branch's state mutation must have reached the store.
	persisted := persistedAuthnState(t, h, start.uid)
	if len(persisted.FactorScratch) != 0 {
		t.Errorf("persisted FactorScratch=%q, want cleared after a rejected assertion",
			persisted.FactorScratch)
	}

	second := postSubmission(t, h, start, csrfCookie, submission)
	if second.Code == http.StatusInternalServerError {
		t.Fatalf("replayed assertion reached the factor: status=%d body=%s",
			second.Code, second.Body.String())
	}
	if second.Code != http.StatusForbidden {
		t.Fatalf("replayed assertion status=%d want 403 body=%s", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "stateref rejected") {
		t.Errorf("replay body=%s, want the StateRef rejection", second.Body.String())
	}

	begins, withChallenge, withoutChallenge := factor.counts()
	if withChallenge != 1 {
		t.Errorf("factor saw a live challenge %d times, want exactly 1", withChallenge)
	}
	if withoutChallenge != 0 {
		t.Errorf("factor was dispatched %d times without a challenge, want 0", withoutChallenge)
	}
	if begins != 1 {
		t.Errorf("Begin ran %d times, want 1", begins)
	}
}

// TestInteractionGet_ReissuesAFreshChallengeAfterFailure is the
// liveness half of the same property: retiring the challenge must not
// strand the user. Re-entering the interaction runs Begin again and
// hands out a fresh challenge under a fresh StateRef.
func TestInteractionGet_ReissuesAFreshChallengeAfterFailure(t *testing.T) {
	t.Parallel()

	factor := &challengeAuthenticator{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = buildChallengeOrchestrator(t, factor)
	})
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	stateRef, csrfCookie := readPromptStateRef(t, getResp)
	_ = getResp.Body.Close()

	first := postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{challengeResponseField: "assertion-blob"},
	})
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("first assertion status=%d want 500 body=%s", first.Code, first.Body.String())
	}

	retryResp := doInteractionGet(t, h, start)
	retryStateRef, _ := readPromptStateRef(t, retryResp)
	_ = retryResp.Body.Close()

	if retryStateRef == stateRef {
		t.Error("re-entry reused the retired StateRef")
	}
	if begins, _, _ := factor.counts(); begins != 2 {
		t.Errorf("Begin ran %d times, want 2 (a fresh ceremony after the failure)", begins)
	}
}

// buildChallengeOrchestrator wires a single-factor chain around the
// supplied challenge-bearing authenticator.
func buildChallengeOrchestrator(t *testing.T, factor op.Authenticator) *authn.Orchestrator {
	t.Helper()
	signer, err := authn.NewStateRefSigner(challengeSignerKey())
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{factor},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return orch
}

func challengeSignerKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x70 + i)
	}
	return key
}
