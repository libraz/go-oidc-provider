package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// authorizeDecision captures the four outcomes the dispatcher chooses
// between. Centralising the decision keeps the cyclomatic complexity of
// [dispatchAuthorize] under the project lint cap.
type authorizeDecision int

const (
	decisionInteract authorizeDecision = iota
	decisionMint
	decisionLoginRequired
	decisionConsentRequired
	decisionInteractionRequired
)

// applyExitOverrides adjusts the decision-matrix outcome for the
// deployment's configuration: the first-party skip may turn a consent
// prompt into a mint, a LoginFlow rule that demands a factor for this
// request turns a mint served from the session into an interaction,
// and so does a registered [authn.TriggerBeforeToken] interaction.
func applyExitOverrides(
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
) authorizeHint {
	if firstPartyShouldSkipConsent(r, hint, req, client, active, deps) {
		hint = applyFirstPartySkip(deps, req, client, active)
	}
	if hint.decision == decisionMint && deps.Authn != nil && active != nil {
		st := initialAuthnState(r, deps, req, client, active, hint, "", deps.now().UTC())
		if deps.Authn.LoginFlowRequiresStep(r.Context(), st) {
			hint = routeThroughLoginFlow(hint, containsString(req.Prompt, "none"))
		}
	}
	if hint.decision == decisionMint && deps.Authn != nil && deps.Authn.HasInteractions(authn.TriggerBeforeToken) {
		hint = routeThroughBeforeToken(hint, containsString(req.Prompt, "none"))
	}
	return hint
}

// routeThroughLoginFlow replaces a silent mint with an interaction when
// the LoginFlow demands a factor step for the request. The chain starts
// with the session's subject, so Primary is not repeated, and the
// cached grant or first-party auto-grant still stands in for consent.
// prompt=none forbids the step and yields interaction_required, as an
// unsatisfied acr_values does.
func routeThroughLoginFlow(mint authorizeHint, promptNone bool) authorizeHint {
	if promptNone {
		return authorizeHint{decision: decisionInteractionRequired}
	}
	return authorizeHint{
		decision:  decisionInteract,
		grant:     mint.grant,
		autoGrant: mint.autoGrant,
	}
}

// authorizeHint bundles the outcome of the decision matrix together with
// the data the chosen outcome consumes (the prompt name for an
// interaction, the existing grant for a silent mint).
type authorizeHint struct {
	decision  authorizeDecision
	prompt    string
	grant     *store.Grant
	autoGrant *grantUpsert

	// reauth mirrors hintState.forceLogin || hintState.acrUnsatisfied:
	// the request may not be served from the authentication the entry
	// session carries. [startInteraction] forwards it onto
	// [authn.State.ReauthRequired] so the orchestrator does not let the
	// inherited subject stand in for a credential.
	reauth bool

	// startPhase is the phase the interaction's chain starts in. The
	// zero value is [authn.PhaseBeforeAuthn]; [routeThroughBeforeToken]
	// sets [authn.PhaseBeforeToken] for a mint it turned into an
	// interaction.
	startPhase authn.Phase
}

// computeAuthorizeHint runs the authorize decision matrix that picks
// between "reuse the session", "re-authenticate" and "prompt for
// consent". The outcome depends on three
// orthogonal inputs: whether a session exists, whether the request forces
// a fresh login (prompt=login or max_age violation), and whether the
// existing grant covers the requested scope (or no grant exists at all).
func computeAuthorizeHint(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	now time.Time,
) (authorizeHint, error) {
	state, err := buildHintState(ctx, deps, req, client, active, now)
	if err != nil {
		return authorizeHint{}, err
	}
	if state.promptNone {
		return decideHintPromptNone(state), nil
	}
	return decideHintInteractive(state), nil
}

// hintState collects the pre-computed flags that drive
// [computeAuthorizeHint]. It is a value type because the per-request flag
// set is small enough to copy and the readability win is worth more than
// the marginal allocation.
type hintState struct {
	hasSession     bool
	forceLogin     bool
	acrUnsatisfied bool
	needConsent    bool
	promptNone     bool
	selectAcct     bool
	existing       *store.Grant
}

// buildHintState computes the orthogonal flag set used by the decision
// matrix. The function is pure aside from the grant lookup; tests that
// need to exercise the matrix in isolation can construct hintState
// directly.
func buildHintState(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	now time.Time,
) (hintState, error) {
	out := hintState{
		hasSession: active != nil,
		forceLogin: containsString(req.Prompt, interaction.PromptLogin),
		promptNone: containsString(req.Prompt, "none"),
		selectAcct: containsString(req.Prompt, interaction.PromptSelectAccount),
	}
	if out.hasSession {
		// The door, the chooser pick and the terminal gate share
		// [sessionMayServe] so their readings of the request cannot drift.
		serveErr := sessionMayServe(ctx, deps, req, sessionAuthContext(active).entry(currentSubject(active)), now)
		out.forceLogin = out.forceLogin || errors.Is(serveErr, errStaleAuthentication)
		out.acrUnsatisfied = errors.Is(serveErr, errACRUnmet)
		g, err := findGrantForConsentDecision(
			ctx,
			deps.Grants,
			active.Session.Subject,
			client.ID,
		)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return hintState{}, err
		}
		if err == nil {
			out.existing = g
		}
	}
	out.needConsent = !consentAlreadyCovered(req, out.existing)
	return out, nil
}

func findGrantForConsentDecision(
	ctx context.Context,
	grants store.GrantStore,
	subject,
	clientID string,
) (*store.Grant, error) {
	grant, err := grants.FindBySubjectClient(ctx, subject, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("authorizeendpoint: find grant for consent decision: %w", err)
	}
	if grant == nil {
		return nil, errors.New("authorizeendpoint: grant lookup returned nil record")
	}
	if grant.ID == "" || grant.Subject != subject || grant.ClientID != clientID {
		return nil, errors.New("authorizeendpoint: grant lookup returned mismatched record")
	}
	return grant, nil
}

// decideHintPromptNone resolves the matrix when prompt=none is present.
// The OIDC spec requires the OP to surface one of the *_required errors
// rather than start an interaction. The strict prompt validator
// (request.Validate / validatePrompt) already rejected prompt=none
// combined with any other prompt as invalid_request, so this branch
// only runs with prompt=none alone.
func decideHintPromptNone(s hintState) authorizeHint {
	switch {
	case !s.hasSession, s.forceLogin:
		return authorizeHint{decision: decisionLoginRequired}
	case s.acrUnsatisfied:
		// RFC 9470 step-up under prompt=none: the session exists but its
		// authentication context is too weak for the requested acr_values,
		// and prompt=none forbids an interaction. §9① resolves this to
		// interaction_required (distinct from the login_required that a
		// max_age expiry or absent session yields).
		return authorizeHint{decision: decisionInteractionRequired}
	case s.needConsent:
		return authorizeHint{decision: decisionConsentRequired}
	default:
		return authorizeHint{decision: decisionMint, grant: s.existing}
	}
}

// decideHintInteractive resolves the matrix when prompt!=none. The
// outcome is either a silent code mint or an interaction redirect.
// The existing grant is forwarded on the interact path so
// [startInteraction] can pre-mark the consent step as already covered
// when the cached grant subsumes the requested scope.
//
// prompt=select_account on a request with an active session is
// routed to the chooser interaction. The hint records the prompt
// as [interaction.PromptSelectAccount] so [startInteraction] knows
// to register the chooser; consent still runs after the chooser
// if the picked subject's grant does not cover the requested
// scope.
func decideHintInteractive(s hintState) authorizeHint {
	switch {
	case !s.hasSession, s.forceLogin, s.acrUnsatisfied:
		// acrUnsatisfied joins the login branch: an RFC 9470 step-up runs
		// the authn chain again to reach the requested acr_values (already
		// carried on the interaction state), and terminateInteraction
		// re-stamps the resolved acr / auth_time onto the session + grant.
		return authorizeHint{
			decision: decisionInteract,
			prompt:   interaction.PromptLogin,
			grant:    s.existing,
			reauth:   true,
		}
	case s.selectAcct:
		return authorizeHint{decision: decisionInteract, prompt: interaction.PromptSelectAccount, grant: s.existing}
	case s.needConsent:
		return authorizeHint{decision: decisionInteract, prompt: interaction.PromptConsent, grant: s.existing}
	default:
		return authorizeHint{decision: decisionMint, grant: s.existing}
	}
}

// routeThroughBeforeToken replaces a silent mint when a
// [authn.TriggerBeforeToken] interaction is registered: those
// interactions run after consent on every code the OP issues, so a mint
// that never drives the chain would skip them.
//
// prompt=none forbids the interaction and yields interaction_required.
// Otherwise the mint becomes an interaction that starts at
// [authn.PhaseBeforeToken]: the session stands in for authentication and
// the cached grant or first-party auto-grant for consent, exactly as
// they did for the silent mint.
func routeThroughBeforeToken(mint authorizeHint, promptNone bool) authorizeHint {
	if promptNone {
		return authorizeHint{decision: decisionInteractionRequired}
	}
	return authorizeHint{
		decision:   decisionInteract,
		grant:      mint.grant,
		autoGrant:  mint.autoGrant,
		startPhase: authn.PhaseBeforeToken,
	}
}
