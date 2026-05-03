package authn

import (
	"errors"
	"net/netip"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// This file is the orchestrator's pure data surface: the [Phase]
// enum, the [State] persistence carrier, the per-tick [Input], the
// public construction [Config], and the sentinel error set. Splitting
// these out of orchestrator.go keeps the state machine entry points
// (Tick / consumeSubmission) front and centre when reading the file.

// Phase enumerates the orchestrator's high-level chain stages. The
// values are stored only in [State] (not persisted) so they can move
// freely between releases; they exist to keep the [Orchestrator.Tick]
// dispatch table readable.
type Phase int

// Phase values. The chain runs strictly forward through these values:
// [Tick] never moves a [State] backwards.
const (
	// PhaseBeforeAuthn is the stage before any factor's
	// [Authenticator.Begin] runs. The orchestrator inserts every
	// pending [TriggerBeforeAuthn] / [TriggerAlways]
	// interaction here.
	PhaseBeforeAuthn Phase = iota

	// PhaseAuthn is the stage during which the orchestrator drives
	// authenticators. The active factor's index is held in
	// [State.ActiveFactorIdx].
	PhaseAuthn

	// PhaseAfterAuthn is the stage between the last factor and the
	// chain terminating. The orchestrator inserts every pending
	// [TriggerAfterAuthn] interaction here.
	PhaseAfterAuthn

	// PhaseDone is the terminal stage. [Tick] returns
	// [ErrChainComplete] when called with a [State] in this phase.
	PhaseDone
)

// State is the orchestrator's per-attempt state carrier. The struct is
// pure data: every field is the orchestrator's own representation of
// the in-flight chain. The HTTP layer persists [State] across requests
// using whatever encoding it picks; the orchestrator does no I/O of
// its own.
// Callers that need to copy a State (e.g., to journal it) MUST treat
// [State.Factors] and [State.InteractionsRun] as the values to deep-
// copy; mutating them after a [Tick] returns is undefined.
type State struct {
	// InteractionUID is the orchestrator-issued identifier for this
	// authorization attempt. The signer binds StateRef tokens to it
	// so a token cannot replay across two interactions.
	InteractionUID string

	// Subject is the OP-internal subject identifier the most recent
	// authenticator bound, or "" when no factor has identified the
	// user yet.
	Subject string

	// ClientID is the OAuth client_id of the relying party that
	// started the authorization request.
	ClientID string

	// RemoteIP is the client IP after trusted-proxy normalisation.
	// The orchestrator never invents a value here; it must have been
	// written by the HTTP layer before the first [Tick].
	RemoteIP netip.Addr

	// UserAgent is the request's User-Agent header truncated to a
	// sane bound by the HTTP layer.
	UserAgent string

	// AuthTime is the wall-clock time the interaction was created.
	// The orchestrator passes it to every [BeginInput.AuthTime]
	// so [time.Now()] never has to be called from authenticator code.
	AuthTime time.Time

	// Factors is the per-step record of every successful
	// [Authenticator.Continue]. The slice is consumed by
	// [Aggregate] when the chain reaches [PhaseDone].
	Factors []Factor

	// CaptchaPassed records whether the SPA cleared the captcha
	// challenge during this attempt. The orchestrator emits at most
	// one captcha [interaction.Prompt] per attempt; once the bit is set it
	// stays set.
	CaptchaPassed bool

	// ActiveFactorIdx is the index of the active
	// [Authenticator] in the chain configuration, or -1 when no
	// factor is currently mid-ceremony. The orchestrator updates it
	// when it picks a candidate at [PhaseAuthn].
	ActiveFactorIdx int

	// ActiveInteractionName is the [Interaction.Name] of the
	// active interaction, or "" when none is mid-ceremony. The
	// orchestrator uses it to route [interaction.FormSubmission] back to the
	// originating Interaction.
	ActiveInteractionName string

	// StepCounter is a monotonic counter the orchestrator embeds
	// into every issued StateRef. Incrementing on every emitted
	// [interaction.Prompt] prevents a stale token from being replayed after
	// the chain advances.
	StepCounter int

	// Phase tracks the orchestrator's current chain stage. See
	// [Phase].
	Phase Phase

	// InteractionsRun records which [Interaction.Name] values
	// have already completed during this attempt. The orchestrator
	// does not insert the same Interaction twice.
	InteractionsRun map[string]bool

	// LastFailures is the running count of [AttemptFailure]
	// outcomes during the active [PhaseAuthn] window. The
	// orchestrator emits a captcha challenge once it reaches
	// [captchaFailureThreshold].
	LastFailures int

	// FactorScratch is the opaque byte slice the active factor's
	// most recent [interaction.Step.Scratch] return populated. The
	// orchestrator persists it across the Begin → Continue boundary
	// and feeds it back to [Authenticator.Continue] through
	// [ContinueInput.Scratch]. It is cleared automatically when the
	// active factor terminates (Result or hard error).
	FactorScratch []byte `json:"factor_scratch,omitempty"`

	// RequestedScopes is the scope list the relying party asked for
	// in the authorize request. The HTTP layer populates it when
	// initialising the chain; the orchestrator forwards it through
	// every [BeginInput.RequestedScopes] / [ContinueInput.RequestedScopes]
	// so the consent interaction (and any user extension that needs
	// the same surface) can read it without re-querying the request.
	RequestedScopes []string `json:"requested_scopes,omitempty"`

	// ChooserGroupID is the active session cookie's chooser-group
	// identifier. The HTTP layer populates it from the session
	// cookie when starting an interaction whose hint matrix routed
	// to the chooser; the orchestrator forwards it through
	// [BeginInput.ChooserGroupID] / [ContinueInput.ChooserGroupID]
	// so the built-in chooser interaction can enumerate live
	// accounts without re-reading the cookie. Empty for chains
	// that do not include the chooser interaction.
	ChooserGroupID string `json:"chooser_group_id,omitempty"`

	// ChooserSelectedSessionID is the SessionID the user picked at
	// the built-in account chooser screen. Populated by the
	// orchestrator from the chooser submission's "session_id"
	// field on a successful chooser Continue; the HTTP layer reads
	// it at terminal-tick time to call [sessions.Manager.Switch]
	// instead of [sessions.Manager.Issue] so the cookie rebinds
	// within the existing chooser group rather than starting a new
	// one. Empty for any chain that did not run the chooser.
	ChooserSelectedSessionID string `json:"chooser_selected_session_id,omitempty"`

	// ChooserBoundSubject reports whether the built-in chooser
	// interaction's most recent Result actively bound a subject. Set
	// only when [recordInteractionResult] observes a chooser result
	// with a non-empty Subject; the chooser self-skip path (no
	// active group) records a marker entry in
	// [State.InteractionsRun] without flipping this flag. The
	// orchestrator's PhaseBeforeAuthn dispatch reads it to decide
	// whether to skip the factor chain — a flag that is true only
	// after the chooser screen actually picked an account.
	ChooserBoundSubject bool `json:"chooser_bound_subject,omitempty"`

	// ApprovedScopes is the scope subset the user accepted at the
	// consent screen, recorded from the most recent
	// [interaction.Result.Scope] the orchestrator observed. The
	// terminal [Tick] result echoes the value so the HTTP layer can
	// mint the authorization code with the approved scope rather
	// than the full requested set.
	ApprovedScopes []string `json:"approved_scopes,omitempty"`

	// CompletedStepKinds records which [LoginFlow] step kinds have
	// run during this attempt. Empty when [Config.LoginFlow] is not
	// configured. The slice is the dedup unit for [LoginFlowRule]
	// re-evaluation: a rule whose Then.Kind is already present is
	// skipped on subsequent passes so the same step cannot run twice
	// in a chain. The dedup invariant defends against timing-oracle
	// attacks where an attacker repeatedly triggers the same Step to
	// extract per-attempt timing.
	CompletedStepKinds []string `json:"completed_step_kinds,omitempty"`

	// RiskScoreCached is the orchestrator's one-shot evaluation of
	// [Config.LoginFlow.Risk] at chain start. [RiskScoreNone] means
	// "no signal available or no LoginFlow / no Risk configured".
	// The cached value is the typed [RiskScore] so a rule predicate
	// `score >= threshold` works uniformly across the
	// orchestrator-cached and embedder-supplied paths.
	// The orchestrator MUST NOT re-call [LoginFlow.Risk] once a
	// non-zero score is cached: external risk APIs are paid, and
	// the budget invariant is that a rule predicate sees the same
	// score for the lifetime of the attempt.
	RiskScoreCached RiskScore `json:"risk_score_cached,omitempty"`

	// ActiveStepKind is the [LoginFlowStep.Kind] of the active
	// LoginFlow step, or "" when no LoginFlow step is mid-ceremony.
	// The orchestrator uses it to route a submission back through the
	// per-step authenticator and to append to [CompletedStepKinds]
	// once the step's Result lands.
	ActiveStepKind string `json:"active_step_kind,omitempty"`

	// ACRValues is the OIDC Core 1.0 §3.1.2.1 acr_values request
	// parameter forwarded from the authorize request, in arrival order.
	// The HTTP layer populates it when initialising the chain so a
	// LoginFlow rule predicate (e.g., [op.RuleACR]) can implement
	// step-up against the requested ACR list. Empty when the request
	// did not carry the parameter.
	ACRValues []string `json:"acr_values,omitempty"`
}

// Input is the per-tick payload the HTTP layer hands to
// [Orchestrator.Tick]. The orchestrator does no clock reads of its
// own; [Input.Now()] is the single source of "current time" for a tick,
// so a deterministic [Clock] in tests yields a deterministic chain
// run.
type Input struct {
	// Submission carries the SPA's form post, or nil when the tick
	// is the first call of an attempt (no prompt outstanding).
	Submission *interaction.FormSubmission

	// CaptchaToken is the SPA's response to a captcha
	// [interaction.Prompt]. Populated only when the previous tick emitted a
	// captcha challenge; otherwise the orchestrator ignores it.
	CaptchaToken string

	// Now is the wall-clock time for this tick. The HTTP layer
	// reads it from the configured [Clock] and passes it through
	// so the orchestrator never calls [time.Now()] directly.
	Now time.Time
}

// Sentinel errors returned by [Orchestrator.Tick]. Callers compare
// against these via errors.Is; the orchestrator wraps them with
// %w-style context only when an upstream verifier emits a structured
// failure that the HTTP layer needs to surface.
var (
	// ErrChainComplete is returned by [Tick] when called with a
	// [State] already in [PhaseDone]. It signals a programming bug
	// in the caller: the HTTP layer is meant to stop driving the
	// orchestrator after the terminal step.
	ErrChainComplete = errors.New("authn: chain already complete")

	// ErrInvalidStateRef is returned when a [interaction.FormSubmission]
	// carries a StateRef that fails [StateRefSigner.Verify]. The
	// HTTP layer treats it as a hard error; the SPA is expected to
	// restart the attempt.
	ErrInvalidStateRef = errors.New("authn: invalid stateref")

	// ErrRiskDenied is returned when the configured
	// [RiskAssessor] returns [RiskDeny] at any stage. The
	// HTTP layer surfaces a fixed error response; the assessor's
	// reason flows to the audit log only.
	ErrRiskDenied = errors.New("authn: risk denied")

	// ErrNoEligibleAuthenticator is returned when, at
	// [PhaseAuthn], no registered [Authenticator] satisfies the
	// chain constraints (Subject already required by candidate set,
	// risk-required factor not registered...). The HTTP layer
	// surfaces a fixed error response.
	ErrNoEligibleAuthenticator = errors.New("authn: no eligible authenticator")

	// ErrInvalidStep is returned when an [Authenticator] or
	// [Interaction] returns a [interaction.Step] with neither Prompt nor
	// Result populated. The orchestrator rejects the bad return so
	// a misbehaving authenticator cannot stall the chain.
	ErrInvalidStep = errors.New("authn: invalid step")

	// ErrFactorRetry signals "the user-supplied credential was
	// rejected; the orchestrator MUST observe the failure and
	// re-emit the current factor's prompt rather than terminating
	// the chain." Authenticators that cannot resolve the failure to
	// a fresh Prompt themselves (the password adapter, for instance,
	// has no in-flight per-attempt state to amend) wrap their
	// soft-failure sentinel in [ErrFactorRetry] so the orchestrator
	// can route the response uniformly. Hard errors — store outage,
	// codec misconfiguration, lockout — MUST NOT wrap this sentinel;
	// they continue to flow to the HTTP layer as 500 / 4xx.
	ErrFactorRetry = errors.New("authn: factor retry")

	// ErrAAL3RequiresUV is returned by [Orchestrator.Tick] when an
	// authenticator that reports [AAL3] completes a Continue without
	// the user-verification bit set on its [interaction.Result.UserVerified]
	// (M-AUTHN-3). NIST SP 800-63B AAL3 requires user verification:
	// a passkey assertion that did not perform UV cannot satisfy AAL3.
	// The orchestrator surfaces this as a chain-fatal error so the
	// HTTP layer rejects the attempt rather than minting a session
	// at a higher AAL than the factor actually achieved.
	ErrAAL3RequiresUV = errors.New("authn: AAL3 factor requires user verification")
)
