package authn

import (
	"errors"
	"fmt"
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

	// Client is the read-only projection of the requesting client.
	// The HTTP layer populates it once when initialising the chain;
	// the orchestrator forwards it through every
	// [BeginInput.Client]. Empty for chains created before this
	// field was added (no schema migration required because Go's
	// json.Unmarshal tolerates missing fields).
	Client interaction.ClientView `json:"client,omitempty"`

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

	// CaptchaFailures counts the tokens the [CaptchaVerifier]
	// rejected during this attempt. It is deliberately separate from
	// [State.LastFailures]: captcha is out-of-band from the
	// brute-force feed, so a rejected token must not push the chain
	// further into the gate it is trying to clear. The orchestrator
	// aborts the chain once the count reaches its internal ceiling so
	// a verifier that rejects everything (misconfigured site key,
	// upstream outage) cannot trap the user in an endless challenge
	// loop. A cleared challenge resets it to zero.
	CaptchaFailures int `json:"captcha_failures,omitempty"`

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

	// ActiveInputs is the [interaction.Prompt.Inputs] list of the
	// prompt the orchestrator most recently emitted. The next
	// submission is validated against this copy — never against a
	// list the client sends — so a caller cannot declare away the
	// constraints its own prompt advertised. It is replaced on every
	// emitted prompt and stays empty for an informational prompt that
	// declares no inputs.
	ActiveInputs []interaction.FieldSpec `json:"active_inputs,omitempty"`

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
	// it at terminal-tick time to plan a
	// [sessions.EstablishSwitch] rather than a
	// [sessions.EstablishIssue], so the cookie rebinds within the
	// existing chooser group rather than starting a new one. Empty
	// for any chain that did not run the chooser.
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

	// ChooserAddAccount reports that this interaction was started from
	// the chooser prompt's AddAccountURL. The HTTP layer sets it only
	// after resolving an active session whose chooser group matches the
	// internal add-account marker in the authorization request. Terminal
	// session establishment reads the flag to plan a
	// [sessions.EstablishAddAccount] rather than a
	// [sessions.EstablishIssue] for a different-subject fresh login.
	ChooserAddAccount bool `json:"chooser_add_account,omitempty"`

	// ChooserAddAccountGroupID is the chooser group that an
	// AddAccountURL-derived fresh login should join after authentication
	// succeeds. It is separate from ChooserGroupID because that field
	// also tells the built-in chooser interaction to render; add-account
	// flows must run the authenticator chain instead.
	ChooserAddAccountGroupID string `json:"chooser_add_account_group_id,omitempty"`

	// ApprovedScopes is the scope subset the user accepted at the
	// consent screen, recorded from the most recent
	// [interaction.Result.Scope] the orchestrator observed. The
	// terminal [Tick] result echoes the value so the HTTP layer can
	// mint the authorization code with the approved scope rather
	// than the full requested set.
	ApprovedScopes []string `json:"approved_scopes,omitempty"`

	// ScopeApprovalRecorded reports that a consent-shaped Interaction
	// answered during this attempt, so [ApprovedScopes] is the user's
	// decision rather than "no ceremony ran". The two cannot be told
	// apart from ApprovedScopes alone: an approval of nothing and an
	// absent ceremony both leave it empty, and the HTTP layer's
	// fallback for an absent ceremony is the full requested scope set.
	//
	// It is also what makes the ceremony authoritative over the scope
	// names it presented: a grant amendment driven by an answered
	// consent screen removes the presented-but-declined scopes rather
	// than only adding the approved ones.
	ScopeApprovalRecorded bool `json:"scope_approval_recorded,omitempty"`

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

	// AcceptLanguage is the verbatim Accept-Language header of the
	// request that started the chain. The HTTP layer populates it when
	// initialising the chain; the orchestrator forwards it to
	// [LoginFlowContext.AcceptLanguage] so a rule predicate reading the
	// public [op.ClientHints] sees the same value the ACR resolver
	// assembles from the terminal request. Empty when the request did
	// not carry the header.
	AcceptLanguage string `json:"accept_language,omitempty"`

	// NewDeviceCached is the device-familiarity verdict the one-shot
	// [Config.LoginFlow.Risk] consult reported through
	// [RiskOutcome.NewDevice]. False when no assessor is configured or
	// the assessor did not set it.
	//
	// The library owns no device-trust state of its own — no cookie, no
	// fingerprint store — so the signal can only come from the
	// embedder's assessor, and it is cached for the lifetime of the
	// attempt for the same reason the risk score is: a predicate must
	// not see it change between passes.
	NewDeviceCached bool `json:"new_device_cached,omitempty"`

	// RiskRequiredFactors is the OR-set of [FactorType] candidates the
	// one-shot [Config.LoginFlow.Risk] consult demanded through
	// [RiskOutcome.RequiredFactors]. Empty when the assessor returned
	// [RiskAllow], named no candidate, or no assessor is configured.
	//
	// The set is a *pending obligation*, not a filter: the chain may
	// not reach [PhaseAfterAuthn] until one of the listed factor types
	// appears in [State.Factors]. Recording it on State (rather than
	// acting on it at the consult site) is what lets the obligation
	// survive the prompt/submission round trips between the consult at
	// chain start and the grant decision at the end.
	RiskRequiredFactors []FactorType `json:"risk_required_factors,omitempty"`

	// ActiveStepKind is the [LoginFlowStep.Kind] of the active
	// LoginFlow step, or "" when no LoginFlow step is mid-ceremony.
	// The orchestrator uses it to route a submission back through the
	// per-step authenticator and to append to [CompletedStepKinds]
	// once the step's Result lands.
	ActiveStepKind string `json:"active_step_kind,omitempty"`

	// ReauthRequired reports that this authorization request may not
	// be served from the authentication the entry session already
	// carries: the relying party asked for prompt=login, the session
	// is older than max_age (max_age=0 included), or its recorded ACR
	// does not satisfy the requested authentication context. The HTTP
	// layer sets the flag when it starts the chain; the orchestrator
	// treats it as "the inherited [State.Subject] identifies the user
	// but does not stand in for a credential".
	//
	// Two dispatch decisions read it, and both would otherwise be
	// short-circuited by a subject the chain never bound itself:
	//
	//   - The LoginFlow seam runs Primary whenever the flag is set and
	//     Primary has not completed during this attempt, instead of
	//     inferring "already authenticated" from a non-empty Subject.
	//   - The built-in chooser's skip of [PhaseAuthn] does not apply,
	//     so picking an account re-enters the factor chain rather than
	//     inheriting the picked session's assurance verbatim.
	//
	// The flag is deliberately not derived inside the orchestrator:
	// max_age / acr_values / prompt live on the authorization request,
	// which the orchestrator never sees.
	ReauthRequired bool `json:"reauth_required,omitempty"`

	// ACRValues is the OIDC Core 1.0 §3.1.2.1 acr_values request
	// parameter forwarded from the authorize request, in arrival order.
	// The HTTP layer populates it when initialising the chain so a
	// LoginFlow rule predicate (e.g., [op.RuleACR]) can implement
	// step-up against the requested ACR list. Empty when the request
	// did not carry the parameter.
	ACRValues []string `json:"acr_values,omitempty"`
}

// RemoteIPString renders [State.RemoteIP] for the surfaces that carry
// the address as a string: the public [op.ClientHints.RemoteIP] a rule
// predicate reads, and the audit event's IP field.
//
// It exists because [netip.Addr.String] renders the zero value as the
// literal "invalid IP" — a plausible-looking but meaningless address
// that a predicate comparing against a real one cannot tell from a
// resolution failure, and that lands verbatim in an audit trail. Both
// surfaces document the unresolvable case as the empty string, so the
// conversion is guarded in one place rather than at each call site.
func (s State) RemoteIPString() string {
	if !s.RemoteIP.IsValid() {
		return ""
	}
	return s.RemoteIP.String()
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

	// CaptchaToken is an out-of-band override for the token the
	// captcha [interaction.Prompt] asks for. The ordinary route is the
	// [CaptchaTokenField] entry of [Input.Submission]; the field exists
	// for callers that drive [Orchestrator.Tick] directly and have
	// already extracted the token themselves. The submission value
	// wins when both are present.
	//
	// The override does not exempt the submission from the outstanding
	// prompt's [interaction.FieldSpec] constraints: the built-in
	// captcha prompt declares [CaptchaTokenField] as required, so a
	// submission that omits it is rejected before the verifier runs
	// regardless of what this field carries.
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

	// ErrReauthNotPerformed is returned by the terminal tick when
	// [State.ReauthRequired] was set but the chain reached its end
	// without a single factor having run. The request asked for a
	// fresh authentication (prompt=login, max_age, unsatisfied
	// acr_values) and the terminal Result would otherwise carry the
	// interaction's creation time as auth_time with an empty amr —
	// an authentication nobody performed. This is the structural
	// backstop behind the per-surface dispatch rules: a future edit
	// that lets an inherited subject short-circuit the chain fails
	// closed here instead of minting a code.
	ErrReauthNotPerformed = errors.New("authn: fresh authentication required but no factor ran")

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
	// authenticator that reports [AAL3] completes a Continue without the
	// user-verification bit set on its
	// [interaction.Result.UserVerified]. NIST SP 800-63B AAL3 requires
	// user verification: a passkey assertion that did not perform UV
	// cannot satisfy AAL3. The orchestrator surfaces this as a
	// chain-fatal error so the HTTP layer rejects the attempt rather
	// than minting a session at a higher AAL than the factor actually
	// achieved.
	ErrAAL3RequiresUV = errors.New("authn: AAL3 factor requires user verification")

	// ErrFactorAbort marks a terminal, user-input-driven factor failure
	// that the HTTP layer renders as a 4xx (not a 500). Unlike
	// [ErrFactorRetry] — a soft failure the orchestrator re-prompts — an
	// abort means the factor cannot continue in this interaction: an
	// expired or already-consumed one-time code, an active brute-force
	// lockout, or a required factor reset. Per-factor adapters wrap their
	// terminal sentinels with it so internal/authorizeendpoint can
	// dispatch on the authn-level class without importing each factor's
	// sentinels.
	ErrFactorAbort = errors.New("authn: factor aborted")

	// ErrSubmissionRejected is returned when a
	// [interaction.FormSubmission] violates the
	// [interaction.FieldSpec] constraints the outstanding prompt
	// declared: a required field missing or empty, a value outside the
	// declared MinLen / MaxLen bounds, a value the declared Pattern
	// does not match, or more entries than the prompt asked for. The
	// orchestrator rejects before any [Authenticator] / [Interaction]
	// method runs, so a factor never has to defend against input its
	// own prompt already ruled out.
	//
	// It wraps [ErrFactorAbort] so the HTTP layer renders a 4xx: the
	// submission cannot have come from the prompt as rendered, which is
	// terminal for this attempt, but the user can start a fresh one.
	ErrSubmissionRejected = fmt.Errorf("authn: submission rejected: %w", ErrFactorAbort)

	// ErrCaptchaExhausted is returned when the [CaptchaVerifier] has
	// rejected the maximum number of tokens the orchestrator accepts
	// for one attempt. The chain terminates instead of re-emitting the
	// challenge forever: a verifier that never succeeds would otherwise
	// leave the user with no reachable factor. It wraps
	// [ErrFactorAbort] so the HTTP layer renders a 4xx rather than a
	// 5xx — the condition is terminal for this attempt but the user can
	// start a fresh one.
	ErrCaptchaExhausted = fmt.Errorf("authn: captcha challenge exhausted: %w", ErrFactorAbort)

	// ErrFactorLocked is the [ErrFactorAbort] refinement a factor wraps
	// when the brute-force gate — its own per-record LockedUntil stamp or
	// the shared cross-factor counter — is what terminated the attempt.
	// It exists so the orchestrator can tell a lockout apart from every
	// other terminal abort without importing each factor's sentinels,
	// which is what lets [AttemptLocked] reach the
	// [LoginAttemptObserver] feed. Wrapping it keeps the HTTP rendering
	// unchanged: dispatch on [ErrFactorAbort] still matches.
	ErrFactorLocked = fmt.Errorf("authn: factor locked: %w", ErrFactorAbort)
)
