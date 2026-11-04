package authn

import (
	"context"
	"net/netip"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// BeginInput carries the per-attempt context an [Authenticator] needs
// to start a ceremony. Subject is empty when the user has not yet been
// identified (the first factor in the chain); subsequent factors
// receive the subject the previous factor's [interaction.Result] returned.
// AuthTime is the orchestrator's reference clock for this attempt
// (typically the wall-clock time the interaction was created). Authn
// implementations MUST NOT call time.Now() directly; reading AuthTime
// keeps the chain run consistent with the Clock the Provider was
// configured with.
type BeginInput struct {
	// Subject is the canonical OP-internal subject identifier the
	// previous factor produced, or "" for the first factor in a
	// chain.
	Subject string

	// ClientID is the OAuth client_id of the relying party that
	// started the authorization request.
	ClientID string

	// AuthTime is the reference time for this attempt (typically the
	// interaction creation time).
	AuthTime time.Time

	// RequestedScopes is the scope list the relying party asked for
	// in the authorize request. Authenticator factors usually ignore
	// it; the built-in consent interaction reads it to render the
	// per-scope approval prompt. The slice is empty when the HTTP
	// layer has not populated State.RequestedScopes (legacy
	// chains, non-authorize entry points).
	RequestedScopes []string

	// Client is the read-only projection of the requesting client.
	// The HTTP layer populates it from the store.Client lookup; the
	// orchestrator forwards it through every BeginInput so the
	// built-in consent interaction can populate
	// [interaction.ConsentTemplateData.Client] without re-querying
	// the client store. Empty for chains that did not resolve a
	// client (legacy code paths; production /authorize always
	// populates this field).
	Client interaction.ClientView

	// ChooserGroupID is the active session cookie's chooser-group
	// identifier. The built-in account chooser interaction reads it
	// to enumerate live accounts; every other factor / interaction
	// ignores the field. Empty when the /authorize entry point did
	// not resolve an active session (no cookie or no chooser
	// group), in which case the chooser interaction is not
	// registered for this attempt.
	ChooserGroupID string
}

// ContinueInput carries the per-submission context an [Authenticator]
// needs to advance a ceremony. The orchestrator populates Subject from
// the chain state (the previous factor's [interaction.Result.Subject], or "" for a
// first-factor identification step that binds the subject); stateless
// adapters use Subject to look up the user's persisted credentials
// (TOTP record, WebAuthn credentials, recovery batch) without keeping
// per-interaction state of their own.
// AuthTime is the same reference clock [BeginInput.AuthTime] carries
// for this attempt; threading it through Continue lets the adapter
// stamp [interaction.Result.AuthTime] consistently regardless of how many
// submissions a multi-screen factor takes.
type ContinueInput struct {
	// Subject is the canonical OP-internal subject identifier the
	// orchestrator has bound to the chain. For the first factor in a
	// chain (the identifying factor) this MAY be empty until that
	// factor's Continue populates it through [interaction.Result.Subject].
	Subject string

	// ClientID is the OAuth client_id of the relying party that
	// started the authorization request.
	ClientID string

	// AuthTime is the reference time for this attempt (typically the
	// interaction creation time). The value is identical to the one
	// passed to [BeginInput.AuthTime] for the same attempt.
	AuthTime time.Time

	// Submission is the SPA's reply to the previous [interaction.Prompt].
	// The orchestrator has already validated [interaction.FormSubmission.StateRef]
	// against the active factor; the adapter is responsible for any
	// per-input validation beyond the [interaction.FieldSpec] constraints.
	Submission interaction.FormSubmission

	// Scratch is the byte slice the matching [interaction.Step.Scratch]
	// stashed on the previous Begin or Continue call. The orchestrator
	// round-trips it through State.FactorScratch without inspection.
	// It is empty when the active factor never emitted a Scratch
	// payload; stateless adapters can ignore the field.
	Scratch []byte

	// RequestedScopes mirrors [BeginInput.RequestedScopes] for the
	// matching submission. The built-in consent interaction reads it
	// to validate that every approved scope was actually in the
	// request set; authenticator factors usually ignore the field.
	RequestedScopes []string

	// ChooserGroupID mirrors [BeginInput.ChooserGroupID] for the
	// matching submission. Read by the built-in account chooser
	// so op.Interaction.Continue can validate the submitted
	// session_id belongs to the active chooser group before
	// rebinding the session cookie. Other interactions ignore
	// the field.
	ChooserGroupID string

	// RemoteIP is the client IP of the request that started the
	// chain, normalised through the trusted-proxy chain. It is the
	// same value [CaptchaInput.RemoteIP] and [RiskInput.RemoteIP]
	// carry, exposed here because an adapter that forwards a
	// submission to an upstream service — the op.StepCaptcha
	// adapter is the built-in case — otherwise has no way to reach
	// it. Invalid when the HTTP layer could not resolve a trusted
	// address; check [netip.Addr.IsValid] before rendering it.
	RemoteIP netip.Addr
}

// Authenticator is the protocol-side state machine for a single
// authentication factor. Implementations are stateless across calls;
// per-attempt state is carried by [interaction.Prompt.StateRef].
// Multi-screen factors (e.g., email OTP: enter address -> enter code)
// are expressed by returning a [interaction.Step] that contains a
// [interaction.Prompt] from [Authenticator.Begin] and further Prompts
// from [Authenticator.Continue] until [interaction.Step.Result] is
// populated and the factor is complete.
// Implementation responsibilities:
//   - User-existence leak defence is the implementation's
//     responsibility: response shape and timing MUST be identical for
//     registered vs unknown identifiers.
//   - [Authenticator.AMR] MUST return one of the RFC 8176 §2 registered
//     values ("pwd", "otp", "hwk", "swk", "face", "fpt", "iris", "geo",
//     "kba"...) or an empty string. Foreign values are dropped by
//     the orchestrator (warning audit log) and never reach amr_history.
//   - [Authenticator.Prompts] MUST declare every [interaction.Prompt.Type]
//     the authenticator may emit so a Driver can validate its routing
//     table at startup.
//
// Implementations MUST be safe for concurrent use by multiple
// goroutines; the orchestrator dispatches across goroutines without
// per-instance locking.
type Authenticator interface {
	// Type returns the [FactorType] this authenticator implements.
	// Two registered authenticators MUST NOT share a Type.
	Type() FactorType

	// AAL returns the assurance level a successful Continue raises
	// the session to. The orchestrator takes the maximum across all
	// completed factors when deriving the session AAL.
	AAL() AAL

	// AMR returns the RFC 8176 §2 registered value contributed to
	// the amr claim, or "" to suppress this factor's contribution.
	AMR() string

	// Prompts returns every [interaction.Prompt.Type] this authenticator
	// may emit. The slice is treated as read-only by the orchestrator.
	Prompts() []string

	// Begin starts the ceremony. The returned [interaction.Step] either
	// carries a [interaction.Prompt] (multi-step factor) or a populated
	// [interaction.Result] (single-step factor that completes
	// immediately, rare).
	Begin(ctx context.Context, in BeginInput) (interaction.Step, error)

	// Continue advances the ceremony with the SPA's submission. A
	// nil-Prompt nil-Result [interaction.Step] is invalid and rejected
	// by the orchestrator.
	Continue(ctx context.Context, in ContinueInput) (interaction.Step, error)
}

// EnrollmentProber is an optional interface an [Authenticator] MAY
// implement to report whether a subject can complete it at all. A
// one-of step offers only the factors whose authenticator reports the
// subject enrolled; an authenticator without it counts as enrolled. An
// error fails the step closed rather than counting either way.
type EnrollmentProber interface {
	Enrolled(ctx context.Context, subject string) (bool, error)
}

// Interaction is a non-authentication screen unit (T&C acceptance,
// KYC gate, device-trust prompt...). Unlike [Authenticator], an
// Interaction does not bind a subject — the subject is already known.
// Interactions do not contribute to amr / acr; they only inject
// [interaction.Prompt] sequences at the chosen [InteractionTrigger]
// point.
// Built-in: the consent screen is registered automatically.
// User extensions ship with a unique [Interaction.Name] prefixed by
// the org identifier (e.g., "myorg.tos.accept").
// Implementations MUST be safe for concurrent use by multiple
// goroutines.
type Interaction interface {
	// Name returns the unique identifier for this interaction. User
	// extensions MUST use a dotted prefix the org owns; built-ins
	// reserve the bare names ("consent"...).
	Name() string

	// Trigger reports when the orchestrator inserts the interaction
	// into the chain. See [InteractionTrigger].
	Trigger() InteractionTrigger

	// Begin starts the interaction. The returned [interaction.Step]
	// follows the same shape rules as [Authenticator.Begin] except
	// that any returned [interaction.Result] MUST leave
	// [interaction.Result.Subject] empty (subject is already bound
	// elsewhere).
	Begin(ctx context.Context, in BeginInput) (interaction.Step, error)

	// Continue advances the interaction with the SPA's submission.
	// [ContinueInput.Subject] is always non-empty for an Interaction
	// because the subject has already been bound by the time the
	// interaction phase runs.
	Continue(ctx context.Context, in ContinueInput) (interaction.Step, error)
}

// InteractionTrigger declares when the orchestrator inserts an
// [Interaction] into the chain. The values are intentionally a small
// closed set — the orchestrator handles cross-trigger ordering — so
// adding a new trigger is a v1.x extension rather than a per-call
// option.
type InteractionTrigger int

// InteractionTrigger values. The orchestrator inserts each interaction
// into the chain at the matching trigger point; cross-trigger ordering
// is library-defined.
const (
	// TriggerBeforeAuthn fires before any factor's Begin.
	// Suitable for region gates that do not need an identified user.
	TriggerBeforeAuthn InteractionTrigger = iota

	// TriggerAfterAuthn fires after the last factor's Continue
	// completes and the subject is bound. Suitable for T&C / KYC.
	TriggerAfterAuthn

	// TriggerBeforeToken fires after consent and before the token
	// endpoint can mint tokens. Suitable for device trust prompts.
	// It runs on every authorization code /authorize issues, including
	// one served from an existing session and a cached grant, so
	// registering it turns such silent reuse into an interaction and
	// prompt=none into interaction_required. Device authorization and
	// CIBA approvals are embedder-driven and do not run the chain.
	TriggerBeforeToken

	// TriggerAlways fires at every chain stage. Reserved for cross-
	// cutting interactions; orchestrator may de-duplicate.
	TriggerAlways
)
