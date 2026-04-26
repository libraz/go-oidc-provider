package authn

import (
	"context"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// FactorType is the typed identifier for an [Authenticator] method. The
// string values double as identifiers in audit logs, [op/interaction]
// JSON, and the RFC 8176 amr derivation, so they MUST stay stable: the
// constants are the wire form and not just symbolic names. New built-in
// values ship with the library; embedders extend the namespace through
// dotted user identifiers (see [FactorType.IsUserDefined]).
//
// See docs/plans/002-product-design.md §E.2 for the full schema.
type FactorType string

// Built-in [FactorType] values. The string content is the canonical
// identifier; renaming any of these breaks audit log continuity and
// orchestrator routing tables and is therefore a v1.0 freeze surface.
//
// User extensions: any FactorType whose string value contains a "." is
// treated as user-defined (e.g., "myorg.sms_otp"). Reserved bare names
// are exhausted by the constants below; pick a prefix.
const (
	// FactorPassword is a knowledge factor (RFC 8176 amr "pwd").
	FactorPassword FactorType = "password"

	// FactorTOTP is RFC 6238 time-based one-time password (amr "otp").
	FactorTOTP FactorType = "totp"

	// FactorPasskey is a WebAuthn assertion. RFC 8176 amr value
	// depends on the user-verification bit: "hwk" with UV, "swk"
	// without (see [Factor.AMRValue]).
	FactorPasskey FactorType = "passkey"

	// FactorRecoveryCode is a single-use pre-issued numeric code
	// stored at enrolment (amr "otp").
	FactorRecoveryCode FactorType = "recovery_code"

	// FactorEmailOTP is a code delivered through email. The factor
	// emits two prompts (send / verify) and is amr "otp".
	FactorEmailOTP FactorType = "email_otp"
)

// IsBuiltin reports whether t is one of the [FactorType] constants
// declared by the library. Built-in identifiers are reserved: a user
// extension MUST NOT match any of them, and the orchestrator rejects
// duplicates at construction time.
func (t FactorType) IsBuiltin() bool {
	switch t {
	case FactorPassword, FactorTOTP, FactorPasskey, FactorRecoveryCode, FactorEmailOTP:
		return true
	default:
		return false
	}
}

// IsUserDefined reports whether t is a non-empty user extension. The
// rule is intentionally simple — a dotted prefix segregates user
// extensions from the bare built-in identifiers — so that Authenticator
// authors do not need to consult a separate registry to verify their
// chosen name is safe.
func (t FactorType) IsUserDefined() bool {
	if t == "" || t.IsBuiltin() {
		return false
	}
	return strings.Contains(string(t), ".")
}

// String returns the underlying identifier. Provided for symmetry with
// the other typed-string identifiers in this package.
func (t FactorType) String() string { return string(t) }

// BeginInput carries the per-attempt context an [Authenticator] needs
// to start a ceremony. Subject is empty when the user has not yet been
// identified (the first factor in the chain); subsequent factors
// receive the subject the previous factor's [interaction.Result] returned.
//
// AuthTime is the orchestrator's reference clock for this attempt
// (typically the wall-clock time the interaction was created). Authn
// implementations MUST NOT call [time.Now] directly; reading AuthTime
// keeps the chain run consistent with the [Clock] the [Provider] was
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
	// layer has not populated [State.RequestedScopes] (legacy
	// chains, non-authorize entry points).
	RequestedScopes []string
}

// ContinueInput carries the per-submission context an [Authenticator]
// needs to advance a ceremony. The orchestrator populates Subject from
// the chain state (the previous factor's [interaction.Result.Subject], or "" for a
// first-factor identification step that binds the subject); stateless
// adapters use Subject to look up the user's persisted credentials
// (TOTP record, WebAuthn credentials, recovery batch) without keeping
// per-interaction state of their own.
//
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
	// round-trips it through [State.FactorScratch] without inspection.
	// It is empty when the active factor never emitted a Scratch
	// payload; stateless adapters can ignore the field.
	Scratch []byte

	// RequestedScopes mirrors [BeginInput.RequestedScopes] for the
	// matching submission. The built-in consent interaction reads it
	// to validate that every approved scope was actually in the
	// request set; authenticator factors usually ignore the field.
	RequestedScopes []string
}

// Authenticator is the protocol-side state machine for a single
// authentication factor. Implementations are stateless across calls;
// per-attempt state is carried by [interaction.Prompt.StateRef].
//
// Multi-screen factors (e.g., email OTP: enter address -> enter code)
// are expressed by returning a [interaction.Step] that contains a
// [interaction.Prompt] from [Authenticator.Begin] and further Prompts
// from [Authenticator.Continue] until [interaction.Step.Result] is
// populated and the factor is complete.
//
// Implementation responsibilities (docs/plans/002-product-design.md
// §E.2.2):
//
//   - User-existence leak defence is the implementation's
//     responsibility: response shape and timing MUST be identical for
//     registered vs unknown identifiers.
//   - [Authenticator.AMR] MUST return one of the RFC 8176 §2 registered
//     values ("pwd", "otp", "hwk", "swk", "face", "fpt", "iris", "geo",
//     "kba", ...) or an empty string. Foreign values are dropped by
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

// Interaction is a non-authentication screen unit (T&C acceptance,
// KYC gate, device-trust prompt, ...). Unlike [Authenticator], an
// Interaction does not bind a subject — the subject is already known.
// Interactions do not contribute to amr / acr; they only inject
// [interaction.Prompt] sequences at the chosen [InteractionTrigger]
// point.
//
// Built-in: the consent screen (§A.5) is registered automatically.
// User extensions ship with a unique [Interaction.Name] prefixed by
// the org identifier (e.g., "myorg.tos.accept"). See §E.9.
//
// Implementations MUST be safe for concurrent use by multiple
// goroutines.
type Interaction interface {
	// Name returns the unique identifier for this interaction. User
	// extensions MUST use a dotted prefix the org owns; built-ins
	// reserve the bare names ("consent", ...).
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

// InteractionTrigger values. See §E.9 for the orchestrator's
// per-trigger ordering rules.
const (
	// TriggerBeforeAuthn fires before any factor's Begin.
	// Suitable for region gates that do not need an identified user.
	TriggerBeforeAuthn InteractionTrigger = iota

	// TriggerAfterAuthn fires after the last factor's Continue
	// completes and the subject is bound. Suitable for T&C / KYC.
	TriggerAfterAuthn

	// TriggerBeforeToken fires after consent and before the token
	// endpoint can mint tokens. Suitable for device trust prompts.
	TriggerBeforeToken

	// TriggerAlways fires at every chain stage. Reserved for cross-
	// cutting interactions; orchestrator may de-duplicate.
	TriggerAlways
)
