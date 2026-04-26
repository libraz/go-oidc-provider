package consent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// Name is the [authn.Interaction.Name] the built-in consent screen
// registers under. The value is fixed; user extensions that want a
// different consent contract MUST pick a different dotted name (e.g.,
// "myorg.consent.scope") so [op.New] does not silently swap them.
const Name = "consent"

// PromptType is the [interaction.Prompt.Type] the interaction emits.
// The value is fixed to the design's "consent.scope" string; SPAs
// dispatch on it to pick the consent-screen template.
const PromptType = "consent.scope"

// ApprovedScopesField is the [interaction.FieldSpec.Name] the SPA
// submits with the user's approved scope subset. The value is a
// space-delimited string mirroring the OAuth scope convention.
const ApprovedScopesField = "approved_scopes"

// approvedScopesMaxLen caps the submitted approval string. The cap is
// generous (the longest realistic scope string is on the order of
// hundreds of bytes) but protects against pathological inputs.
const approvedScopesMaxLen = 8 * 1024

// Sentinel errors. Callers dispatch via [errors.Is]; the orchestrator
// surfaces every non-nil error verbatim, so the wording shows up in
// audit logs without re-wrapping.
var (
	// ErrSubjectRequired is returned when the orchestrator dispatches
	// to the consent interaction without a bound subject. The chain
	// is mis-wired in that case: consent runs at
	// [authn.TriggerAfterAuthn], by which time at least one factor
	// must have populated [authn.State.Subject].
	ErrSubjectRequired = errors.New("consent: subject is required")

	// ErrApprovedScopesMissing is returned when the SPA submission
	// omits [ApprovedScopesField]. The orchestrator's [interaction.FieldSpec]
	// validation should already have caught this; the interaction
	// re-checks at the trust boundary.
	ErrApprovedScopesMissing = errors.New("consent: approved_scopes field is missing")

	// ErrApprovedScopeNotRequested is returned when the SPA submits a
	// scope identifier that was not in the request. Surfacing this as
	// an error rather than silently dropping prevents a malicious SPA
	// from minting an authorization code with a scope the RP never
	// asked for.
	ErrApprovedScopeNotRequested = errors.New("consent: approved scope was not requested")

	// ErrRequiredScopeDeclined is returned when the SPA omits a scope
	// the catalogue marks Required. Required scopes (typically
	// "openid" and any client-mandated scopes) cannot be declined;
	// declining them aborts the chain.
	ErrRequiredScopeDeclined = errors.New("consent: required scope was declined")
)

// Interaction is the built-in consent screen. It is constructed by
// [New] from the scope catalogue and is safe for concurrent use
// after construction.
type Interaction struct {
	catalog map[string]interaction.ConsentScope
}

// New builds a [*Interaction] from the supplied catalogue. The slice
// is the union of every registered scope; each entry's metadata
// (description, required flag) is surfaced verbatim on the prompt.
// Scopes the relying party requests but the catalogue does not
// describe receive a default rendering with only the Name field
// populated, so an unconfigured custom scope still surfaces on the
// screen rather than being silently dropped.
func New(catalog []interaction.ConsentScope) *Interaction {
	idx := make(map[string]interaction.ConsentScope, len(catalog))
	for _, s := range catalog {
		idx[s.Name] = s
	}
	return &Interaction{catalog: idx}
}

// Name implements [authn.Interaction]. Always returns [Name].
func (*Interaction) Name() string { return Name }

// Trigger implements [authn.Interaction]. Consent runs after
// authentication so the subject is bound before the user is asked to
// approve scopes.
func (*Interaction) Trigger() authn.InteractionTrigger { return authn.TriggerAfterAuthn }

// Begin implements [authn.Interaction]. It projects the request's
// scope list through the catalogue and emits the consent prompt. An
// empty [authn.BeginInput.RequestedScopes] yields an empty Scopes
// slice; the SPA renders an "approve nothing" prompt that still binds
// to the orchestrator's StateRef so the user can confirm a scopeless
// authorize request.
func (i *Interaction) Begin(_ context.Context, in authn.BeginInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	scopes := make([]interaction.ConsentScope, 0, len(in.RequestedScopes))
	for _, name := range in.RequestedScopes {
		if entry, ok := i.catalog[name]; ok {
			scopes = append(scopes, entry)
			continue
		}
		scopes = append(scopes, interaction.ConsentScope{Name: name})
	}
	return interaction.Step{
		Prompt: &interaction.Prompt{
			Type: PromptType,
			Data: interaction.ConsentScopePromptData{Scopes: scopes},
			Inputs: []interaction.FieldSpec{{
				Name:     ApprovedScopesField,
				Kind:     interaction.FieldText,
				Label:    "consent.approved_scopes",
				Required: true,
				MaxLen:   approvedScopesMaxLen,
			}},
		},
	}, nil
}

// Continue implements [authn.Interaction]. It validates that every
// approved scope was in the request set, that every catalogue-required
// scope is present, and returns the approved subset on
// [interaction.Result.Scope]. The orchestrator records the slice on
// [authn.State.ApprovedScopes] so the terminal Result echoes it back
// to the HTTP layer.
func (i *Interaction) Continue(_ context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	raw, ok := in.Submission.Values[ApprovedScopesField]
	if !ok {
		return interaction.Step{}, ErrApprovedScopesMissing
	}
	approved, err := i.parseApproved(raw, in.RequestedScopes)
	if err != nil {
		return interaction.Step{}, err
	}
	if err := i.checkRequired(approved, in.RequestedScopes); err != nil {
		return interaction.Step{}, err
	}
	return interaction.Step{Result: &interaction.Result{Scope: approved}}, nil
}

// parseApproved splits the SPA-submitted string and validates every
// token belongs to the request set. The output preserves request order
// so the recorded grant scope is deterministic across runs.
func (i *Interaction) parseApproved(raw string, requested []string) ([]string, error) {
	requestedSet := make(map[string]struct{}, len(requested))
	for _, n := range requested {
		requestedSet[n] = struct{}{}
	}
	approvedSet := make(map[string]struct{})
	for _, name := range strings.Fields(raw) {
		if _, ok := requestedSet[name]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrApprovedScopeNotRequested, name)
		}
		approvedSet[name] = struct{}{}
	}
	out := make([]string, 0, len(approvedSet))
	for _, name := range requested {
		if _, ok := approvedSet[name]; ok {
			out = append(out, name)
		}
	}
	return slices.Clip(out), nil
}

// checkRequired ensures every catalogue-required scope present in the
// request set is also in the approved set. Required scopes that the
// catalogue does not describe (i.e., scope names the RP requested but
// the embedder never registered) are NOT enforced — the catalogue is
// the source of truth.
func (i *Interaction) checkRequired(approved, requested []string) error {
	approvedSet := make(map[string]struct{}, len(approved))
	for _, name := range approved {
		approvedSet[name] = struct{}{}
	}
	for _, name := range requested {
		entry, ok := i.catalog[name]
		if !ok || !entry.Required {
			continue
		}
		if _, ok := approvedSet[name]; !ok {
			return fmt.Errorf("%w: %q", ErrRequiredScopeDeclined, name)
		}
	}
	return nil
}

// Compile-time confirmation that *Interaction satisfies the public
// interface. The receiver is a pointer because the catalogue is a
// reference-typed map; a value-receiver method set would force a copy
// on every interface dispatch.
var _ authn.Interaction = (*Interaction)(nil)
