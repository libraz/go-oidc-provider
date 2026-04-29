// Package chooser implements the built-in account chooser
// [authn.Interaction]. It is registered automatically by op.New for
// embedders that ship multi-account flows; user extensions MUST
// NOT register an interaction whose Name() collides with
// [authn.BuiltinChooserName].
//
// The interaction's job is narrow:
//
//   - Begin enumerates the live accounts in the active chooser group
//     via [sessions.Manager.Accounts] and emits a
//     [interaction.ChooserPromptData] envelope so the SPA / HTML
//     driver can render the picker.
//   - Continue validates that the submitted SessionID belongs to the
//     active chooser group (by calling [sessions.Manager.Switch] for
//     its membership check; the resulting cookie value is discarded
//     here because the HTTP layer regenerates it via the orchestrator
//     state field [authn.State.ChooserSelectedSessionID]).
//   - Continue returns [interaction.Result] with Subject set to the
//     picked session's subject. The orchestrator special-cases the
//     built-in chooser name to propagate Subject onto State and to
//     skip the factor chain.
//
// The cookie rebind itself happens at the HTTP layer in
// internal/authorizeendpoint/interaction.go::terminateInteraction,
// which reads State.ChooserSelectedSessionID and calls
// [sessions.Manager.Switch] before redirecting back to the RP.
package chooser

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Sentinel errors. The orchestrator surfaces every non-nil error
// verbatim, so the wording shows up in audit logs without wrapping.
var (
	// ErrChooserGroupRequired is returned when the orchestrator
	// dispatches to the chooser without an active chooser group ID
	// in BeginInput / ContinueInput. The /authorize hint matrix is
	// mis-wired in that case: the chooser is registered only for
	// requests with an active session, which always carries a
	// chooser group ID.
	ErrChooserGroupRequired = errors.New("chooser: ChooserGroupID is required")

	// ErrSessionIDMissing is returned when the SPA submission omits
	// the session_id field. The orchestrator's [interaction.FieldSpec]
	// validation should already have caught this; the interaction
	// re-checks at the trust boundary.
	ErrSessionIDMissing = errors.New("chooser: session_id field is missing")

	// ErrSessionNotInGroup is returned when the SPA submits a
	// session_id that does not belong to the active chooser group.
	// The orchestrator surfaces this as a user-decline /
	// invalid-request; the HTTP layer can decide whether to retry
	// the chooser or fail the authorize request.
	ErrSessionNotInGroup = errors.New("chooser: session does not belong to chooser group")
)

// Interaction is the built-in account chooser. Construct with [New];
// safe for concurrent use after construction.
type Interaction struct {
	sessions *sessions.Manager
}

// New builds a [*Interaction] bound to the supplied sessions manager.
// The manager is the source of truth for chooser-group membership and
// the executor of the cookie rebind.
func New(mgr *sessions.Manager) *Interaction {
	return &Interaction{sessions: mgr}
}

// Name implements [authn.Interaction]. Always returns
// [authn.BuiltinChooserName].
func (*Interaction) Name() string { return authn.BuiltinChooserName }

// Trigger implements [authn.Interaction]. The chooser runs at
// [authn.TriggerBeforeAuthn] because picking an account binds the
// subject without consulting the factor chain.
func (*Interaction) Trigger() authn.InteractionTrigger { return authn.TriggerBeforeAuthn }

// Begin implements [authn.Interaction]. It lists the live accounts
// in the active chooser group, projects them onto
// [interaction.ChooserPromptData], and returns the prompt step.
//
// The chooser is registered for every Provider but participates only
// when the /authorize hint matrix routed prompt=select_account. For
// any other request the HTTP layer leaves [BeginInput.ChooserGroupID]
// empty; in that case Begin self-skips by returning an empty Result
// step, which the orchestrator records and advances past.
func (i *Interaction) Begin(ctx context.Context, in authn.BeginInput) (interaction.Step, error) {
	if in.ChooserGroupID == "" {
		return interaction.Step{Result: &interaction.Result{}}, nil
	}
	accounts, err := i.sessions.Accounts(ctx, in.ChooserGroupID)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("chooser: list accounts: %w", err)
	}
	rows := make([]interaction.ChooserAccount, 0, len(accounts))
	for _, a := range accounts {
		rows = append(rows, interaction.ChooserAccount{
			SessionID: a.SessionID,
			Subject:   a.Subject,
			AuthTime:  a.AuthTime,
		})
	}
	return interaction.Step{
		Prompt: &interaction.Prompt{
			Type: authn.ChooserPromptType,
			Data: interaction.ChooserPromptData{Accounts: rows},
			Inputs: []interaction.FieldSpec{{
				Name:     authn.ChooserSessionIDField,
				Kind:     interaction.FieldText,
				Label:    "chooser.session_id",
				Required: true,
				MaxLen:   sessionIDMaxLen,
			}},
		},
	}, nil
}

// Continue implements [authn.Interaction]. It validates that the
// submitted SessionID belongs to the active chooser group, looks up
// the picked session's subject, and returns the chooser result. The
// orchestrator's chooser-name special-case propagates Subject onto
// State; the HTTP layer reads [authn.State.ChooserSelectedSessionID]
// (which the orchestrator captures from the submission) to drive
// the cookie rebind via [sessions.Manager.Switch].
func (i *Interaction) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if in.ChooserGroupID == "" {
		return interaction.Step{}, ErrChooserGroupRequired
	}
	sid, ok := in.Submission.Values[authn.ChooserSessionIDField]
	if !ok || sid == "" {
		return interaction.Step{}, ErrSessionIDMissing
	}
	// Switch is the membership check: it returns ErrCookieInvalid
	// when the SessionID belongs to a different chooser group, and
	// ErrCurrentSessionExpired when the SessionID has been
	// garbage-collected. Either way the user did not pick a valid
	// row, so we surface the orchestrator-friendly error.
	if _, err := i.sessions.Switch(ctx, in.ChooserGroupID, sid); err != nil {
		if errors.Is(err, sessions.ErrCookieInvalid) || errors.Is(err, sessions.ErrCurrentSessionExpired) {
			return interaction.Step{}, fmt.Errorf("%w: %w", ErrSessionNotInGroup, err)
		}
		return interaction.Step{}, fmt.Errorf("chooser: switch: %w", err)
	}
	// Fetch the picked session to get its Subject. We could plumb
	// the value through Switch's return type, but Switch's contract
	// is "rebind cookie", not "look up subject"; reading the
	// SessionStore directly here keeps Switch focused.
	rows, err := i.sessions.Accounts(ctx, in.ChooserGroupID)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("chooser: list after switch: %w", err)
	}
	for _, a := range rows {
		if a.SessionID == sid {
			return interaction.Step{Result: &interaction.Result{
				Subject:  a.Subject,
				AuthTime: a.AuthTime,
			}}, nil
		}
	}
	// The session vanished between the Switch call and the list
	// call. Treat as expired.
	return interaction.Step{}, fmt.Errorf("%w: %w", ErrSessionNotInGroup, store.ErrNotFound)
}

// sessionIDMaxLen caps the submission's session_id field byte length.
// 64 hex chars (256 bits) is well above the 16-byte
// [sessions.IDLength] random value rendered as base64url.
const sessionIDMaxLen = 64

// Compile-time confirmation that *Interaction satisfies the public
// interface.
var _ authn.Interaction = (*Interaction)(nil)
