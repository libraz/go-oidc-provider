package tokenendpoint

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/grants/teardown"
	"github.com/libraz/go-oidc-provider/op/store"
)

// teardownReasonSubjectDeprovisioned labels the teardown of a grant
// whose subject the user store no longer knows.
const teardownReasonSubjectDeprovisioned = "subject_deprovisioned"

// errSubjectDeprovisioned reports that the user store answered
// [store.ErrNotFound] for the subject a redemption would mint for.
var errSubjectDeprovisioned = errors.New("tokenendpoint: subject no longer exists")

// lookupLiveSubject resolves the end-user subject a redemption is about
// to mint for. It returns [errSubjectDeprovisioned] when the user store
// no longer holds the subject and the store's own error on any other
// fault. A nil [Deps.UserStore] means the handler was built without a
// user directory, and the redemption proceeds with a nil user.
func lookupLiveSubject(ctx context.Context, deps Deps, subject string) (*store.User, error) {
	if deps.UserStore == nil {
		return nil, nil //nolint:nilnil // documented contract: no user directory wired
	}
	user, err := deps.UserStore.FindBySubject(ctx, subject)
	if err == nil && user == nil {
		// A nil record alongside a nil error violates the store contract;
		// a subject the backend cannot produce is treated as absent.
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, errSubjectDeprovisioned
	}
	return user, err
}

// writeSubjectLookupError answers a failed [lookupLiveSubject]: a
// deprovisioned subject is invalid_grant, any other fault is
// server_error so no token is minted on a directory the OP cannot read.
func writeSubjectLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSubjectDeprovisioned) {
		writeError(w, http.StatusBadRequest, errInvalidGrant, "grant subject no longer exists")
		return
	}
	writeError(w, http.StatusInternalServerError, errServerError, "")
}

// deprovisionedRedemption describes a redemption refused because its
// subject no longer exists.
type deprovisionedRedemption struct {
	ClientID  string
	Subject   string
	GrantType string
	// GrantID is the grant to tear down; empty when the grant type
	// allocates its grant only at redemption and nothing was issued yet.
	GrantID string
}

// retireDeprovisionedGrant tears the refused redemption's grant down
// through the shared [teardown.Revoker] and records the refusal. The
// teardown is best-effort: the client is owed invalid_grant either way,
// and a rung that did not run raises the same warn-level event every
// other teardown on this endpoint does.
func retireDeprovisionedGrant(ctx context.Context, deps Deps, in deprovisionedRedemption) {
	if in.GrantID != "" {
		out := grantTeardown(deps, teardownReasonSubjectDeprovisioned).Run(ctx, teardown.WholeGrant(in.GrantID))
		reportTeardown(ctx, deps, out, auditTokenRevokeFailed, teardownReasonSubjectDeprovisioned, in.GrantID)
	}
	extras := map[string]any{
		"surface":    teardownReasonSubjectDeprovisioned,
		"grant_type": in.GrantType,
	}
	if in.GrantID != "" {
		extras["grant_id"] = in.GrantID
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditTokenRevoked,
		Level:    audit.LevelWarn,
		Message:  "redemption refused: grant subject no longer exists",
		ActorID:  in.Subject,
		ClientID: in.ClientID,
		Extras:   extras,
	})
}
