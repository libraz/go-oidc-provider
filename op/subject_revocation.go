package op

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/grants/teardown"
)

// RevokeSubject revokes every grant the subject holds, for an embedder
// that disables or deprovisions a user. Each grant returned by
// [store.GrantStore.ListBySubject] has its access tokens and refresh
// tokens retired through the same teardown Grant Management revoke,
// /end_session and /revoke use, and its grant record is then deleted.
// A record that is already gone counts as deleted.
//
// The call is idempotent: a subject that holds no grants returns nil.
// An empty subject is a configuration_error [*Error], as is a store
// without a grant substore. Store failures are wrapped in a server_error
// [*Error]; every grant is attempted and their failures are joined, so
// one unreachable grant does not leave the others live, and the call
// can be retried.
//
// Tokens issued through the device_code and CIBA grants are NOT
// reached: those grants keep no grant record, so ListBySubject cannot
// return them. They stop only at the token endpoint's subject check,
// which refuses a redemption once the subject is gone from the user
// store. An embedder that merely disables a user, keeping the record,
// must therefore also delete it from the user store, or accept that
// device_code and CIBA refresh chains live until they expire.
//
// Browser sessions are not touched: the session store has no subject
// index. A session left behind cannot mint tokens once its grants are
// gone, and after the user record is removed the next /authorize
// re-authenticates.
func (p *Provider) RevokeSubject(ctx context.Context, subject string) error {
	if subject == "" {
		return &Error{
			Code:        codeConfiguration,
			Description: "RevokeSubject: subject must not be empty",
		}
	}
	grants := p.cfg.store.Grants()
	if isNilLike(grants) {
		return &Error{
			Code:        codeConfiguration,
			Description: "RevokeSubject: the store has no GrantStore",
		}
	}
	list, err := grants.ListBySubject(ctx, subject)
	if err != nil {
		return &Error{
			Code:        codeServerError,
			Description: "RevokeSubject: store rejected ListBySubject",
			Cause:       err,
		}
	}
	revoker := teardown.Revoker{
		RefreshTokens:      p.cfg.store.RefreshTokens(),
		OpaqueAccessTokens: p.cfg.store.OpaqueAccessTokens(),
		AccessTokens:       p.cfg.store.AccessTokens(),
		GrantRevocations:   p.cfg.store.GrantRevocations(),
		Strategy:           p.cfg.atRevocation,
		Now:                p.cfg.clock.Now().UTC(),
		TombstoneRetention: teardown.TombstoneRetention(p.cfg.accessTokenTTL),
		Reason:             "subject_revoked",
	}
	var errs []error
	for _, g := range list {
		if g == nil || g.ID == "" {
			continue
		}
		if err := revoker.RevokeGrant(ctx, grants, g.ID); err != nil {
			errs = append(errs, fmt.Errorf("grant %s: %w", g.ID, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return &Error{
			Code:        codeServerError,
			Description: "RevokeSubject: store rejected the grant teardown",
			Cause:       err,
		}
	}
	return nil
}
