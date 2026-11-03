package op

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/internal/ssf"
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
// The device_code and CIBA grants record a grant at redemption, and a
// token exchange issues under the grant of its subject_token, so their
// credentials are retired here too; a poll redeeming while the call runs
// is refused and its credentials retired. A device code or CIBA request
// approved but not yet redeemed records no grant and is not reached: its
// redemption is refused once the UserStore no longer knows the subject.
// Credentials issued without a grant
// record are NOT reached: those a [CustomGrantHandler] issues, whose
// subject the handler rather than a grant record vouches for, and the
// access tokens of the jwt-bearer grant ([WithJWTBearerGrant]), ID-JAG
// redemptions included. They stop only when they expire or are revoked
// individually; for jwt-bearer, the next redemption is refused once the
// subject resolver or the UserStore no longer knows the subject.
//
// Browser sessions, lockout counters and factor records are not
// touched. To erase a deleted user's data including its sessions, call
// [Provider.ForgetSubject], which runs RevokeSubject first.
//
// Under [WithSharedSignals] a CAEP session-revoked SET is queued for
// every receiver the subject holds a grant with, before the grants are
// torn down, since the grants are what name the receivers. A failure to
// queue it is audited as ssf.enqueue_failed and does not stop the
// revocation.
func (p *Provider) RevokeSubject(ctx context.Context, subject string) error {
	if subject == "" {
		return newConfigurationError("RevokeSubject: subject must not be empty", nil)
	}
	grants := p.cfg.store.Grants()
	if nilcheck.IsNil(grants) {
		return newConfigurationError("RevokeSubject: the store has no GrantStore", nil)
	}
	list, err := grants.ListBySubject(ctx, subject)
	if err != nil {
		return &Error{
			Code:        codeServerError,
			Description: "RevokeSubject: store rejected ListBySubject",
			Cause:       err,
		}
	}
	if p.cfg.ssfTransmitter != nil {
		// Audited by the transmitter; the revocation proceeds regardless.
		_, _ = p.cfg.ssfTransmitter.Publish(ctx, ssf.EventSessionRevoked, subject, ssf.Fields{})
	}
	revoker := revocation.Revoker{
		RefreshTokens:      p.cfg.store.RefreshTokens(),
		OpaqueAccessTokens: p.cfg.store.OpaqueAccessTokens(),
		AccessTokens:       p.cfg.store.AccessTokens(),
		GrantRevocations:   p.cfg.store.GrantRevocations(),
		Strategy:           p.cfg.atRevocation,
		Now:                p.cfg.clock.Now().UTC(),
		TombstoneRetention: revocation.TombstoneRetention(p.cfg.accessTokenTTL),
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
