package authorizeendpoint

import (
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
)

// codeBinding carries the fields of an authorization code that differ per
// exit; everything else is read off the request.
type codeBinding struct {
	ID       string
	ClientID string
	Subject  string
	GrantID  string
	Scope    []string
	AuthTime time.Time
	ACR      string
	AMR      []string
}

// newAuthorizationCode builds the code both terminal exits persist: b
// supplies the exit-specific fields, req the request-bound ones.
func newAuthorizationCode(
	req *authorize.Request,
	b codeBinding,
	grant *store.Grant,
	now time.Time,
	ttl time.Duration,
) *store.AuthorizationCode {
	return &store.AuthorizationCode{
		ID:                  b.ID,
		ClientID:            b.ClientID,
		Subject:             b.Subject,
		GrantID:             b.GrantID,
		RedirectURI:         req.RedirectURI,
		Scope:               b.Scope,
		Resource:            req.Resource,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		DPoPJKT:             req.DPoPJKT,

		AuthTime:              b.AuthTime,
		ACR:                   b.ACR,
		AMR:                   b.AMR,
		AuthorizationDetails:  codeAuthorizationDetails(req, grant),
		Claims:                authorize.EncodeClaimsToGrant(req.Claims),
		AuthorizationRecorded: true,

		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
}

// authorizationCodeMatches reports whether code is the record
// [newAuthorizationCode] would have written for (req, b). The grant id is
// compared only when compareGrant is set, for callers that do not know it.
func authorizationCodeMatches(code *store.AuthorizationCode, req *authorize.Request, b codeBinding, compareGrant bool) bool {
	if code == nil {
		return false
	}
	return code.ID == b.ID &&
		code.ClientID == b.ClientID &&
		code.Subject == b.Subject &&
		(!compareGrant || code.GrantID == b.GrantID) &&
		code.RedirectURI == req.RedirectURI &&
		slices.Equal(code.Scope, b.Scope) &&
		code.Resource == req.Resource &&
		code.CodeChallenge == req.CodeChallenge &&
		code.CodeChallengeMethod == req.CodeChallengeMethod &&
		code.Nonce == req.Nonce &&
		code.State == req.State &&
		code.DPoPJKT == req.DPoPJKT
}

// transactionalDeps returns deps with the stores a code mint touches
// rebound to tx.
func transactionalDeps(deps resolved, tx store.Tx) resolved {
	deps.PARs = tx.PushedAuthRequests()
	deps.Codes = tx.AuthorizationCodes()
	deps.Grants = tx.Grants()
	return deps
}
