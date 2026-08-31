package authorizeendpoint

import (
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// requestedACRValues names the authentication contexts the request asked
// for, in the OP's preference order. It is a thin alias for
// [authorize.Request.RequestedACRValues]: the enumeration lives in the
// shared request package because every authentication-request surface
// has to agree about which values a request names — /authorize hands
// them to the ACR policy, and all three surfaces check them against
// `acr_values_supported`.
func requestedACRValues(req *authorize.Request) []string {
	return req.RequestedACRValues()
}

// essentialACRRequested reports whether the request marked the acr
// claim essential. Only the claims parameter can express essentiality
// (OIDC Core 1.0 §5.5.1.1); acr_values is a voluntary hint by
// definition, so a request that carries only acr_values is served with
// the acr claim omitted when the policy cannot satisfy it, whereas an
// essential request is refused outright.
func essentialACRRequested(req *authorize.Request) bool {
	if req == nil {
		return false
	}
	spec, ok := req.Claims.IDTokenSpec("acr")
	return ok && spec.Essential
}

// grantAuthContext is the authentication context a grant carries into
// token issuance: the auth_time, acr and amr the OP reports for the
// authentication that backs an authorization code. The token endpoint
// reads all three off the grant, so whatever is stamped here is what
// lands in the id_token.
type grantAuthContext struct {
	AuthTime time.Time
	ACR      string
	AMR      []string
}

// sessionAuthContext projects the active session record into the
// context a grant must carry. Every /authorize path that emits or
// reuses a grant without running a fresh ceremony stamps this value, so
// the id_token describes the session the request was actually served
// from rather than an older, possibly stronger authentication recorded
// on the grant. The decision matrix (max_age, acr_values) validates the
// request against exactly these session fields, so reporting anything
// else would contradict the check that just passed.
//
// The interactive path does not use this helper: a completed ceremony
// supplies its own freshly-resolved auth_time / acr / amr, which
// upsertGrant stamps at completion time.
func sessionAuthContext(active *sessions.Active) grantAuthContext {
	if active == nil || active.Session == nil {
		return grantAuthContext{}
	}
	return grantAuthContext{
		AuthTime: active.Session.AuthTime,
		ACR:      active.Session.ACR,
		AMR:      slices.Clone(active.Session.AMR),
	}
}

// stampGrantAuthContext copies ac onto g and reports whether any field
// actually changed. The caller uses the report to skip a store write on
// the common path where the grant already matches the session.
func stampGrantAuthContext(g *store.Grant, ac grantAuthContext) bool {
	if g == nil {
		return false
	}
	changed := !g.AuthTime.Equal(ac.AuthTime) ||
		g.ACR != ac.ACR ||
		!slices.Equal(g.AMR, ac.AMR)
	g.AuthTime = ac.AuthTime
	g.ACR = ac.ACR
	g.AMR = slices.Clone(ac.AMR)
	return changed
}
