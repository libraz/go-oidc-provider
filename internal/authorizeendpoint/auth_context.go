package authorizeendpoint

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
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

// grantAuthContext is an authentication context: auth_time, acr and amr.
// It appears in two roles. As read off the backing record — a session,
// or the factors a ceremony just ran — acr is the canonical URI of the
// level reached ([authn.AAL.ACRURI]) and amr the per-factor aggregate;
// that is what a session records. As stamped on a grant it is
// [reportAuthContext]'s verdict for one request, which the token endpoint
// copies into the id_token.
type grantAuthContext struct {
	AuthTime time.Time
	ACR      string
	AMR      []string
}

// sessionAuthContext projects the active session record into the
// authentication it records. Every /authorize path that emits or reuses
// a grant without running a fresh ceremony starts from this value, so
// the id_token describes the session the request was actually served
// from rather than an older, possibly stronger authentication recorded
// on the grant. The decision matrix (max_age, acr_values) validates the
// request against exactly these session fields; [reportAuthContext]
// then turns them into what the grant reports to the requesting client.
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

// reportAuthContext resolves what a grant reports to the client req came
// from: the configured ACR policy's verdict for this request over the
// level recorded, which is recovered from recorded.ACR. The recorded acr
// is never passed through, so an acr one client's request drew from a
// lax policy cannot reach another client through a session they share.
//
// st supplies the steps completed during this attempt and the remote
// hints; a response served from an established session passes a state
// with no completed steps, because none of them produced its level. A
// voluntary request the policy cannot satisfy is reported with no acr;
// an essential one fails with [errACRUnmet].
func reportAuthContext(
	ctx context.Context,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	subject string,
	st authn.State,
	recorded grantAuthContext,
) (grantAuthContext, error) {
	reported := grantAuthContext{
		AuthTime: recorded.AuthTime,
		ACR:      recorded.ACR,
		AMR:      slices.Clone(recorded.AMR),
	}
	if deps.ACRResolver == nil {
		return reported, nil
	}
	out := deps.ACRResolver(ctx, ACRResolveInput{
		RequestedACRValues: requestedACRValues(req),
		CompletedKinds:     append([]string(nil), st.CompletedStepKinds...),
		InternalAAL:        authn.AALFromACRURI(recorded.ACR),
		Subject:            subject,
		ClientID:           req.ClientID,
		RequestedScopes:    append([]string(nil), req.Scope...),
		RemoteIP:           acrRemoteIP(r, deps, st),
		UserAgent:          acrUserAgent(r, st),
		AcceptLanguage:     r.Header.Get("Accept-Language"),
	})
	switch {
	case out.OK:
		reported.ACR = out.ACR
		if out.AMR != nil {
			reported.AMR = append([]string(nil), out.AMR...)
		}
	case essentialACRRequested(req):
		// Flattening an essential request to "" would hand the relying
		// party a code for an authentication it declared insufficient.
		return grantAuthContext{}, errACRUnmet
	default:
		reported.ACR = ""
	}
	return reported, nil
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
