package authorizeendpoint

import (
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// requestedACRValues is the single source of truth for "which
// authentication context did this request ask for". OIDC Core 1.0
// §5.5.1.1 lets a relying party name it two ways — the acr_values
// parameter, or an "acr" entry under the claims parameter's id_token
// member — and the two are alternative spellings of the same ask.
// Reading only acr_values would hand a claims-only request an acr the
// OP never agreed to: the step-up gate honours both spellings, so a
// policy that sees only one can approve a context the gate rejected.
//
// Ordering is acr_values first (the parameter form carries the RP's
// preference order) followed by the claims spec's "value" and "values"
// entries. Duplicates are dropped so a value named through both
// spellings is offered to the policy once. Non-string claims entries
// are skipped: acr is a string claim, and a numeric or object entry
// names no context the OP could satisfy.
func requestedACRValues(req *authorize.Request) []string {
	if req == nil {
		return nil
	}
	out := make([]string, 0, len(req.ACRValues))
	seen := make(map[string]struct{}, len(req.ACRValues))
	add := func(v string) {
		if v == "" {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range req.ACRValues {
		add(v)
	}
	if spec, ok := req.Claims.IDTokenSpec("acr"); ok {
		if v, isString := spec.Value.(string); isString {
			add(v)
		}
		for _, candidate := range spec.Values {
			if v, isString := candidate.(string); isString {
				add(v)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
