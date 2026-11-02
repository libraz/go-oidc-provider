package tokens

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Authorization is the state that belongs to one authorization rather than
// to the (subject, client) grant several authorizations share: the
// authentication it was served from, the authorization_details it granted
// and its OIDC Core 1.0 §5.5 claims request (in the [store.Grant.Claims]
// encoding). Codes, refresh chains and access tokens each carry their own
// copy; the grant only stands in for records written without one.
type Authorization struct {
	AuthTime             time.Time
	ACR                  string
	AMR                  []string
	AuthorizationDetails []map[string]any
	Claims               map[string]any
}

// ResolveAuthorization returns the per-authorization state a code, refresh
// token or access token was issued under.
//
// own is what the artifact carries and recorded reports whether it was
// written at issuance. g is the artifact's grant, or nil; it is consulted
// only when it is clientID's own grant, never the grant a token-exchange
// lineage inherited from another client.
//
//   - recorded: own is authoritative. The grant only narrows
//     authorization_details, so a Grant Management replace still withdraws
//     details from live artifacts while a later authorization never adds
//     any.
//   - not recorded (a row written before the fields existed, or a backend
//     that does not persist them): the readers' earlier rule applies. The
//     grant's authorization_details and claims request win when it has
//     them, and it fills whichever of auth_time, acr and amr the artifact
//     lacks.
func ResolveAuthorization(own Authorization, recorded bool, g *store.Grant, clientID string) Authorization {
	out := Authorization{
		AuthTime:             own.AuthTime,
		ACR:                  own.ACR,
		AMR:                  slices.Clone(own.AMR),
		AuthorizationDetails: own.AuthorizationDetails,
		Claims:               own.Claims,
	}
	if g == nil || g.ClientID != clientID {
		return out
	}
	if !recorded {
		fillFromGrant(&out, g)
		return out
	}
	out.AuthorizationDetails = narrowAuthorizationDetails(out.AuthorizationDetails, g.AuthorizationDetails)
	return out
}

func fillFromGrant(out *Authorization, g *store.Grant) {
	if out.AuthTime.IsZero() {
		out.AuthTime = g.AuthTime
		if out.AuthTime.IsZero() {
			out.AuthTime = g.UpdatedAt
		}
	}
	if out.ACR == "" {
		out.ACR = g.ACR
	}
	if len(out.AMR) == 0 {
		out.AMR = slices.Clone(g.AMR)
	}
	if len(g.AuthorizationDetails) > 0 {
		out.AuthorizationDetails = g.AuthorizationDetails
	}
	if len(g.Claims) > 0 {
		out.Claims = g.Claims
	}
}

// ContainsAuthorizationDetail reports whether set holds an element deeply
// equal to el.
func ContainsAuthorizationDetail(set []map[string]any, el map[string]any) bool {
	return slices.ContainsFunc(set, func(have map[string]any) bool { return reflect.DeepEqual(have, el) })
}

// narrowAuthorizationDetails keeps the elements of own the grant still
// holds. A grant without details leaves own as it is.
func narrowAuthorizationDetails(own, granted []map[string]any) []map[string]any {
	if len(own) == 0 || len(granted) == 0 {
		return own
	}
	out := make([]map[string]any, 0, len(own))
	for _, el := range own {
		if ContainsAuthorizationDetail(granted, el) {
			out = append(out, el)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// errGrantStoreContract reports a GrantStore.Find that returned neither a
// grant nor an error.
var errGrantStoreContract = errors.New("tokens: grant store returned no grant and no error")

// FindGrant returns the grant grantID names, or nil when grantID is empty,
// grants is nil, or the store holds no such grant. Any other lookup failure
// is returned, so a fault never reads as an absent grant.
func FindGrant(ctx context.Context, grants store.GrantStore, grantID string) (*store.Grant, error) {
	if grantID == "" || grants == nil {
		return nil, nil //nolint:nilnil // no grant to consult
	}
	g, err := grants.Find(ctx, grantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, nil //nolint:nilnil // no grant to consult
	case err != nil:
		return nil, err
	case g == nil:
		return nil, errGrantStoreContract
	}
	return g, nil
}
