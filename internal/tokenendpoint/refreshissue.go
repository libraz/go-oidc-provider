package tokenendpoint

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Refresh-token drop reasons. Every gate [issueRefreshToken] applies
// before persisting a chain root names itself with one of these values,
// which rides onto the caller's drop hook so an audit record can say
// which condition withheld the credential instead of only that one did.
const (
	// refreshDropProviderGrantDisabled: the Provider does not serve the
	// refresh_token grant at all, so the same token endpoint would
	// reject the credential with unsupported_grant_type.
	refreshDropProviderGrantDisabled = "provider_grant_disabled"

	// refreshDropClientNotRegistered: the client's registration does
	// not list refresh_token.
	refreshDropClientNotRegistered = "client_not_registered"

	// refreshDropScopeIneligible: the grant's scope policy
	// ([clientPermitsRefresh]) does not qualify the granted scope.
	refreshDropScopeIneligible = "scope_not_eligible"

	// refreshDropEmptySubject / refreshDropEmptyScope: the response
	// carries none of the material [refresh.Issuer] structurally
	// requires on a chain root.
	refreshDropEmptySubject = "empty_subject"
	refreshDropEmptyScope   = "empty_scope"

	// refreshDropMultipleResources: the response named more than one
	// resource audience. RFC 8707 §2.2 pins one resource indicator per
	// chain, and the rotation path re-mints against that single value,
	// so a multi-audience response has no representable binding.
	refreshDropMultipleResources = "multiple_resource_audience"
)

// refreshIssuance is the input to [issueRefreshToken]. The struct
// carries what a chain root needs regardless of which grant is minting
// it; the two fields that vary by grant are the scope predicate
// ([ScopeEligible]) and the drop hook ([OnDrop]).
type refreshIssuance struct {
	// Client is the authenticated client the chain belongs to.
	Client *store.Client

	// Subject is the value persisted on the record. SubjectPublic
	// marks it as an already-projected wire subject that the rotation
	// path MUST NOT run through the subject generator a second time.
	Subject       string
	SubjectPublic bool

	// GrantID ties the chain to the access token issued alongside it
	// so both ride the same per-grant revocation cascade.
	GrantID string

	// Scope is the granted scope set; it selects the TTL bucket and is
	// replayed onto every rotation.
	Scope []string

	// Resource is the single RFC 8707 resource indicator the chain is
	// pinned to, empty when the request named none.
	Resource string

	// Nonce is replayed onto id_tokens minted from later rotations.
	Nonce string

	// Origin names the grant that created the chain; metrics and the
	// audit stream project it to attribute chain creation.
	Origin store.RefreshTokenOrigin

	// Binding carries the request's sender constraint so refresh-time
	// enforcement can require a matching proof / certificate.
	Binding tokenBinding

	// AuthCtx supplies the authentication context replayed onto
	// refresh-derived id_tokens (auth_time / acr / amr) and the
	// authorization_details echoed on later responses.
	AuthCtx authContext

	// AccessTokenExtra are the private claims a later rotation stamps
	// onto the JWT access token it mints. Non-nil only for chains
	// rooted in a custom grant, whose handler owns those claims.
	AccessTokenExtra map[string]any

	// ScopeEligible is the grant's scope-policy predicate. Nil means
	// the grant has no scope precondition: delegation-style custom
	// grants legitimately issue refresh tokens with no OIDC scope, so
	// the openid / offline_access reading of OIDC Core 1.0 §11 does
	// not apply to them.
	ScopeEligible func(scope []string) bool

	// Ineligible, when non-empty, names a grant-specific condition the
	// caller resolved before the call that withholds the credential.
	// It is reported through [OnDrop] like any gate this function
	// applies itself.
	Ineligible string

	// OnDrop, when non-nil, is invoked with the reason a refresh token
	// was withheld. Grants that drop silently (the built-in four,
	// whose scope predicate encodes an ordinary "this response does
	// not carry offline access" outcome) leave it nil.
	OnDrop func(reason string)
}

// issueRefreshToken is the single terminal through which every refresh
// chain root is minted and persisted — built-in grants and custom
// grants alike. Centralising it is what keeps the invariant true that
// a refresh token is written only when the Provider serves the
// refresh_token grant AND the client is registered for it: a grant that
// mints its own chain root would otherwise hand the client a credential
// the same token endpoint refuses to redeem, leaving unredeemable rows
// behind and contradicting grant_types_supported.
//
// Returns the empty string with a nil error when a gate withheld the
// credential; that is a successful response, not a failure. A non-nil
// error means the store or the issuer failed and the caller MUST fail
// the whole token response.
func issueRefreshToken(ctx context.Context, deps Deps, in refreshIssuance) (string, error) {
	if reason := refreshDropReason(deps, in); reason != "" {
		if in.OnDrop != nil {
			in.OnDrop(reason)
		}
		return "", nil
	}
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: deps.RefreshTokens,
		Clock: deps.clockFunc(),
		TTL:   pickRefreshTokenTTL(deps, in.Scope),
	})
	if err != nil {
		return "", err
	}
	token, err := issuer.Issue(ctx, refresh.IssueInput{
		ClientID:             in.Client.ID,
		Subject:              in.Subject,
		SubjectPublic:        in.SubjectPublic,
		GrantID:              in.GrantID,
		Scope:                append([]string(nil), in.Scope...),
		Resource:             in.Resource,
		Origin:               in.Origin,
		AuthTime:             timeFromUnix(in.AuthCtx.AuthTime),
		ACR:                  in.AuthCtx.ACR,
		AMR:                  append([]string(nil), in.AuthCtx.AMR...),
		AuthorizationDetails: cloneAuthorizationDetails(in.AuthCtx.AuthorizationDetails),
		AccessTokenExtra:     in.AccessTokenExtra,
		Nonce:                in.Nonce,
		DPoPJKT:              refreshDPoPJKT(in.Client, in.Binding.DPoPJKT),
		MTLSCertThumbprint:   in.Binding.MTLSThumbprint,
	})
	if err != nil {
		return "", err
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditTokenIssued,
		Level:    audit.LevelInfo,
		Message:  "refresh token issued",
		ActorID:  in.Subject,
		ClientID: in.Client.ID,
		Extras: map[string]any{
			"grant_id":       in.GrantID,
			"offline_access": oidcscope.ContainsOfflineAccess(in.Scope),
			"ttl_bucket":     ttlBucketFor(deps, in.Scope),
			// The origin rides as the typed store value, not as a string:
			// it is the same value persisted on the chain, and consumers
			// that project it onto a label resolve it by type so no
			// request-derived string can stand in for a grant.
			auditevent.ExtraRefreshOrigin: in.Origin,
		},
	})
	return token, nil
}

// refreshDropReason returns the first gate that withholds the refresh
// token, or the empty string when the chain root may be persisted. The
// order runs from the widest gate to the narrowest so the reported
// reason names the operator-visible cause (a disabled grant) rather
// than a downstream symptom of it.
func refreshDropReason(deps Deps, in refreshIssuance) string {
	if reason := deps.refreshIssuanceBlockedReason(in.Client); reason != "" {
		return reason
	}
	if in.ScopeEligible != nil && !in.ScopeEligible(in.Scope) {
		return refreshDropScopeIneligible
	}
	if in.Ineligible != "" {
		return in.Ineligible
	}
	// The two structural preconditions [refresh.Issuer] enforces. They
	// are gates rather than errors: a response the OP cannot represent
	// as a chain root is a response without a refresh token, not a
	// failed token request.
	if in.Subject == "" {
		return refreshDropEmptySubject
	}
	if len(in.Scope) == 0 {
		return refreshDropEmptyScope
	}
	return ""
}
