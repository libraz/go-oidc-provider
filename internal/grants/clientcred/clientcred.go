package clientcred

import (
	"errors"
	"slices"

	"github.com/libraz/go-oidc-provider/op/store"
)

// grantTypeWire is the RFC 6749 §4.4 grant_type wire string. It is
// duplicated here (rather than imported from op/grant) so the
// authorization layer stays free of the public op/ namespace; the
// constant matches op/grant.ClientCredentials.String() by construction
// and is covered by a compile-time assertion in the test suite.
const grantTypeWire = "client_credentials"

// scopeOpenID is the OIDC scope the package rejects. Duplicated for
// the same reason as grantTypeWire.
const scopeOpenID = "openid"

// Sentinel errors. The HTTP layer maps these to OAuth wire codes:
//
//   - ErrPublicClient        → unauthorized_client.
//   - ErrGrantNotPermitted   → unauthorized_client.
//   - ErrOpenIDScope         → invalid_scope.
//   - ErrScopeForbidden      → invalid_scope.
var (
	// ErrPublicClient indicates the authenticated client is registered
	// as public. RFC 6749 §4.4 confines client_credentials to
	// confidential clients because the authentication IS the
	// authorization; a client without a credential cannot speak for
	// itself.
	ErrPublicClient = errors.New("clientcred: public clients cannot use client_credentials")

	// ErrGrantNotPermitted indicates the client is not registered for
	// the client_credentials grant. The check guards against a
	// confidential client repurposing a credential beyond its
	// intended role.
	ErrGrantNotPermitted = errors.New("clientcred: client is not permitted to use client_credentials")

	// ErrOpenIDScope indicates the requested scope contains "openid".
	// The OIDC scope drives id_token issuance, which has no meaning in
	// a grant where there is no end-user; the rejection prevents a
	// configuration mistake from minting useless tokens.
	ErrOpenIDScope = errors.New("clientcred: openid scope is not permitted in client_credentials")

	// ErrScopeForbidden indicates the requested scope contains an entry
	// outside the client's registered Scopes set. RFC 6749 §3.3
	// permits the OP to narrow the requested scope; the library's
	// posture is to reject any out-of-set entry rather than silently
	// dropping it.
	ErrScopeForbidden = errors.New("clientcred: requested scope is not permitted for client")
)

// AuthorizeInput is the parameter bundle [Authorize] consumes.
type AuthorizeInput struct {
	// Client is the authenticated client record. The caller has
	// already verified credentials; Authorize only consults policy
	// fields.
	Client *store.Client

	// RequestedScope is the optional space-delimited scope the RP
	// sent on the wire (already split into a slice). An empty slice
	// means "no scope param"; the function falls back to the
	// client's full registered set.
	RequestedScope []string
}

// Authorized is the successful return of [Authorize].
type Authorized struct {
	// Scope is the granted scope set: either the validated requested
	// scope (when non-empty) or the client's full registered set
	// (when the request omitted scope). The slice is freshly
	// allocated so the caller may mutate it without affecting the
	// input.
	Scope []string
}

// Authorize applies the RFC 6749 §4.4 authorization checks for the
// client_credentials grant: client must be confidential, must list
// the grant in its registered GrantTypes, must not request "openid",
// and any requested scope must be a subset of the client's
// registered Scopes. On success it returns the granted scope set.
func Authorize(in AuthorizeInput) (*Authorized, error) {
	if in.Client == nil {
		return nil, errors.New("clientcred: nil client")
	}
	if in.Client.PublicClient {
		return nil, ErrPublicClient
	}
	if !slices.Contains(in.Client.GrantTypes, grantTypeWire) {
		return nil, ErrGrantNotPermitted
	}
	if slices.Contains(in.RequestedScope, scopeOpenID) {
		return nil, ErrOpenIDScope
	}
	if len(in.RequestedScope) == 0 {
		return &Authorized{Scope: slices.Clone(in.Client.Scopes)}, nil
	}
	allowed := make(map[string]struct{}, len(in.Client.Scopes))
	for _, s := range in.Client.Scopes {
		allowed[s] = struct{}{}
	}
	for _, s := range in.RequestedScope {
		if _, ok := allowed[s]; !ok {
			return nil, ErrScopeForbidden
		}
	}
	return &Authorized{Scope: slices.Clone(in.RequestedScope)}, nil
}
