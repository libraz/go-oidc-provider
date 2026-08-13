package scenariokit

import (
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// WithClientCredentials enables the client_credentials grant alongside
// the library defaults (authorization_code + refresh_token).
//
// The token endpoint refuses a grant_type the Provider has not enabled
// before it dispatches, so a scenario that exercises client_credentials
// has to opt in explicitly — otherwise it asserts against
// unsupported_grant_type rather than the behaviour the row describes.
// Rows that assert the refusal itself construct their own grant set.
func WithClientCredentials() op.Option {
	return op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials)
}
