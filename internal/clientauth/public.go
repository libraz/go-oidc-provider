package clientauth

import "github.com/libraz/go-oidc-provider/op/store"

// IsPublicClient reports whether c authenticates as a public client: it is
// flagged PublicClient or registered with token_endpoint_auth_method=none.
// A nil client is not public.
func IsPublicClient(c *store.Client) bool {
	return c != nil && (c.PublicClient || c.TokenEndpointAuthMethod == string(MethodNone))
}
