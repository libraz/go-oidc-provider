package op

import (
	"strconv"

	"github.com/libraz/go-oidc-provider/internal/protectedresource"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
)

// ProtectedResource describes one resource server for which the OP hosts
// an OAuth 2.0 Protected Resource Metadata document (RFC 9728). The OP
// serves the document at /.well-known/oauth-protected-resource, appending
// the resource identifier's path component per RFC 9728 §3.1 when several
// resources are registered. The OP advertises itself as the resource's
// authorization server; it does not validate the resource's bearer
// tokens — that remains the resource server's responsibility.
//
// Stable since v1.0.
type ProtectedResource struct {
	// Resource is the resource identifier (RFC 8707 form: an absolute
	// URI with no fragment). It is validated at [New] time and also
	// determines the well-known path the document is served at.
	Resource string

	// ScopesSupported lists the OAuth scopes the resource recognises.
	ScopesSupported []string

	// BearerMethodsSupported lists the RFC 6750 methods the resource
	// accepts ("header", "body", "query"). Empty omits the field.
	BearerMethodsSupported []string

	// ResourceSigningAlgValuesSupported lists the JWS alg values the
	// resource uses to sign resource responses, when it signs them.
	ResourceSigningAlgValuesSupported []string

	// JWKSURI is the resource's JWK Set URL, when it publishes one.
	JWKSURI string

	// ResourceDocumentation is a human-readable documentation URL.
	ResourceDocumentation string
}

// WithProtectedResources registers one or more resource-server metadata
// documents (RFC 9728). Each document is served read-only at
// /.well-known/oauth-protected-resource (plus the resource's path
// component per RFC 9728 §3.1) and names the OP's own issuer in
// authorization_servers.
//
// Validation:
//   - At least one [ProtectedResource] is required.
//   - Each Resource MUST be a valid resource indicator (absolute URI,
//     no fragment), validated like an RFC 8707 resource parameter.
//   - Duplicate Resource values (after canonicalisation) are rejected;
//     the cross-call check runs in [New] so repeated calls and a single
//     variadic call are equivalent.
//
// Repeated calls append, so embedders MAY layer a base set with a
// deployment-specific overlay.
//
// Stable since v1.0.
func WithProtectedResources(resources ...ProtectedResource) Option {
	return optionFunc(func(c *config) error {
		if len(resources) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithProtectedResources requires at least one ProtectedResource",
			}
		}
		for i, r := range resources {
			if err := resourceindicator.Validate(r.Resource); err != nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithProtectedResources[" + strconv.Itoa(i) + "]: invalid resource " + strconv.Quote(r.Resource),
					Cause:       err,
				}
			}
		}
		c.protectedResources = append(c.protectedResources, resources...)
		return nil
	})
}

// validateProtectedResources rejects two registered resources that
// canonicalise to the same identifier, and — because the well-known mount
// path is derived from the resource's path component only (RFC 9728 §3.1,
// host-insensitive) — also rejects two distinct resources whose paths
// collide on the same mount pattern. Without the second check the router
// would call mux.Handle twice on one pattern and panic at [New].
func (c *config) validateProtectedResources() error {
	seen := make(map[string]struct{}, len(c.protectedResources))
	paths := make(map[string]string, len(c.protectedResources))
	for i, r := range c.protectedResources {
		canon, err := resourceindicator.Canonicalize(r.Resource)
		if err != nil {
			// Unreachable: the option site already validated every entry.
			return &Error{
				Code:        codeConfiguration,
				Description: "WithProtectedResources[" + strconv.Itoa(i) + "]: invalid resource " + strconv.Quote(r.Resource),
				Cause:       err,
			}
		}
		if _, dup := seen[canon]; dup {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithProtectedResources: duplicate resource " + strconv.Quote(r.Resource),
			}
		}
		seen[canon] = struct{}{}

		path := protectedresource.WellKnownPath(r.Resource)
		if prev, dup := paths[path]; dup {
			return &Error{
				Code: codeConfiguration,
				Description: "WithProtectedResources: resources " + strconv.Quote(prev) + " and " +
					strconv.Quote(r.Resource) + " map to the same metadata path " + strconv.Quote(path) +
					" (RFC 9728 §3.1 derives the path from the resource path component, ignoring host)",
			}
		}
		paths[path] = r.Resource
	}
	return nil
}
