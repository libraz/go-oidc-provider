package op

import (
	"context"
	"strconv"

	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
)

// AuthorizationDetailType registers one RFC 9396 §2 "type" value the OP
// accepts inside an authorization_details element, paired with a validator
// the embedder uses to enforce the type-specific shape.
//
// The library performs only the RFC 9396 §2.1 structural checks (the
// request is a JSON array of objects, each carrying a non-empty string
// "type" the OP recognises) and conservative size limits; the meaning of
// every other member is type-specific and therefore delegated to Validate.
// A nil Validate is rejected at [New]: registering a type without a
// validator would accept arbitrary payloads under that type.
//
// Stable since v0.x. The type is experimental until v1.0.
type AuthorizationDetailType struct {
	// Type is the RFC 9396 §2 "type" identifier (for example
	// "payment_initiation"). It MUST be non-empty and unique across all
	// registered types.
	Type string

	// Validate enforces the type-specific shape of one authorization
	// details element. el is the decoded JSON object (its "type" member
	// equals Type); client is the authenticated client the request
	// belongs to. A non-nil return rejects the request with
	// invalid_authorization_details. Validate MUST NOT mutate el.
	Validate func(ctx context.Context, el map[string]any, client *store.Client) error
}

// WithAuthorizationDetailTypes registers the authorization_details types
// the OP accepts (RFC 9396). Enabling this implicitly turns on
// [feature.RAR]: the authorization_details parameter becomes acceptable at
// /authorize, /par, and /token, the granted details are persisted and
// echoed on the token response and introspection, and discovery advertises
// authorization_details_types_supported.
//
// Validation:
//   - At least one [AuthorizationDetailType] is required.
//   - Each Type MUST be non-empty; each Validate MUST be non-nil.
//   - Duplicate Type values are rejected; the cross-call check runs
//     against the live config so repeated calls and a single variadic
//     call behave identically.
//
// Repeated calls append, so embedders MAY layer a base set with a
// deployment-specific overlay.
//
// Stable since v0.x.
func WithAuthorizationDetailTypes(types ...AuthorizationDetailType) Option {
	return optionFunc(func(c *config) error {
		if len(types) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAuthorizationDetailTypes requires at least one AuthorizationDetailType",
			}
		}
		for i, dt := range types {
			if dt.Type == "" {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithAuthorizationDetailTypes[" + strconv.Itoa(i) + "]: Type must not be empty",
				}
			}
			if dt.Validate == nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithAuthorizationDetailTypes[" + strconv.Itoa(i) + "]: Validate must not be nil for type " + strconv.Quote(dt.Type),
				}
			}
			if c.hasAuthorizationDetailType(dt.Type) {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithAuthorizationDetailTypes: duplicate type " + strconv.Quote(dt.Type),
				}
			}
			c.authorizationDetailTypes = append(c.authorizationDetailTypes, dt)
		}
		if !featureEnabled(c.features, feature.RAR) {
			c.features = append(c.features, feature.RAR)
		}
		return nil
	})
}

// hasAuthorizationDetailType reports whether a type with the given
// identifier is already registered on the config.
func (c *config) hasAuthorizationDetailType(typ string) bool {
	for _, dt := range c.authorizationDetailTypes {
		if dt.Type == typ {
			return true
		}
	}
	return false
}

// authorizationDetailRegistry projects the registered types onto the
// internal validator registry the authorize / token endpoints consume.
// Returns nil when no types are registered so the endpoints treat
// authorization_details as an ignorable unknown extension.
func authorizationDetailRegistry(c *config) map[string]authorizationdetails.Validator {
	if len(c.authorizationDetailTypes) == 0 {
		return nil
	}
	reg := make(map[string]authorizationdetails.Validator, len(c.authorizationDetailTypes))
	for _, dt := range c.authorizationDetailTypes {
		reg[dt.Type] = authorizationdetails.Validator(dt.Validate)
	}
	return reg
}

// authorizationDetailTypeNames returns the registered type identifiers in
// registration order, for the discovery advertisement.
func (c *config) authorizationDetailTypeNames() []string {
	if len(c.authorizationDetailTypes) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.authorizationDetailTypes))
	for _, dt := range c.authorizationDetailTypes {
		out = append(out, dt.Type)
	}
	return out
}
