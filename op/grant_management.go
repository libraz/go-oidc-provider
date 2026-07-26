package op

import (
	"strconv"

	"github.com/libraz/go-oidc-provider/op/feature"
)

// GrantManagementAction enumerates the grant_management_action values the
// OAuth 2.0 Grant Management draft defines. The create / replace / merge
// actions are supplied at the authorization endpoint; query / revoke are
// operations on the grant management endpoint (GET / DELETE).
//
// Experimental: the Grant Management spec is an IETF draft, so the
// enum and its option MAY change in a minor release to track a
// wire-incompatible draft bump.
type GrantManagementAction string

const (
	// GrantActionCreate requests a brand-new grant. A grant_id MUST NOT
	// accompany it.
	GrantActionCreate GrantManagementAction = "create"

	// GrantActionReplace overwrites the referenced grant's scope and
	// authorization_details with the new request's. Requires grant_id.
	GrantActionReplace GrantManagementAction = "replace"

	// GrantActionMerge unions the referenced grant's scope and
	// authorization_details with the new request's. Requires grant_id.
	GrantActionMerge GrantManagementAction = "merge"

	// GrantActionQuery is the read operation on the grant management
	// endpoint (GET {endpoint}/{grant_id}).
	GrantActionQuery GrantManagementAction = "query"

	// GrantActionRevoke is the delete operation on the grant management
	// endpoint (DELETE {endpoint}/{grant_id}).
	GrantActionRevoke GrantManagementAction = "revoke"
)

// valid reports whether a is one of the five defined actions.
func (a GrantManagementAction) valid() bool {
	switch a {
	case GrantActionCreate, GrantActionReplace, GrantActionMerge, GrantActionQuery, GrantActionRevoke:
		return true
	default:
		return false
	}
}

// WithGrantManagement enables the OAuth 2.0 Grant Management draft: the
// grant_management_action / grant_id authorization parameters are honoured,
// the grant management endpoint (query / revoke) is mounted, the token
// response carries grant_id, and discovery advertises the feature.
//
// actions is the closed set the OP accepts (advertised as
// grant_management_actions_supported). At least one action is required and
// each MUST be one of the defined values. actionRequired maps to discovery's
// grant_management_action_required: when true an authorization request that
// omits grant_management_action is rejected.
//
// Enabling this implicitly turns on [feature.GrantManagement].
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
func WithGrantManagement(actions []GrantManagementAction, actionRequired bool) Option {
	return optionFunc(func(c *config) error {
		if len(actions) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithGrantManagement requires at least one GrantManagementAction",
			}
		}
		seen := make(map[GrantManagementAction]struct{}, len(actions))
		for i, a := range actions {
			if !a.valid() {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithGrantManagement[" + strconv.Itoa(i) + "]: unknown action " + strconv.Quote(string(a)),
				}
			}
			if _, dup := seen[a]; dup {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithGrantManagement: duplicate action " + strconv.Quote(string(a)),
				}
			}
			seen[a] = struct{}{}
		}
		c.grantManagementActions = append([]GrantManagementAction(nil), actions...)
		c.grantManagementActionRequired = actionRequired
		c.grantManagementEnabled = true
		if !featureEnabled(c.features, feature.GrantManagement) {
			c.features = append(c.features, feature.GrantManagement)
		}
		return nil
	})
}

// grantManagementActionStrings returns the configured actions as wire
// strings for the discovery advertisement, in registration order.
func (c *config) grantManagementActionStrings() []string {
	if len(c.grantManagementActions) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.grantManagementActions))
	for _, a := range c.grantManagementActions {
		out = append(out, string(a))
	}
	return out
}

// grantManagementActionEnabled reports whether action is in the configured
// grant_management_actions set. It is used to gate the grant management
// endpoint's GET (query) / DELETE (revoke) operations so the endpoint never
// honours an action the OP did not advertise.
func (c *config) grantManagementActionEnabled(action GrantManagementAction) bool {
	if !c.grantManagementEnabled {
		return false
	}
	for _, a := range c.grantManagementActions {
		if a == action {
			return true
		}
	}
	return false
}

// grantManagementActionSet projects the configured actions onto the
// string-keyed set the authorize endpoint consumes. Returns nil when the
// feature is off.
func grantManagementActionSet(c *config) map[string]bool {
	if !c.grantManagementEnabled || len(c.grantManagementActions) == 0 {
		return nil
	}
	out := make(map[string]bool, len(c.grantManagementActions))
	for _, a := range c.grantManagementActions {
		out[string(a)] = true
	}
	return out
}
