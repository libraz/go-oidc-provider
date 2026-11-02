package op

import (
	"slices"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// storeCapabilityReasons names the accessor and the cause reported when a
// [storeTableManifest] substore the configuration needs is nil. DeviceCodes
// and CIBARequests are absent: their grant validators report the gap first.
//
//nolint:gochecknoglobals // lookup table; declared once and read-only.
var storeCapabilityReasons = map[string]struct{ desc, because string }{
	"Clients": {"ClientStore", "every client lookup at the authorize / token endpoints requires it"},
	"ConsumedJTIs": {
		"ConsumedJTIStore",
		"every client-authenticating endpoint's private_key_jwt verifier, and the JAR and DPoP replay gates, consume it",
	},
	"AuthorizationCodes": {"AuthorizationCodeStore", "grant.AuthorizationCode is enabled"},
	"Sessions":           {"SessionStore", "a grant that mounts the browser authorize endpoint is enabled"},
	"Interactions":       {"InteractionStore", "a grant that mounts the browser authorize endpoint is enabled"},
	"PushedAuthRequests": {"PushedAuthRequestStore", "feature.PAR is enabled"},
}

// validateStoreCapabilities enforces fail-fast detection of substores
// the configured store does not implement. Single-backend adapters
// such as oidcredis return nil from accessors that fall outside their
// scope; without this check the OP would defer the failure to the
// first request that touches the missing substore (or, for stores
// that previously panicked, crash the process). The check is keyed on
// the active grant / feature set so an embedder who runs only the
// flows their backend supports never sees a spurious rejection.
//
// Substore-specific validators (validateAccessTokenFormat,
// validateAccessTokenRevocation, validateRegistration, ...) keep
// their existing checks; this function fills the gap for the
// always-on substores (Clients, ConsumedJTIs, Users, AuthorizationCodes,
// RefreshTokens, Grants) and the grant-gated specialty substores
// (DeviceCodes, CIBARequests, PushedAuthRequests).
func (c *config) validateStoreCapabilities() error {
	for _, row := range storeTableManifest {
		reason, ok := storeCapabilityReasons[row.label]
		if !ok || (row.when != nil && !row.when(c)) {
			continue
		}
		if nilcheck.IsNil(row.store(c.store)) {
			return newConfigurationError("Store."+reason.desc+"() returned nil but "+
				reason.because, nil)
		}
	}
	for _, check := range []struct {
		need    bool
		got     any
		desc    string
		because string
	}{
		{
			need:    true,
			got:     c.effectiveUserStore(),
			desc:    "UserStore",
			because: "the always-mounted /userinfo endpoint resolves every subject through it (supply WithUserStore to source users elsewhere)",
		},
		{
			need:    c.grantEnabled(grant.RefreshToken),
			got:     c.store.RefreshTokens(),
			desc:    "RefreshTokenStore",
			because: "grant.RefreshToken is enabled",
		},
		{
			need:    needsGrantStore(c.grants),
			got:     c.store.Grants(),
			desc:    "GrantStore",
			because: "an interactive grant that issues consent records is enabled",
		},
	} {
		if !check.need {
			continue
		}
		if nilcheck.IsNil(check.got) {
			return newConfigurationError("Store."+check.desc+"() returned nil but "+
				check.because, nil)
		}
	}
	if err := c.validateRefreshRetryStoreCapability(); err != nil {
		return err
	}
	if grantsRequireAuthorizeEndpoint(c.grants) {
		return c.validateAuthorizeEndpointStoreCapabilities()
	}
	return nil
}

// validateRefreshRetryStoreCapability enforces [store.RefreshRetryResponseStore]
// on the refresh substore whenever the token endpoint will actually reach for
// it. The refresh rotation path persists a sealed retry response when it holds
// encryption keys, and those keys are the cookie keys, so the capability is
// mandatory exactly when the refresh_token grant is enabled and cookie keys are
// configured. Without this check the shortfall surfaces as a request-time
// failure on every rotation rather than at construction.
func (c *config) validateRefreshRetryStoreCapability() error {
	if !slices.Contains(c.grants, grant.RefreshToken) || len(c.cookieKeys) == 0 {
		return nil
	}
	refreshTokens := c.store.RefreshTokens()
	if nilcheck.IsNil(refreshTokens) {
		return nil
	}
	if _, ok := refreshTokens.(store.RefreshRetryResponseStore); !ok {
		return newConfigurationError("Store.RefreshTokens() must implement "+
			"store.RefreshRetryResponseStore because grant.RefreshToken is "+
			"enabled and cookie keys are configured, which makes the token "+
			"endpoint persist durable refresh retry responses", nil)
	}
	return nil
}

// validateAuthorizeEndpointStoreCapabilities enforces the transactional and
// compare-and-swap store contracts that a grant mounting the browser authorize
// endpoint depends on: the store must be [store.Transactional], its interaction
// substore must implement [store.InteractionStoreCAS], and its grant substore
// must implement [store.GrantClientLister].
func (c *config) validateAuthorizeEndpointStoreCapabilities() error {
	if tx := transactionalStore(c.store); nilcheck.IsNil(tx) {
		return newConfigurationError("Store must implement store.Transactional because "+
			"a grant that mounts the browser authorize endpoint is enabled", nil)
	}
	if interactions := c.store.Interactions(); !nilcheck.IsNil(interactions) {
		if _, ok := interactions.(store.InteractionStoreCAS); !ok {
			return newConfigurationError("Store.Interactions() must implement "+
				"store.InteractionStoreCAS because a grant that mounts "+
				"the browser authorize endpoint is enabled", nil)
		}
	}
	if grants := c.store.Grants(); !nilcheck.IsNil(grants) {
		if _, ok := grants.(store.GrantClientLister); !ok {
			return newConfigurationError("Store.Grants() must implement "+
				"store.GrantClientLister because a grant that mounts "+
				"the browser authorize endpoint is enabled", nil)
		}
	}
	return nil
}

// needsGrantStore reports whether the configured grant set requires a
// non-nil [store.GrantStore]. Every interactive grant issues a grant
// record, so the predicate is "any grant other than
// client_credentials".
func needsGrantStore(grants []grant.Type) bool {
	for _, g := range grants {
		if g == grant.ClientCredentials {
			continue
		}
		return true
	}
	return false
}
