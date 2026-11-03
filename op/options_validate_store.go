package op

import (
	"errors"
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
// validateAccessTokenRevocation, validateRegistration, the device-code
// and CIBA grant validators, ...) run earlier in validate and return
// at their first failure; this function fills the gap for the
// always-on substores (Clients, ConsumedJTIs, Users, AuthorizationCodes,
// RefreshTokens, Grants) and the grant-gated PushedAuthRequests,
// Sessions and Interactions substores.
//
// It reports together, in one joined error, every gap among exactly
// those substores plus the refresh-retry, transactional, compare-and-swap
// and grant-lister capabilities, so a store built from scratch sees them
// all in a single run. Gaps in the substores owned by the earlier
// validators are reported one at a time, before this function runs.
func (c *config) validateStoreCapabilities() error {
	errs := c.nilSubstoreErrors()
	if err := c.validateRefreshRetryStoreCapability(); err != nil {
		errs = append(errs, err)
	}
	if grantsRequireAuthorizeEndpoint(c.grants) {
		if err := c.validateAuthorizeEndpointStoreCapabilities(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// nilSubstoreErrors returns one configuration error per substore the
// active configuration needs but the store returns nil for.
func (c *config) nilSubstoreErrors() []error {
	var errs []error
	for _, row := range storeTableManifest {
		reason, ok := storeCapabilityReasons[row.label]
		if !ok || (row.when != nil && !row.when(c)) {
			continue
		}
		if nilcheck.IsNil(row.store(c.store)) {
			errs = append(errs, newConfigurationError("Store."+reason.desc+"() returned nil but "+
				reason.because, nil))
		}
	}
	for _, check := range []struct {
		need    bool
		got     any
		desc    string
		because string
	}{
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
			errs = append(errs, newConfigurationError("Store."+check.desc+"() returned nil but "+
				check.because, nil))
		}
	}
	if grantsResolveEndUser(c.grants) && nilcheck.IsNil(c.effectiveUserStore()) {
		errs = append(errs, newConfigurationError(errUserStoreUnresolved, nil))
	}
	return errs
}

// errUserStoreUnresolved is the description reported when a grant that
// resolves end-user subjects is enabled and no user store is configured.
const errUserStoreUnresolved = "no end-user store is configured but an enabled grant resolves end-user " +
	"subjects (token redemption, /userinfo and ID Token claims read it); set PrimaryPassword.Store " +
	"in WithLoginFlow or pass op.WithUserStore, e.g. op.WithUserStore(st.Users()) with a bundled " +
	"adapter's concrete Users()"

// grantsResolveEndUser reports whether any enabled grant redeems for an
// end-user subject. client_credentials is the only grant that never does.
func grantsResolveEndUser(grants []grant.Type) bool {
	return slices.ContainsFunc(grants, func(g grant.Type) bool { return g != grant.ClientCredentials })
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
	var errs []error
	if tx := transactionalStore(c.store); nilcheck.IsNil(tx) {
		errs = append(errs, newConfigurationError("Store must implement store.Transactional because "+
			"a grant that mounts the browser authorize endpoint is enabled", nil))
	}
	if interactions := c.store.Interactions(); !nilcheck.IsNil(interactions) {
		if _, ok := interactions.(store.InteractionStoreCAS); !ok {
			errs = append(errs, newConfigurationError("Store.Interactions() must implement "+
				"store.InteractionStoreCAS because a grant that mounts "+
				"the browser authorize endpoint is enabled", nil))
		}
	}
	if grants := c.store.Grants(); !nilcheck.IsNil(grants) {
		if _, ok := grants.(store.GrantClientLister); !ok {
			errs = append(errs, newConfigurationError("Store.Grants() must implement "+
				"store.GrantClientLister because a grant that mounts "+
				"the browser authorize endpoint is enabled", nil))
		}
	}
	return errors.Join(errs...)
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
