package op

import (
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/store"
)

// infoMissingStoreCapabilities logs, once at construction, the optional
// store capabilities the configuration would use but the store does not
// implement. Each one has a documented fallback, so the OP still runs;
// the line exists because a hand-written wrapper around a bundled store
// hides these capabilities without failing, and the fallback is otherwise
// visible only as broader revocation or a skipped cascade.
//
// Capabilities [New] already requires are refused there and not listed.
func (c *config) infoMissingStoreCapabilities() {
	if c.logger == nil || nilcheck.IsNil(c.store) {
		return
	}
	missing := c.missingStoreCapabilities()
	if len(missing) == 0 {
		return
	}
	c.logger.Info("the store does not implement optional capabilities this configuration uses; "+
		"each falls back to its documented behaviour (see the op/store godoc of each interface)",
		"missing", missing)
}

// missingStoreCapabilities lists each optional capability as
// "<substore>: <interface>", in a fixed order.
func (c *config) missingStoreCapabilities() []string {
	var missing []string
	check := func(substore any, label string, implements bool) {
		if !nilcheck.IsNil(substore) && !implements {
			missing = append(missing, label)
		}
	}

	revocations := c.store.GrantRevocations()
	_, ok := revocations.(store.IssuanceRevocationChecker)
	check(revocations, "GrantRevocations: store.IssuanceRevocationChecker", ok)

	opaque := c.store.OpaqueAccessTokens()
	_, ok = opaque.(store.OpaqueAccessTokenChainRevoker)
	check(opaque, "OpaqueAccessTokens: store.OpaqueAccessTokenChainRevoker", ok)

	if c.dcr == nil {
		return missing
	}
	grants := c.store.Grants()
	_, ok = grants.(store.GrantSubjectLister)
	check(grants, "Grants: store.GrantSubjectLister", ok)
	for _, sub := range []struct {
		label    string
		substore any
	}{
		{"RefreshTokens", c.store.RefreshTokens()},
		{"Grants", grants},
		{"AccessTokens", c.store.AccessTokens()},
		{"OpaqueAccessTokens", opaque},
	} {
		_, ok = sub.substore.(store.RevokeByClient)
		check(sub.substore, sub.label+": store.RevokeByClient", ok)
	}
	return missing
}
