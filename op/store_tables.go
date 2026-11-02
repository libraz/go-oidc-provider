package op

import (
	"slices"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// storeTableRow declares one substore the provider touches: the label its
// schema failure is reported under, how to reach it, and the configuration
// under which a mounted endpoint reads or writes it. A nil when means every
// configuration.
type storeTableRow struct {
	label string
	store func(store.Store) any
	when  func(*config) bool
}

// storeTableManifest is the single declaration of which substores a
// configuration needs. The construction-time schema check derives its
// candidate set from it; the SQL adapter's schema/TABLES.md states the same
// conditions per table.
//
// RefreshTokens is unconditional: /revocation, /introspect, subject
// revocation and the client-deletion cascade look refresh tokens up and
// clear them whichever grants are enabled.
//
//nolint:gochecknoglobals // manifest; declared once and read-only.
var storeTableManifest = []storeTableRow{
	{"Clients", func(s store.Store) any { return s.Clients() }, nil},
	{"Metadata", func(s store.Store) any { return s.Metadata() }, nil},
	{"ConsumedJTIs", func(s store.Store) any { return s.ConsumedJTIs() }, nil},
	{"AccessTokens", func(s store.Store) any { return s.AccessTokens() }, nil},
	{"OpaqueAccessTokens", func(s store.Store) any { return s.OpaqueAccessTokens() }, nil},
	{"GrantRevocations", func(s store.Store) any { return s.GrantRevocations() }, nil},
	{"Grants", func(s store.Store) any { return s.Grants() }, nil},
	{"RefreshTokens", func(s store.Store) any { return s.RefreshTokens() }, nil},
	{
		"AuthorizationCodes", func(s store.Store) any { return s.AuthorizationCodes() },
		func(c *config) bool { return c.grantEnabled(grant.AuthorizationCode) },
	},
	{
		"Sessions", func(s store.Store) any { return s.Sessions() },
		func(c *config) bool { return grantsRequireAuthorizeEndpoint(c.grants) },
	},
	{
		"Interactions", func(s store.Store) any { return s.Interactions() },
		func(c *config) bool { return grantsRequireAuthorizeEndpoint(c.grants) },
	},
	{
		"PushedAuthRequests", func(s store.Store) any { return s.PushedAuthRequests() },
		func(c *config) bool { return featureEnabled(c.features, feature.PAR) },
	},
	{
		"InitialAccessTokens", func(s store.Store) any { return s.InitialAccessTokens() },
		func(c *config) bool { return c.dcr != nil },
	},
	{
		"RegistrationAccessTokens", func(s store.Store) any { return s.RegistrationAccessTokens() },
		func(c *config) bool { return c.dcr != nil },
	},
	{
		"DeviceCodes", func(s store.Store) any { return s.DeviceCodes() },
		func(c *config) bool { return c.grantEnabled(grant.DeviceCode) },
	},
	{
		"CIBARequests", func(s store.Store) any { return s.CIBARequests() },
		func(c *config) bool { return c.grantEnabled(grant.CIBA) },
	},
	{
		"SSFStreams", func(s store.Store) any { return ssfSubstores(s).streams },
		func(c *config) bool { return c.sharedSignals },
	},
	{
		"SSFEvents", func(s store.Store) any { return ssfSubstores(s).events },
		func(c *config) bool { return c.sharedSignals },
	},
}

// ssfStores are the Shared Signals substores of a store; both are nil when
// the store does not implement [store.SharedSignalsStore].
type ssfStores struct {
	streams store.SSFStreamStore
	events  store.SSFEventStore
}

func ssfSubstores(s store.Store) ssfStores {
	ssf, ok := s.(store.SharedSignalsStore)
	if !ok {
		return ssfStores{}
	}
	return ssfStores{streams: ssf.SSFStreams(), events: ssf.SSFEvents()}
}

// grantEnabled reports whether g is among the enabled grants.
func (c *config) grantEnabled(g grant.Type) bool { return slices.Contains(c.grants, g) }
