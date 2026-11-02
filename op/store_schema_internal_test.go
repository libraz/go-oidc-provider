package op

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// schemaProbe records each ValidateSchema call under its name and
// returns the configured error.
type schemaProbe struct {
	name string
	log  *[]string
	err  error
}

func (p *schemaProbe) ValidateSchema(context.Context) error {
	*p.log = append(*p.log, p.name)
	return p.err
}

type (
	probeClients struct {
		store.ClientStore
		*schemaProbe
	}
	probeMetadata struct {
		store.MetadataStore
		*schemaProbe
	}
	probeJTIs struct {
		store.ConsumedJTIStore
		*schemaProbe
	}
	probeMetadataJTIs struct {
		store.MetadataStore
		store.ConsumedJTIStore
		*schemaProbe
	}
	probeAccessTokens struct {
		store.AccessTokenRegistry
		*schemaProbe
	}
	probeOpaque struct {
		store.OpaqueAccessTokenStore
		*schemaProbe
	}
	probeRevocations struct {
		store.GrantRevocationStore
		*schemaProbe
	}
	probeGrants struct {
		store.GrantStore
		*schemaProbe
	}
	probeCodes struct {
		store.AuthorizationCodeStore
		*schemaProbe
	}
	probeRefresh struct {
		store.RefreshTokenStore
		*schemaProbe
	}
	probeSessions struct {
		store.SessionStore
		*schemaProbe
	}
	probeInteractions struct {
		store.InteractionStore
		*schemaProbe
	}
	probePARs struct {
		store.PushedAuthRequestStore
		*schemaProbe
	}
	probeIATs struct {
		store.InitialAccessTokenStore
		*schemaProbe
	}
	probeRATs struct {
		store.RegistrationAccessTokenStore
		*schemaProbe
	}
	probeDeviceCodes struct {
		store.DeviceCodeStore
		*schemaProbe
	}
	probeCIBA struct {
		store.CIBARequestStore
		*schemaProbe
	}
	probeSSFStreams struct {
		store.SSFStreamStore
		*schemaProbe
	}
	probeSSFEvents struct {
		store.SSFEventStore
		*schemaProbe
	}
	probeLockouts struct {
		store.AuthnLockoutStore
		*schemaProbe
	}
	probeUsers struct {
		store.UserStore
		*schemaProbe
	}
	probeUserPasswords struct {
		store.UserPasswordStore
		*schemaProbe
	}
	probeTOTPs struct {
		store.TOTPStore
		*schemaProbe
	}
)

// schemaFakeStore is an inmem store whose accessors return recording
// wrappers. A field left nil makes its accessor return nil.
type schemaFakeStore struct {
	*inmem.Store

	clients       store.ClientStore
	metadata      store.MetadataStore
	jtis          store.ConsumedJTIStore
	accessTokens  store.AccessTokenRegistry
	opaque        store.OpaqueAccessTokenStore
	revocations   store.GrantRevocationStore
	grants        store.GrantStore
	codes         store.AuthorizationCodeStore
	refresh       store.RefreshTokenStore
	sessions      store.SessionStore
	interactions  store.InteractionStore
	pars          store.PushedAuthRequestStore
	iats          store.InitialAccessTokenStore
	rats          store.RegistrationAccessTokenStore
	deviceCodes   store.DeviceCodeStore
	ciba          store.CIBARequestStore
	ssfStreams    store.SSFStreamStore
	ssfEvents     store.SSFEventStore
	lockouts      store.AuthnLockoutStore
	users         store.UserStore
	userPasswords store.UserPasswordStore
	probes        map[string]*schemaProbe
	log           *[]string
}

func (s *schemaFakeStore) Clients() store.ClientStore           { return s.clients }
func (s *schemaFakeStore) Metadata() store.MetadataStore        { return s.metadata }
func (s *schemaFakeStore) ConsumedJTIs() store.ConsumedJTIStore { return s.jtis }
func (s *schemaFakeStore) AccessTokens() store.AccessTokenRegistry {
	return s.accessTokens
}

func (s *schemaFakeStore) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return s.opaque
}

func (s *schemaFakeStore) GrantRevocations() store.GrantRevocationStore {
	return s.revocations
}
func (s *schemaFakeStore) Grants() store.GrantStore { return s.grants }
func (s *schemaFakeStore) AuthorizationCodes() store.AuthorizationCodeStore {
	return s.codes
}
func (s *schemaFakeStore) RefreshTokens() store.RefreshTokenStore { return s.refresh }
func (s *schemaFakeStore) Sessions() store.SessionStore           { return s.sessions }
func (s *schemaFakeStore) Interactions() store.InteractionStore   { return s.interactions }
func (s *schemaFakeStore) PushedAuthRequests() store.PushedAuthRequestStore {
	return s.pars
}

func (s *schemaFakeStore) InitialAccessTokens() store.InitialAccessTokenStore {
	return s.iats
}

func (s *schemaFakeStore) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	return s.rats
}
func (s *schemaFakeStore) DeviceCodes() store.DeviceCodeStore     { return s.deviceCodes }
func (s *schemaFakeStore) CIBARequests() store.CIBARequestStore   { return s.ciba }
func (s *schemaFakeStore) SSFStreams() store.SSFStreamStore       { return s.ssfStreams }
func (s *schemaFakeStore) SSFEvents() store.SSFEventStore         { return s.ssfEvents }
func (s *schemaFakeStore) AuthnLockouts() store.AuthnLockoutStore { return s.lockouts }
func (s *schemaFakeStore) Users() store.UserStore                 { return s.users }
func (s *schemaFakeStore) UserPasswords() store.UserPasswordStore { return s.userPasswords }

func newSchemaFakeStore() *schemaFakeStore {
	in := inmem.New()
	log := &[]string{}
	f := &schemaFakeStore{Store: in, probes: map[string]*schemaProbe{}, log: log}
	p := func(name string) *schemaProbe {
		probe := &schemaProbe{name: name, log: log}
		f.probes[name] = probe
		return probe
	}
	f.clients = &probeClients{in.Clients(), p("Clients")}
	f.metadata = &probeMetadata{in.Metadata(), p("Metadata")}
	f.jtis = &probeJTIs{in.ConsumedJTIs(), p("ConsumedJTIs")}
	f.accessTokens = &probeAccessTokens{in.AccessTokens(), p("AccessTokens")}
	f.opaque = &probeOpaque{in.OpaqueAccessTokens(), p("OpaqueAccessTokens")}
	f.revocations = &probeRevocations{in.GrantRevocations(), p("GrantRevocations")}
	f.grants = &probeGrants{in.Grants(), p("Grants")}
	f.codes = &probeCodes{in.AuthorizationCodes(), p("AuthorizationCodes")}
	f.refresh = &probeRefresh{in.RefreshTokens(), p("RefreshTokens")}
	f.sessions = &probeSessions{in.Sessions(), p("Sessions")}
	f.interactions = &probeInteractions{in.Interactions(), p("Interactions")}
	f.pars = &probePARs{in.PushedAuthRequests(), p("PushedAuthRequests")}
	f.iats = &probeIATs{in.InitialAccessTokens(), p("InitialAccessTokens")}
	f.rats = &probeRATs{in.RegistrationAccessTokens(), p("RegistrationAccessTokens")}
	f.deviceCodes = &probeDeviceCodes{in.DeviceCodes(), p("DeviceCodes")}
	f.ciba = &probeCIBA{in.CIBARequests(), p("CIBARequests")}
	f.ssfStreams = &probeSSFStreams{in.SSFStreams(), p("SSFStreams")}
	f.ssfEvents = &probeSSFEvents{in.SSFEvents(), p("SSFEvents")}
	f.lockouts = &probeLockouts{in.AuthnLockouts(), p("AuthnLockouts")}
	f.users = &probeUsers{in.Users(), p("Users")}
	f.userPasswords = &probeUserPasswords{in.UserPasswords(), p("user store")}
	return f
}

// schemaAlways is what every configuration checks, in report order.
var schemaAlways = []string{
	"Clients", "Metadata", "ConsumedJTIs", "AccessTokens",
	"OpaqueAccessTokens", "GrantRevocations", "Grants", "RefreshTokens",
}

// schemaDefaultGrant is what the authorization_code grant adds.
var schemaDefaultGrant = []string{"AuthorizationCodes", "Sessions", "Interactions"}

func schemaDefaultFlow(f *schemaFakeStore, rules ...Rule) Option {
	return WithLoginFlow(LoginFlow{Primary: PrimaryPassword{Store: f.userPasswords}, Rules: rules})
}

func runStoreSchema(t *testing.T, f *schemaFakeStore, opts ...Option) error {
	t.Helper()
	c, err := newConfig(append([]Option{WithStore(f)}, opts...))
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	return c.validateStoreSchema(context.Background())
}

func assertSchemaLog(t *testing.T, f *schemaFakeStore, want []string) {
	t.Helper()
	if !slices.Equal(*f.log, want) {
		t.Fatalf("checked stores:\n got  %q\n want %q", *f.log, want)
	}
}

func TestStoreSchema_DefaultConfiguration(t *testing.T) {
	t.Parallel()

	f := newSchemaFakeStore()
	if err := runStoreSchema(t, f, schemaDefaultFlow(f)); err != nil {
		t.Fatalf("validateStoreSchema: %v", err)
	}
	assertSchemaLog(t, f, slices.Concat(schemaAlways, schemaDefaultGrant, []string{"user store", "AuthnLockouts"}))
}

func TestStoreSchema_ClientCredentialsOnly(t *testing.T) {
	t.Parallel()

	f := newSchemaFakeStore()
	if err := runStoreSchema(t, f, WithGrants(grant.ClientCredentials)); err != nil {
		t.Fatalf("validateStoreSchema: %v", err)
	}
	assertSchemaLog(t, f, slices.Concat(schemaAlways, []string{"Users"}))
}

func TestStoreSchema_FeaturesAddTheirStores(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		opt   Option
		added []string
	}{
		{"par", WithFeature(feature.PAR), []string{"PushedAuthRequests"}},
		{"dcr", WithDynamicRegistration(RegistrationOption{}), []string{"InitialAccessTokens", "RegistrationAccessTokens"}},
		{"device_code", WithDeviceCodeGrant(), []string{"DeviceCodes"}},
		{"ciba", WithCIBA(), []string{"CIBARequests"}},
		{"ssf", WithSharedSignals(), []string{"SSFStreams", "SSFEvents"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSchemaFakeStore()
			if err := runStoreSchema(t, f, schemaDefaultFlow(f), tc.opt); err != nil {
				t.Fatalf("validateStoreSchema: %v", err)
			}
			assertSchemaLog(t, f, slices.Concat(schemaAlways, schemaDefaultGrant, tc.added, []string{"user store", "AuthnLockouts"}))
		})
	}
}

func TestStoreSchema_StepTOTPAddsItsStore(t *testing.T) {
	t.Parallel()

	f := newSchemaFakeStore()
	totp := &probeTOTPs{f.TOTPs(), &schemaProbe{name: "TOTP", log: f.log}}
	if err := runStoreSchema(t, f, schemaDefaultFlow(f, Rule{Then: StepTOTP{Store: totp}})); err != nil {
		t.Fatalf("validateStoreSchema: %v", err)
	}
	assertSchemaLog(t, f, slices.Concat(schemaAlways, schemaDefaultGrant, []string{"user store", "TOTP", "AuthnLockouts"}))
}

func TestStoreSchema_ExplicitLockoutStoreIsTheOneChecked(t *testing.T) {
	t.Parallel()

	f := newSchemaFakeStore()
	lockouts := &probeLockouts{inmem.New().AuthnLockouts(), &schemaProbe{name: "WithAuthnLockoutStore", log: f.log}}
	if err := runStoreSchema(t, f, schemaDefaultFlow(f), WithAuthnLockoutStore(lockouts)); err != nil {
		t.Fatalf("validateStoreSchema: %v", err)
	}
	assertSchemaLog(t, f, slices.Concat(schemaAlways, schemaDefaultGrant, []string{"user store", "WithAuthnLockoutStore"}))
}

func TestStoreSchema_AggregatesFailuresWithLabels(t *testing.T) {
	t.Parallel()

	f := newSchemaFakeStore()
	grantsErr := errors.New("grants table missing")
	usersErr := errors.New("users table missing")
	f.probes["Grants"].err = grantsErr
	f.probes["user store"].err = usersErr

	err := runStoreSchema(t, f, schemaDefaultFlow(f))
	var opErr *Error
	if !errors.As(err, &opErr) || opErr.Code != codeConfiguration {
		t.Fatalf("err = %v, want a configuration *Error", err)
	}
	if opErr.Description != "store schema does not match this configuration" {
		t.Fatalf("description = %q", opErr.Description)
	}
	if !errors.Is(err, grantsErr) || !errors.Is(err, usersErr) {
		t.Fatalf("err = %v, want both causes reachable through errors.Is", err)
	}
	for _, want := range []string{"Grants: grants table missing", "user store: users table missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %q, want it to contain %q", err, want)
		}
	}
	// A failure does not stop the remaining stores from being checked.
	assertSchemaLog(t, f, slices.Concat(schemaAlways, schemaDefaultGrant, []string{"user store", "AuthnLockouts"}))
}

func TestStoreSchema_SkipsNilSubstore(t *testing.T) {
	t.Parallel()

	f := newSchemaFakeStore()
	f.sessions = nil
	if err := runStoreSchema(t, f, schemaDefaultFlow(f)); err != nil {
		t.Fatalf("validateStoreSchema: %v", err)
	}
	assertSchemaLog(t, f, slices.Concat(schemaAlways,
		[]string{"AuthorizationCodes", "Interactions", "user store", "AuthnLockouts"}))
}

func TestStoreSchema_SameValueCheckedOnce(t *testing.T) {
	t.Parallel()

	f := newSchemaFakeStore()
	shared := &probeMetadataJTIs{f.Store.Metadata(), f.Store.ConsumedJTIs(), &schemaProbe{name: "Metadata+ConsumedJTIs", log: f.log}}
	f.metadata = shared
	f.jtis = shared
	if err := runStoreSchema(t, f, schemaDefaultFlow(f)); err != nil {
		t.Fatalf("validateStoreSchema: %v", err)
	}
	want := slices.Concat([]string{"Clients", "Metadata+ConsumedJTIs"}, schemaAlways[3:], schemaDefaultGrant, []string{"user store", "AuthnLockouts"})
	assertSchemaLog(t, f, want)
}

func TestStoreSchema_SharedRemedyLineReportedOnce(t *testing.T) {
	t.Parallel()

	const remedy = "create the missing tables with the shipped migrations"
	f := newSchemaFakeStore()
	grantsErr := errors.Join(errors.New("grants table missing"), errors.New(remedy))
	clientsErr := errors.Join(errors.New("clients table missing"), errors.New(remedy))
	f.probes["Grants"].err = grantsErr
	f.probes["Clients"].err = clientsErr

	err := runStoreSchema(t, f, schemaDefaultFlow(f))
	if got := strings.Count(err.Error(), remedy); got != 1 {
		t.Fatalf("remedy appears %d times in %q, want once", got, err)
	}
	if !strings.HasSuffix(err.Error(), remedy) {
		t.Fatalf("err = %q, want the shared line last", err)
	}
	for _, want := range []string{"Clients: clients table missing", "Grants: grants table missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %q, want it to contain %q", err, want)
		}
	}
	if !errors.Is(err, grantsErr) || !errors.Is(err, clientsErr) {
		t.Fatalf("err = %v, want both causes reachable through errors.Is", err)
	}
}
