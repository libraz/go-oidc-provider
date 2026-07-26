package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/libraz/go-oidc-provider/op/store"
)

// tableWaitTimeout bounds [Store.CreateTables] while it waits for a
// freshly created table to become active. DynamoDB Local flips to
// ACTIVE almost immediately; the real service takes seconds.
const tableWaitTimeout = 2 * time.Minute

// API is the subset of the DynamoDB client the adapter calls. Taking an
// interface rather than the concrete *dynamodb.Client keeps the adapter
// testable without a network and documents its blast radius: these are
// the only operations an IAM policy has to permit.
type API interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	CreateTable(context.Context, *dynamodb.CreateTableInput, ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	UpdateTimeToLive(context.Context, *dynamodb.UpdateTimeToLiveInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateTimeToLiveOutput, error)
}

// Clock returns the wall-clock time the adapter uses to evaluate record
// expiry. It mirrors the other adapters' Clock so backends can be
// swapped without re-wiring construction.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// Now is the wall-clock fallback when no [WithClock] override is
// supplied. The adapter is a sub-module without access to
// internal/timex; embedders inject their clock through [WithClock].
//
//nolint:forbidigo // sub-module fallback; embedders override via WithClock.
func (systemClock) Now() time.Time { return time.Now() }

// Option configures a [Store] at construction time. Options are applied
// in order; later calls take precedence.
type Option func(*config)

type config struct {
	clock     Clock
	prefix    string
	overrides map[string]string
}

// WithClock injects the wall-clock implementation used to evaluate
// record expiry. The default is the system wall clock.
func WithClock(c Clock) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.clock = c
		}
	}
}

// WithTablePrefix sets the prefix every default table name carries. The
// default is "oidc_", producing names like "oidc_authorization_codes".
// A deployment that runs several OPs against one AWS account gives each
// its own prefix.
func WithTablePrefix(prefix string) Option {
	return func(cfg *config) { cfg.prefix = prefix }
}

// WithNaming overrides individual physical table names. Keys are the
// logical names the adapter uses internally ("clients",
// "authorization_codes", "refresh_tokens", "access_tokens",
// "opaque_access_tokens", "grant_revocations", "grants", "sessions",
// "par_records", "interactions", "consumed_jtis", "users",
// "initial_access_tokens", "registration_access_tokens", "op_metadata",
// "device_codes", "ciba_requests", "totp_secrets", "passkeys",
// "recovery_codes", "email_otps", "authn_lockouts"); values are the
// physical table names to use. An override replaces the prefixed
// default outright. Unknown keys cause [New] to return an error so
// typos surface at construction time.
func WithNaming(overrides map[string]string) Option {
	return func(cfg *config) {
		if cfg.overrides == nil {
			cfg.overrides = make(map[string]string, len(overrides))
		}
		for k, v := range overrides {
			cfg.overrides[k] = v
		}
	}
}

// Store is the DynamoDB adapter. It satisfies [store.Store],
// [store.ClientRegistry], [store.StaticClientReconciler], and
// [store.Transactional].
//
// Experimental: see the package documentation.
type Store struct {
	api   API
	names nameMap
	clock Clock

	clientsImpl            *clientStore
	authCodesImpl          *authCodeStore
	refreshesImpl          *refreshStore
	accessTokensImpl       *accessTokenStore
	opaqueAccessTokensImpl *opaqueAccessTokenStore
	grantRevocationsImpl   *grantRevocationStore
	grantsImpl             *grantStore
	sessionsImpl           *sessionStore
	parsImpl               *parStore
	interactionsImpl       *interactionStore
	jtisImpl               *jtiStore
	usersImpl              *userStore
	iatsImpl               *iatStore
	ratsImpl               *ratStore
	metadataImpl           *metadataStore
	deviceCodesImpl        *deviceCodeStore
	cibaRequestsImpl       *cibaRequestStore

	totpsImpl         *totpStore
	passkeysImpl      *passkeyStore
	recoveryCodesImpl *recoveryStore
	emailOTPsImpl     *emailOTPStore
	authnLockoutsImpl *authnLockoutStore
}

// New constructs a Store that issues requests through api. The caller
// owns the client, its credentials, and its region; the adapter never
// constructs one itself.
//
// Tables are not created here. Call [Store.CreateTables] in development
// and tests, or provision from [Store.TableDefinitions] in production.
func New(api API, opts ...Option) (*Store, error) {
	if api == nil {
		return nil, errors.New("oidcdynamo: api is nil")
	}
	cfg := &config{clock: systemClock{}, prefix: "oidc_"}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	names := defaultNames(cfg.prefix)
	if err := names.applyOverrides(cfg.overrides); err != nil {
		return nil, err
	}
	if err := names.validateAll(); err != nil {
		return nil, err
	}
	s := &Store{api: api, names: names, clock: cfg.clock}
	s.attachSubstores()
	return s, nil
}

func (s *Store) attachSubstores() {
	s.clientsImpl = &clientStore{parent: s}
	s.authCodesImpl = &authCodeStore{parent: s}
	s.refreshesImpl = &refreshStore{parent: s}
	s.accessTokensImpl = &accessTokenStore{parent: s}
	s.opaqueAccessTokensImpl = &opaqueAccessTokenStore{parent: s}
	s.grantRevocationsImpl = &grantRevocationStore{parent: s}
	s.grantsImpl = &grantStore{parent: s}
	s.sessionsImpl = &sessionStore{parent: s}
	s.parsImpl = &parStore{parent: s}
	s.interactionsImpl = &interactionStore{parent: s}
	s.jtisImpl = &jtiStore{parent: s}
	s.usersImpl = &userStore{parent: s}
	s.iatsImpl = &iatStore{parent: s}
	s.ratsImpl = &ratStore{parent: s}
	s.metadataImpl = &metadataStore{parent: s}
	s.deviceCodesImpl = &deviceCodeStore{parent: s}
	s.cibaRequestsImpl = &cibaRequestStore{parent: s}
	s.totpsImpl = &totpStore{parent: s}
	s.passkeysImpl = &passkeyStore{parent: s}
	s.recoveryCodesImpl = &recoveryStore{parent: s}
	s.emailOTPsImpl = &emailOTPStore{parent: s}
	s.authnLockoutsImpl = &authnLockoutStore{parent: s}
}

func (s *Store) now() time.Time { return s.clock.Now() }

// Clients implements [store.Store].
func (s *Store) Clients() store.ClientStore { return s.clientsImpl }

// AuthorizationCodes implements [store.Store].
func (s *Store) AuthorizationCodes() store.AuthorizationCodeStore { return s.authCodesImpl }

// RefreshTokens implements [store.Store].
func (s *Store) RefreshTokens() store.RefreshTokenStore { return s.refreshesImpl }

// Grants implements [store.Store].
func (s *Store) Grants() store.GrantStore { return s.grantsImpl }

// Sessions implements [store.Store].
func (s *Store) Sessions() store.SessionStore { return s.sessionsImpl }

// PushedAuthRequests implements [store.Store].
func (s *Store) PushedAuthRequests() store.PushedAuthRequestStore { return s.parsImpl }

// Interactions implements [store.Store].
func (s *Store) Interactions() store.InteractionStore { return s.interactionsImpl }

// ConsumedJTIs implements [store.Store].
func (s *Store) ConsumedJTIs() store.ConsumedJTIStore { return s.jtisImpl }

// Users implements [store.Store].
func (s *Store) Users() store.UserStore { return s.usersImpl }

// InitialAccessTokens implements [store.Store].
func (s *Store) InitialAccessTokens() store.InitialAccessTokenStore { return s.iatsImpl }

// RegistrationAccessTokens implements [store.Store].
func (s *Store) RegistrationAccessTokens() store.RegistrationAccessTokenStore { return s.ratsImpl }

// AccessTokens implements [store.Store].
func (s *Store) AccessTokens() store.AccessTokenRegistry { return s.accessTokensImpl }

// OpaqueAccessTokens implements [store.Store].
func (s *Store) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return s.opaqueAccessTokensImpl }

// GrantRevocations implements [store.Store].
func (s *Store) GrantRevocations() store.GrantRevocationStore { return s.grantRevocationsImpl }

// Metadata implements [store.Store].
func (s *Store) Metadata() store.MetadataStore { return s.metadataImpl }

// DeviceCodes implements [store.Store].
func (s *Store) DeviceCodes() store.DeviceCodeStore { return s.deviceCodesImpl }

// CIBARequests implements [store.Store].
func (s *Store) CIBARequests() store.CIBARequestStore { return s.cibaRequestsImpl }

// The authentication-factor substores sit outside [store.Store]: the
// login flow receives them directly. The accessor names match the inmem
// and SQL adapters so the three are drop-in interchangeable.

// TOTPs returns the [store.TOTPStore] backed by the totp_secrets table.
func (s *Store) TOTPs() store.TOTPStore { return s.totpsImpl }

// Passkeys returns the [store.PasskeyStore] backed by the passkeys table.
func (s *Store) Passkeys() store.PasskeyStore { return s.passkeysImpl }

// RecoveryCodes returns the [store.RecoveryStore] backed by the
// recovery_codes table.
func (s *Store) RecoveryCodes() store.RecoveryStore { return s.recoveryCodesImpl }

// EmailOTPs returns the [store.EmailOTPStore] backed by the email_otps
// table.
func (s *Store) EmailOTPs() store.EmailOTPStore { return s.emailOTPsImpl }

// AuthnLockouts returns the [store.AuthnLockoutStore] backed by the
// authn_lockouts table.
func (s *Store) AuthnLockouts() store.AuthnLockoutStore { return s.authnLockoutsImpl }

// GetClient implements [store.ClientStore] on the aggregate so a caller
// holding a *Store can reach the client substore without a hop.
func (s *Store) GetClient(ctx context.Context, id string) (*store.Client, error) {
	return s.clientsImpl.GetClient(ctx, id)
}

// RegisterClient implements [store.ClientRegistry].
func (s *Store) RegisterClient(ctx context.Context, c *store.Client) error {
	return s.clientsImpl.RegisterClient(ctx, c)
}

// UpdateClient implements [store.ClientRegistry].
func (s *Store) UpdateClient(ctx context.Context, c *store.Client) error {
	return s.clientsImpl.UpdateClient(ctx, c)
}

// DeleteClient implements [store.ClientRegistry].
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	return s.clientsImpl.DeleteClient(ctx, id)
}

// ReconcileStaticClients implements [store.StaticClientReconciler].
func (s *Store) ReconcileStaticClients(ctx context.Context, clients []*store.Client) error {
	return s.clientsImpl.ReconcileStaticClients(ctx, clients)
}

var (
	_ store.Store                  = (*Store)(nil)
	_ store.ClientRegistry         = (*Store)(nil)
	_ store.StaticClientReconciler = (*Store)(nil)
	_ store.Transactional          = (*Store)(nil)
)
