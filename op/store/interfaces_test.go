package store_test

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// The fakes below exercise the interface shape declared in op/store. They
// are not exercised at runtime; their job is to fail to compile when a
// signature drifts. The bodies return sentinel errors so the file remains
// vet-clean.

// --- ClientStore / ClientRegistry --------------------------------------------------

type fakeClientStore struct{}

func (fakeClientStore) GetClient(_ context.Context, _ string) (*store.Client, error) {
	return nil, store.ErrNotFound
}

type fakeClientRegistry struct{ fakeClientStore }

func (fakeClientRegistry) RegisterClient(_ context.Context, _ *store.Client) error {
	return store.ErrAlreadyExists
}

func (fakeClientRegistry) UpdateClient(_ context.Context, _ *store.Client) error {
	return store.ErrNotFound
}

func (fakeClientRegistry) DeleteClient(_ context.Context, _ string) error {
	return store.ErrNotFound
}

var (
	_ store.ClientStore    = (*fakeClientStore)(nil)
	_ store.ClientRegistry = (*fakeClientRegistry)(nil)
)

// --- AuthorizationCodeStore --------------------------------------------------------

type fakeAuthCodeStore struct{}

func (fakeAuthCodeStore) Save(_ context.Context, _ *store.AuthorizationCode) error {
	return store.ErrAlreadyExists
}

func (fakeAuthCodeStore) Find(_ context.Context, _ string) (*store.AuthorizationCode, error) {
	return nil, store.ErrNotFound
}

func (fakeAuthCodeStore) Consume(_ context.Context, _ string) (*store.AuthorizationCode, error) {
	return nil, store.ErrAlreadyConsumed
}

var _ store.AuthorizationCodeStore = (*fakeAuthCodeStore)(nil)

// --- RefreshTokenStore -------------------------------------------------------------

type fakeRefreshStore struct{}

func (fakeRefreshStore) Save(_ context.Context, _ *store.RefreshToken) error {
	return store.ErrAlreadyExists
}

func (fakeRefreshStore) Find(_ context.Context, _ string) (*store.RefreshToken, error) {
	return nil, store.ErrNotFound
}

func (fakeRefreshStore) Consume(_ context.Context, _ string) (*store.RefreshToken, error) {
	return nil, store.ErrAlreadyConsumed
}

func (fakeRefreshStore) RevokeChain(_ context.Context, _ string) error {
	return store.ErrNotFound
}

var _ store.RefreshTokenStore = (*fakeRefreshStore)(nil)

// --- GrantStore --------------------------------------------------------------------

type fakeGrantStore struct{}

func (fakeGrantStore) Save(_ context.Context, _ *store.Grant) error {
	return store.ErrAlreadyExists
}

func (fakeGrantStore) Find(_ context.Context, _ string) (*store.Grant, error) {
	return nil, store.ErrNotFound
}

func (fakeGrantStore) FindBySubjectClient(_ context.Context, _, _ string) (*store.Grant, error) {
	return nil, store.ErrNotFound
}

func (fakeGrantStore) Delete(_ context.Context, _ string) error {
	return store.ErrNotFound
}

var _ store.GrantStore = (*fakeGrantStore)(nil)

// --- SessionStore ------------------------------------------------------------------

type fakeSessionStore struct{}

func (fakeSessionStore) Save(_ context.Context, _ *store.Session) error {
	return store.ErrAlreadyExists
}

func (fakeSessionStore) Find(_ context.Context, _ string) (*store.Session, error) {
	return nil, store.ErrNotFound
}

func (fakeSessionStore) Touch(_ context.Context, _ string, _, _ time.Time) error {
	return store.ErrNotFound
}

func (fakeSessionStore) Delete(_ context.Context, _ string) error {
	return store.ErrNotFound
}

func (fakeSessionStore) ListByChooserGroup(_ context.Context, _ string) ([]*store.Session, error) {
	return nil, nil
}

var _ store.SessionStore = (*fakeSessionStore)(nil)

// --- PushedAuthRequestStore --------------------------------------------------------

type fakePARStore struct{}

func (fakePARStore) Save(_ context.Context, _ *store.PushedAuthRequest) error {
	return store.ErrAlreadyExists
}

func (fakePARStore) Find(_ context.Context, _ string) (*store.PushedAuthRequest, error) {
	return nil, store.ErrNotFound
}

func (fakePARStore) Consume(_ context.Context, _ string) (*store.PushedAuthRequest, error) {
	return nil, store.ErrAlreadyConsumed
}

var _ store.PushedAuthRequestStore = (*fakePARStore)(nil)

// --- InteractionStore --------------------------------------------------------------

type fakeInteractionStore struct{}

func (fakeInteractionStore) Save(_ context.Context, _ *store.Interaction) error {
	return store.ErrAlreadyExists
}

func (fakeInteractionStore) Find(_ context.Context, _ string) (*store.Interaction, error) {
	return nil, store.ErrNotFound
}

func (fakeInteractionStore) Delete(_ context.Context, _ string) error {
	return store.ErrNotFound
}

var _ store.InteractionStore = (*fakeInteractionStore)(nil)

// --- ConsumedJTIStore --------------------------------------------------------------

type fakeJTIStore struct{}

func (fakeJTIStore) Mark(_ context.Context, _ string, _ time.Time) error {
	return store.ErrAlreadyConsumed
}

func (fakeJTIStore) Has(_ context.Context, _ string) (bool, error) {
	return false, nil
}

var _ store.ConsumedJTIStore = (*fakeJTIStore)(nil)

// --- UserStore ---------------------------------------------------------------------

type fakeUserStore struct{}

func (fakeUserStore) FindBySubject(_ context.Context, _ string) (*store.User, error) {
	return nil, store.ErrNotFound
}

var _ store.UserStore = (*fakeUserStore)(nil)

// --- Transactional / Tx ------------------------------------------------------------

type fakeTx struct{}

func (fakeTx) AuthorizationCodes() store.AuthorizationCodeStore { return fakeAuthCodeStore{} }
func (fakeTx) Grants() store.GrantStore                         { return fakeGrantStore{} }
func (fakeTx) RefreshTokens() store.RefreshTokenStore           { return fakeRefreshStore{} }
func (fakeTx) Sessions() store.SessionStore                     { return fakeSessionStore{} }
func (fakeTx) PushedAuthRequests() store.PushedAuthRequestStore { return fakePARStore{} }
func (fakeTx) Commit() error                                    { return nil }
func (fakeTx) Rollback() error                                  { return nil }

type fakeTransactional struct{ fakeStore }

func (fakeTransactional) BeginTx(_ context.Context) (store.Tx, error) {
	return fakeTx{}, nil
}

var (
	_ store.Tx            = (*fakeTx)(nil)
	_ store.Transactional = (*fakeTransactional)(nil)
)

// --- Store -------------------------------------------------------------------------

type fakeStore struct{}

func (fakeStore) Clients() store.ClientStore                       { return fakeClientStore{} }
func (fakeStore) AuthorizationCodes() store.AuthorizationCodeStore { return fakeAuthCodeStore{} }
func (fakeStore) RefreshTokens() store.RefreshTokenStore           { return fakeRefreshStore{} }
func (fakeStore) Grants() store.GrantStore                         { return fakeGrantStore{} }
func (fakeStore) Sessions() store.SessionStore                     { return fakeSessionStore{} }
func (fakeStore) PushedAuthRequests() store.PushedAuthRequestStore { return fakePARStore{} }
func (fakeStore) Interactions() store.InteractionStore             { return fakeInteractionStore{} }
func (fakeStore) ConsumedJTIs() store.ConsumedJTIStore             { return fakeJTIStore{} }
func (fakeStore) Users() store.UserStore                           { return fakeUserStore{} }
func (fakeStore) InitialAccessTokens() store.InitialAccessTokenStore {
	return fakeInitialAccessTokenStore{}
}

func (fakeStore) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	return fakeRegistrationAccessTokenStore{}
}

var _ store.Store = (*fakeStore)(nil)

type fakeInitialAccessTokenStore struct{}

func (fakeInitialAccessTokenStore) Put(context.Context, *store.InitialAccessToken) error {
	return nil
}

func (fakeInitialAccessTokenStore) GetByHash(context.Context, string) (*store.InitialAccessToken, error) {
	return nil, store.ErrNotFound
}

func (fakeInitialAccessTokenStore) IncrementUses(context.Context, string) (int, error) {
	return 0, store.ErrNotFound
}
func (fakeInitialAccessTokenStore) Delete(context.Context, string) error { return store.ErrNotFound }

var _ store.InitialAccessTokenStore = (*fakeInitialAccessTokenStore)(nil)

type fakeRegistrationAccessTokenStore struct{}

func (fakeRegistrationAccessTokenStore) Put(context.Context, *store.RegistrationAccessToken) error {
	return nil
}

func (fakeRegistrationAccessTokenStore) GetByClientID(context.Context, string) (*store.RegistrationAccessToken, error) {
	return nil, store.ErrNotFound
}

func (fakeRegistrationAccessTokenStore) Delete(context.Context, string) error {
	return store.ErrNotFound
}

var _ store.RegistrationAccessTokenStore = (*fakeRegistrationAccessTokenStore)(nil)
