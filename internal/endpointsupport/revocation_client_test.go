package endpointsupport_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fakeClientStore answers GetClient with a fixed outcome and counts the
// calls, so a test can pin both the answer and whether the lookup was
// attempted at all.
type fakeClientStore struct {
	err   error
	calls int
}

func (f *fakeClientStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &store.Client{ID: id}, nil
}

// deletedClientStore is the registry state a client deletion leaves
// behind.
func deletedClientStore() *fakeClientStore {
	return &fakeClientStore{err: store.ErrNotFound}
}

func grantBoundClaims() *tokens.AccessTokenClaims {
	return &tokens.AccessTokenClaims{JTI: "at-1", GrantID: "grant-1", ClientID: "client-1"}
}

// A deleted client must stop its already-issued JWT access tokens. No
// other mechanism can: the tombstone substore is keyed on grant_id and a
// deletion produces no list of grants, so without this probe the token
// stays live until exp on the default strategy.
func TestJWTAccessTokenRevoked_DeletedClientRevokesTheToken(t *testing.T) {
	t.Parallel()

	clients := deletedClientStore()
	grants := &fakeGrantRevocations{}
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		GrantRevocations:   grants,
		Clients:            clients,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, grantBoundClaims())
	if !ok || !revoked {
		t.Fatalf("revoked=%v ok=%v want true/true", revoked, ok)
	}
	if len(grants.isRevokedWith) != 0 {
		t.Errorf("tombstone substore consulted %d times; a deleted client settles the answer alone", len(grants.isRevokedWith))
	}
}

// The same holds for a client_credentials token, which carries no grant
// at all — the case a per-grant cascade could never have covered.
func TestJWTAccessTokenRevoked_DeletedClientRevokesAGrantlessToken(t *testing.T) {
	t.Parallel()

	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		AccessTokens:       &fakeATRegistry{findErr: store.ErrNotFound},
		Clients:            deletedClientStore(),
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, &tokens.AccessTokenClaims{JTI: "at-cc", ClientID: "client-1"})
	if !ok || !revoked {
		t.Fatalf("revoked=%v ok=%v want true/true", revoked, ok)
	}
}

// The JTI-registry strategy gets the same gate; the two strategies
// differ in how a token is denylisted, not in whether its client has to
// exist.
func TestJWTAccessTokenRevoked_DeletedClientRevokesUnderTheJTIStrategy(t *testing.T) {
	t.Parallel()

	registry := &fakeATRegistry{findErr: store.ErrNotFound}
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		AccessTokens:       registry,
		Clients:            deletedClientStore(),
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
	}, grantBoundClaims())
	if !ok || !revoked {
		t.Fatalf("revoked=%v ok=%v want true/true", revoked, ok)
	}
}

// RevocationStrategyNone declares that no per-token state is consulted.
// Adding a registry read behind it would break that declaration, so the
// probe must not run — asserted on the call count rather than on the
// outcome, which a skipped lookup and a successful one share.
func TestJWTAccessTokenRevoked_StrategyNoneDoesNotProbeTheRegistry(t *testing.T) {
	t.Parallel()

	clients := deletedClientStore()
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		Clients:            clients,
		RevocationStrategy: store.RevocationStrategyNone,
	}, grantBoundClaims())
	if !ok || revoked {
		t.Fatalf("revoked=%v ok=%v want false/true", revoked, ok)
	}
	if clients.calls != 0 {
		t.Errorf("GetClient called %d times under RevocationStrategyNone; want 0", clients.calls)
	}
}

// A live client leaves the decision to the strategy's own substores.
func TestJWTAccessTokenRevoked_LiveClientDefersToTheStrategy(t *testing.T) {
	t.Parallel()

	clients := &fakeClientStore{}
	grants := &fakeGrantRevocations{}
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		GrantRevocations:   grants,
		Clients:            clients,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, grantBoundClaims())
	if !ok || revoked {
		t.Fatalf("revoked=%v ok=%v want false/true", revoked, ok)
	}
	if len(grants.isRevokedWith) != 1 {
		t.Errorf("tombstone substore consulted %d times, want 1", len(grants.isRevokedWith))
	}
}

// A registry fault is not a deletion. Reporting it as unresolved leaves
// the posture to the caller, which differs per endpoint: userinfo fails
// the request, introspection answers inactive.
func TestJWTAccessTokenRevoked_ClientLookupFaultIsUnresolved(t *testing.T) {
	t.Parallel()

	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		GrantRevocations:   &fakeGrantRevocations{},
		Clients:            &fakeClientStore{err: errors.New("backend down")},
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, grantBoundClaims())
	if ok || revoked {
		t.Fatalf("revoked=%v ok=%v want false/false", revoked, ok)
	}
}

// A deployment that wires no registry, and a token minted outside one,
// are not evidence of a deletion — neither may fail closed.
func TestJWTAccessTokenRevoked_NoRegistryOrNoClientIDSkipsTheProbe(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		clients store.ClientStore
		claims  *tokens.AccessTokenClaims
	}{
		{name: "no registry wired", clients: nil, claims: grantBoundClaims()},
		{
			name:    "token carries no client_id",
			clients: deletedClientStore(),
			claims:  &tokens.AccessTokenClaims{JTI: "at-1", GrantID: "grant-1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
				GrantRevocations:   &fakeGrantRevocations{},
				Clients:            tc.clients,
				RevocationStrategy: store.RevocationStrategyGrantTombstone,
			}, tc.claims)
			if !ok || revoked {
				t.Fatalf("revoked=%v ok=%v want false/true", revoked, ok)
			}
		})
	}
}
