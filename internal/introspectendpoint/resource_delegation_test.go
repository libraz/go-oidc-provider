package introspectendpoint_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// The resource identifiers the delegation fixture registers. delegated
// names the gateway as an introspection client; foreign does not, so it
// doubles as the negative control for audience scoping.
const (
	delegatedResource = "https://api.example.com/orders"
	foreignResource   = "https://api.example.com/billing"
)

const (
	gatewayClientID = "rs-gateway"
	tokenClientID   = "app-rp"
)

// delegationFixture wires an OP whose orders API delegates introspection
// to a gateway client, plus the app whose tokens the gateway will read.
// The two clients share a secret spelling because only the client_id
// distinguishes them at the endpoint.
type delegationFixture struct {
	*fixture
	secret string
}

// newDelegationFixture builds the provider, registers both clients, and
// returns a fixture whose helpers post as either of them.
func newDelegationFixture(tb testing.TB) *delegationFixture {
	tb.Helper()
	const secret = "delegation-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithProtectedResources(op.ProtectedResource{
				Resource:             delegatedResource,
				IntrospectionClients: []string{gatewayClientID},
			}, op.ProtectedResource{
				Resource: foreignResource,
			}),
		),
	)
	for _, id := range []string{gatewayClientID, tokenClientID} {
		prov.RegisterClient(tb, testkit.ClientFixture{
			ID:                      id,
			SecretHash:              hash,
			TokenEndpointAuthMethod: "client_secret_basic",
			Scopes:                  []string{"openid", "profile"},
			Resources:               []string{delegatedResource, foreignResource},
		})
	}
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/introspect",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
	return &delegationFixture{fixture: f, secret: secret}
}

// introspectAs posts token to /introspect authenticated as callerID and
// reports whether the answer was active.
func (f *delegationFixture) introspectAs(tb testing.TB, callerID, token string) bool {
	tb.Helper()
	resp := f.post(tb, url.Values{"token": {token}}, callerID, f.secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("status=%d want 200", resp.StatusCode)
	}
	active, _ := decodeJSON(tb, resp)["active"].(bool)
	return active
}

// jwtFor mints a JWT access token issued to tokenClientID and addressed
// to the supplied audience.
func (f *delegationFixture) jwtFor(t *testing.T, audience string) string {
	t.Helper()
	return f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = tokenClientID
		c.Audience = []string{audience}
		c.JTI = "at-delegation-" + audience
	})
}

// TestHandler_ResourceServerIntrospectsAnotherClientsToken covers what
// RFC 7662 exists for: a resource server reading the token a caller
// presented to it, which was issued to that caller and not to the
// resource server. Before the delegation existed, an RS that followed
// this OP's own protected-resource metadata to the introspection
// endpoint authenticated successfully and received {"active": false} for
// every token it would ever see.
func TestHandler_ResourceServerIntrospectsAnotherClientsToken(t *testing.T) {
	t.Parallel()

	t.Run("jwt access token", func(t *testing.T) {
		t.Parallel()

		f := newDelegationFixture(t)
		if !f.introspectAs(t, gatewayClientID, f.jwtFor(t, delegatedResource)) {
			t.Error("delegated resource server got active=false for a token addressed to its resource")
		}
	})

	t.Run("opaque access token", func(t *testing.T) {
		t.Parallel()

		f := newDelegationFixture(t)
		rec := &store.OpaqueAccessToken{
			ID:        "opaque-delegated-1",
			ClientID:  tokenClientID,
			Subject:   "user-delegated",
			Scope:     []string{"openid"},
			Audience:  delegatedResource,
			IssuedAt:  f.clock.now,
			ExpiresAt: f.clock.now.Add(time.Hour),
		}
		f.saveOpaqueAccessToken(t, rec)

		if !f.introspectAs(t, gatewayClientID, rec.ID) {
			t.Error("delegated resource server got active=false for an opaque token addressed to its resource")
		}
	})
}

// TestHandler_DelegationIsScopedToTheResource pins the least-privilege
// half of the design. Registering a gateway for one API must not hand it
// visibility over every client's tokens — only over the ones actually
// addressed to the resource it speaks for.
func TestHandler_DelegationIsScopedToTheResource(t *testing.T) {
	t.Parallel()

	f := newDelegationFixture(t)
	if f.introspectAs(t, gatewayClientID, f.jwtFor(t, foreignResource)) {
		t.Error("gateway read a token addressed to a resource it is not registered for")
	}
}

// TestHandler_UndelegatedClientStillSeesOnlyItsOwnTokens pins that the
// default posture is unchanged. A client the embedder never named stays
// same-client-only, so adding the feature cannot loosen an existing
// deployment that does not opt in.
func TestHandler_UndelegatedClientStillSeesOnlyItsOwnTokens(t *testing.T) {
	t.Parallel()

	f := newDelegationFixture(t)
	// tokenClientID owns the token; the assertion is that the *other*
	// direction stays closed, so introspect as the app for a token the
	// gateway would own.
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = gatewayClientID
		c.Audience = []string{delegatedResource}
		c.JTI = "at-undelegated-1"
	})
	if f.introspectAs(t, tokenClientID, token) {
		t.Error("a client that is not a registered introspection client read another client's token")
	}
}

// TestHandler_DelegationDoesNotCoverRefreshTokens pins the deliberate
// exclusion. A refresh token is the client's own credential, not
// something a resource server is ever presented with, so widening the
// owner check for it would hand the gateway a credential it has no use
// for and every reason not to hold.
func TestHandler_DelegationDoesNotCoverRefreshTokens(t *testing.T) {
	t.Parallel()

	f := newDelegationFixture(t)
	rec := &store.RefreshToken{
		ID:        "refresh-delegated-1",
		ClientID:  tokenClientID,
		Subject:   "user-delegated",
		GrantID:   "grant-delegated-1",
		Scope:     []string{"openid"},
		Resource:  delegatedResource,
		CreatedAt: f.clock.now,
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
	}
	f.saveRefreshToken(t, rec)

	if f.introspectAs(t, gatewayClientID, rec.ID) {
		t.Error("gateway read another client's refresh token")
	}
	// Control: the owning client still can, so the row above is not
	// passing because the record was unreadable for some other reason.
	if !f.introspectAs(t, tokenClientID, rec.ID) {
		t.Error("the owning client can no longer introspect its own refresh token")
	}
}
