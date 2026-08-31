package tokenendpoint_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// replayTeardownFixture wires a provider that issues access tokens in
// format, answers introspection, and runs strategy, around the movable
// clock anchor cur.
func replayTeardownFixture(
	tb testing.TB,
	cur *time.Time,
	format op.AccessTokenFormat,
	strategy op.AccessTokenRevocationStrategy,
) *fixture {
	tb.Helper()
	prov := testkit.NewProvider(tb,
		testkit.WithClock(movableClock{cur: cur}),
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAccessTokenFormat(format),
			op.WithAccessTokenRevocationStrategy(strategy),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: *cur},
	}
}

// seedReplayChainWithAccessToken seeds a refresh chain and returns the
// access token the first rotation handed out together with the live
// chain tip. The access token is the credential an attacker who redeemed
// a stolen refresh token walks away with, so it is the one the cascade
// has to retire.
func seedReplayChainWithAccessToken(
	tb testing.TB,
	f *fixture,
	clientID, secret, seed, grantID string,
) (accessToken, tip string) {
	tb.Helper()
	f.seedGrant(tb, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: clientID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(tb, &store.RefreshToken{
		ID:       seed,
		ClientID: clientID,
		Subject:  "user-1",
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})
	resp := f.post(tb, refreshForm(seed, ""), clientID, secret)
	defer func() { _ = resp.Body.Close() }()
	body := decodeJSON(tb, resp)
	accessToken, _ = body["access_token"].(string)
	tip, _ = body["refresh_token"].(string)
	if accessToken == "" || tip == "" {
		tb.Fatalf("rotation returned no credentials: %v", body)
	}
	return accessToken, tip
}

// TestRefresh_ReplayCascadeRetiresOpaqueAccessTokens pins the
// access-token half of the RFC 9700 §2.2.2 cascade for the opaque
// format, under every revocation strategy.
//
// An opaque access token is a substore row, and whether it is still
// redeemable has nothing to do with the strategy that decides how a JWT
// access token is made to stop verifying. A deployment that runs the
// opaque format therefore MUST see the attacker's access token die with
// the replayed chain whichever strategy is configured — otherwise the
// same compromise that retires a chain leaves /introspect answering
// active:true until natural expiry.
func TestRefresh_ReplayCascadeRetiresOpaqueAccessTokens(t *testing.T) {
	t.Parallel()

	strategies := map[string]op.AccessTokenRevocationStrategy{
		"grant_tombstone": op.RevocationStrategyGrantTombstone,
		"jti_registry":    op.RevocationStrategyJTIRegistry,
		"none":            op.RevocationStrategyNone,
	}
	for name, strategy := range strategies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
			f := replayTeardownFixture(t, &cur, op.AccessTokenFormatOpaque, strategy)
			client, secret := f.confidentialClientFixture(t)
			const seed = "rt-replay-opaque"
			grantID := "grant-replay-opaque-" + name

			accessToken, _ := seedReplayChainWithAccessToken(t, f, client.ID, secret, seed, grantID)
			if !introspectActive(t, f, client.ID, secret, accessToken) {
				t.Fatal("the rotation's access token is not active; the fixture is not exercising the opaque path")
			}

			// Past the grace window so the re-presentation is classified as
			// theft rather than as a retry of a lost response.
			cur = cur.Add(2 * time.Minute)
			assertRefreshRefused(t, f, client.ID, secret, seed, "replay")

			if introspectActive(t, f, client.ID, secret, accessToken) {
				t.Error("the access token issued under the replayed grant is still active")
			}
			rec, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), accessToken)
			if err != nil {
				t.Fatalf("OpaqueAccessTokens.Find: %v", err)
			}
			if !rec.Revoked {
				t.Error("opaque access-token row left unrevoked by the replay cascade")
			}
		})
	}
}

// TestRefresh_ReplayCascadeRetiresJWTAccessTokensUnderJTIRegistry pins
// the same obligation for the JTI-registry strategy, where the chain
// cascade used to write no denylist row at all: the JWT access token
// descended from the replayed grant stayed verifiable even though a
// sibling teardown site (an authorization-code replay on the same
// deployment) would have retired it.
func TestRefresh_ReplayCascadeRetiresJWTAccessTokensUnderJTIRegistry(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := replayTeardownFixture(t, &cur, op.AccessTokenFormatJWT, op.RevocationStrategyJTIRegistry)
	client, secret := f.confidentialClientFixture(t)
	const seed = "rt-replay-jwt"
	const grantID = "grant-replay-jwt"

	accessToken, _ := seedReplayChainWithAccessToken(t, f, client.ID, secret, seed, grantID)
	if !introspectActive(t, f, client.ID, secret, accessToken) {
		t.Fatal("the rotation's access token is not active before the replay")
	}

	cur = cur.Add(2 * time.Minute)
	assertRefreshRefused(t, f, client.ID, secret, seed, "replay")

	if introspectActive(t, f, client.ID, secret, accessToken) {
		t.Error("the JWT access token issued under the replayed grant is still active")
	}
}
