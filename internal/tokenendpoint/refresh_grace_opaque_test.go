package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	httptestutil "github.com/libraz/go-oidc-provider/internal/testutil/httptest"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// introspectActive asks the OP whether token is still usable, using the
// same endpoint a resource server consults. The opaque format exists so
// that answer is authoritative on every request, which makes it the
// honest way to ask "is this credential live?".
func introspectActive(tb testing.TB, f *fixture, clientID, secret, token string) bool {
	tb.Helper()
	resp := httptestutil.PostForm(
		tb,
		f.prov.HTTPClient(nil),
		f.prov.Server.URL+"/oidc/introspect",
		url.Values{"token": {token}},
		clientID,
		secret,
	)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("POST /introspect status=%d want 200, body=%v", resp.StatusCode, decodeJSON(tb, resp))
	}
	active, _ := decodeJSON(tb, resp)["active"].(bool)
	return active
}

// graceOpaqueFixture wires a provider that issues opaque access tokens,
// answers introspection, and speaks DPoP, so a grace retry can be driven
// over a sender-constrained chain and its result observed the way a
// resource server would observe it. cur is the movable clock anchor the
// caller advances to step inside the grace window.
func graceOpaqueFixture(tb testing.TB, cur *time.Time) *fixture {
	tb.Helper()
	prov := testkit.NewProvider(tb,
		testkit.WithClock(movableClock{cur: cur}),
		testkit.WithOptions(
			op.WithFeature(feature.DPoP),
			op.WithFeature(feature.Introspect),
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: *cur},
	}
}

// TestRefresh_OpaqueFormat_SenderConstrainedGraceRetryRevokesPriorAT pins
// the one-live-token invariant across the fork in the refresh exit paths.
// A sender-constrained grace retry does not replay the cached access
// token — it mints a fresh one bound to the key the retry presents — and a
// mint carries the same obligation the rotation's mint carries: every
// opaque access token already issued under the grant is retired first.
// Without that, a client whose response was lost leaves two live bearer
// credentials under one grant, and the stolen-token window the opaque
// format is meant to collapse to clock-skew reopens for the full token
// lifetime on whichever one the attacker holds.
func TestRefresh_OpaqueFormat_SenderConstrainedGraceRetryRevokesPriorAT(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := graceOpaqueFixture(t, &cur)
	client, secret := f.confidentialClientFixture(t)

	const refreshID = "rt-opaque-grace"
	const grantID = "grant-opaque-grace"
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	// Left unbound so the confidential client may present a different DPoP
	// key on the retry, which is what forces the re-mint rather than a
	// verbatim replay.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	keyA := newDPoPKey(t)
	keyB := newDPoPKey(t)

	firstProof := makeDPoPProof(t, keyA, "POST", f.endpoint, cur, "jti-opaque-grace-A", "")
	first := postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, refreshForm(refreshID, ""), client.ID, secret, firstProof)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d want 200, body=%v", first.StatusCode, decodeJSON(t, first))
	}
	firstBody := decodeJSON(t, first)
	priorAT, _ := firstBody["access_token"].(string)
	if priorAT == "" {
		t.Fatal("first refresh returned no access_token")
	}
	if !introspectActive(t, f, client.ID, secret, priorAT) {
		t.Fatal("access token from the first rotation is not active; the fixture is not exercising the opaque path")
	}

	// Step inside the grace window and replay the ORIGINAL refresh token
	// with a different DPoP key, the shape RFC 9700 §2.2.2 recovery exists
	// for: the client never saw the first response.
	cur = cur.Add(5 * time.Second)
	retryProof := makeDPoPProof(t, keyB, "POST", f.endpoint, cur, "jti-opaque-grace-B", "")
	second := postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, refreshForm(refreshID, ""), client.ID, secret, retryProof)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("grace status=%d want 200, body=%v", second.StatusCode, decodeJSON(t, second))
	}
	graceAT, _ := decodeJSON(t, second)["access_token"].(string)
	if graceAT == "" {
		t.Fatal("grace retry returned no access_token")
	}
	if graceAT == priorAT {
		t.Fatal("sender-constrained grace must re-mint rather than replay the originally-bound access token")
	}

	if introspectActive(t, f, client.ID, secret, priorAT) {
		t.Error("access token from the first rotation is still active after the grace re-mint; two live credentials under one grant")
	}
	if !introspectActive(t, f, client.ID, secret, graceAT) {
		t.Error("the access token the grace retry handed back is not active")
	}

	// The wire answer above is the contract; the rows behind it say which
	// way the cascade ran, so a future backend that reports inactive for
	// the wrong reason is not mistaken for a passing test.
	prior, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), priorAT)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(prior): %v", err)
	}
	if !prior.Revoked {
		t.Errorf("prior opaque AT Revoked=%v want true", prior.Revoked)
	}
	fresh, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), graceAT)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(grace): %v", err)
	}
	if fresh.Revoked {
		t.Errorf("re-minted opaque AT Revoked=%v want false", fresh.Revoked)
	}
	if fresh.GrantID != grantID {
		t.Errorf("re-minted opaque AT GrantID=%q want %q", fresh.GrantID, grantID)
	}
}

// TestRefresh_OpaqueFormat_BearerGraceRetryKeepsCachedAccessTokenLive is
// the other half of the invariant. A bearer grace retry mints nothing —
// it replays the cached response verbatim — so it has no prior token to
// retire: the access token it hands back IS the one the rotation issued,
// and revoking "the prior token" there would hand the client a credential
// the OP had just killed. The one-live-token property holds by
// degeneration rather than by cascade.
func TestRefresh_OpaqueFormat_BearerGraceRetryKeepsCachedAccessTokenLive(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := graceOpaqueFixture(t, &cur)
	client, secret := f.confidentialClientFixture(t)

	const refreshID = "rt-opaque-grace-bearer"
	const grantID = "grant-opaque-grace-bearer"
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	first := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d want 200, body=%v", first.StatusCode, decodeJSON(t, first))
	}
	rotatedAT, _ := decodeJSON(t, first)["access_token"].(string)
	if rotatedAT == "" {
		t.Fatal("first refresh returned no access_token")
	}

	cur = cur.Add(5 * time.Second)
	second := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("grace status=%d want 200, body=%v", second.StatusCode, decodeJSON(t, second))
	}
	replayedAT, _ := decodeJSON(t, second)["access_token"].(string)
	if replayedAT != rotatedAT {
		t.Fatalf("bearer grace access_token=%q want the cached %q", replayedAT, rotatedAT)
	}
	if !introspectActive(t, f, client.ID, secret, replayedAT) {
		t.Error("bearer grace replayed an access token the OP had revoked; the client is handed a dead credential")
	}
}
