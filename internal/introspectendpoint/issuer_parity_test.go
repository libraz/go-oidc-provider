package introspectendpoint_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestHandler_ActiveResponsesCarryIssuerOnEveryBranch pins that "iss"
// is present whichever record type answered the introspection.
//
// A resource server that validates the issuer of an introspection
// response is doing what RFC 7662 §2.2 lists "iss" for, and it has no
// way to know which token format the OP was configured with. When the
// JWT branch was the only one projecting "iss", flipping the
// deployment's access-token format from JWT to opaque broke every such
// resource server without a single line changing on either side.
func TestHandler_ActiveResponsesCarryIssuerOnEveryBranch(t *testing.T) {
	t.Parallel()

	t.Run("jwt access token", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		client, secret := f.confidentialClient(t, "client-conf-introspect")
		token := f.signAccessToken(t, nil)

		resp := f.post(t, url.Values{"token": {token}}, client.ID, secret)
		defer resp.Body.Close()
		assertIssuerEcho(t, f, resp)
	})

	t.Run("opaque access token", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		client, secret := f.confidentialClient(t, "client-opaque-iss")
		rec := &store.OpaqueAccessToken{
			ID:        "opaque-iss-1",
			ClientID:  client.ID,
			Subject:   "user-opaque",
			Scope:     []string{"openid"},
			IssuedAt:  f.clock.now,
			ExpiresAt: f.clock.now.Add(time.Hour),
		}
		f.saveOpaqueAccessToken(t, rec)

		resp := f.post(t, url.Values{"token": {rec.ID}}, client.ID, secret)
		defer resp.Body.Close()
		assertIssuerEcho(t, f, resp)
	})

	t.Run("refresh token", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		client, secret := f.confidentialClient(t, "client-refresh-iss")
		rec := &store.RefreshToken{
			ID:        "refresh-iss-1",
			ClientID:  client.ID,
			Subject:   "user-refresh",
			GrantID:   "grant-refresh-iss-1",
			Scope:     []string{"openid"},
			CreatedAt: f.clock.now,
			ExpiresAt: f.clock.now.Add(24 * time.Hour),
		}
		f.saveRefreshToken(t, rec)

		resp := f.post(t, url.Values{"token": {rec.ID}}, client.ID, secret)
		defer resp.Body.Close()
		assertIssuerEcho(t, f, resp)
	})
}

// assertIssuerEcho fails unless the response is active and its "iss"
// member is the OP's issuer URL.
func assertIssuerEcho(tb testing.TB, f *fixture, resp *http.Response) {
	tb.Helper()
	got := decodeJSON(tb, resp)
	if got["active"] != true {
		tb.Fatalf("active=%v want true: %v", got["active"], got)
	}
	if got["iss"] != f.prov.Issuer {
		tb.Errorf("iss=%v want %q", got["iss"], f.prov.Issuer)
	}
}

// TestHandler_OpaqueBranchesWithholdJTI pins the deliberate asymmetry
// that accompanies the "iss" parity above. The only identifier an
// opaque record holds is the credential the client presented, so
// projecting it as "jti" would echo a live bearer token into a
// response body that resource servers routinely log.
func TestHandler_OpaqueBranchesWithholdJTI(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-jti")
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-jti-must-not-echo",
		ClientID:  client.ID,
		Subject:   "user-opaque",
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.post(t, url.Values{"token": {rec.ID}}, client.ID, secret)
	defer resp.Body.Close()

	got := decodeJSON(t, resp)
	if got["active"] != true {
		t.Fatalf("active=%v want true: %v", got["active"], got)
	}
	if jti, ok := got["jti"]; ok {
		t.Errorf("response carries jti=%v; the opaque branch has no identifier other than the token itself", jti)
	}
}
