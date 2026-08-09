package grantmgmtendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/grantmgmtendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// gmAssertionAudience stands in for the OP's token-endpoint URL, which
// is the audience the OP wires into its shared assertion verifier.
const gmAssertionAudience = "https://op.test/oidc/token"

const gmPKJWTClientID = "client-gm-pkjwt"

const gmPKJWTKeyID = "rp-gm-kid"

// staticJWKS resolves one fixed key set for every client, standing in
// for the OP's registry-backed JWKS resolver.
type staticJWKS struct{ keys *josev4.JSONWebKeySet }

func (r staticJWKS) JWKS(_ context.Context, _ string) (*josev4.JSONWebKeySet, error) {
	return r.keys, nil
}

// pkjwtFixture builds a grant-management fixture whose confidential
// client authenticates with private_key_jwt: both operations enabled,
// an ES256 assertion verifier wired, and the client-auth policy pinned
// to private_key_jwt the way a FAPI 2.0 profile pins it. Returns the
// fixture and the private key the caller signs assertions with.
func pkjwtFixture(tb testing.TB) (*fixture, *ecdsa.PrivateKey) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	resolver := staticJWKS{keys: &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     gmPKJWTKeyID,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}}}}

	f := newFixture(tb, func(d *grantmgmtendpoint.Deps) {
		clk, ok := d.Clock.(fixedClock)
		if !ok {
			tb.Fatalf("fixture clock has type %T, want fixedClock", d.Clock)
		}
		d.QueryEnabled = true
		d.RevokeEnabled = true
		d.AssertionVerifier = &clientauth.PrivateKeyJWTVerifier{
			Resolver: resolver,
			JTIStore: inmem.New(inmem.WithClock(clk)).ConsumedJTIs(),
			Audience: gmAssertionAudience,
			Clock:    clk.Now,
		}
		d.AllowedClientAuthMethods = []clientauth.Method{clientauth.MethodPrivateKeyJWT}
	})

	jwksRaw, err := json.Marshal(resolver.keys)
	if err != nil {
		tb.Fatalf("Marshal JWKS: %v", err)
	}
	//nolint:gosec // G101 false positive: "private_key_jwt" is the OIDC auth-method name, not a credential.
	if err := f.store.RegisterClient(context.Background(), &store.Client{
		ID:                      gmPKJWTClientID,
		TokenEndpointAuthMethod: "private_key_jwt",
		Scopes:                  []string{"openid"},
		JWKs:                    jwksRaw,
	}); err != nil {
		tb.Fatalf("RegisterClient: %v", err)
	}
	return f, priv
}

// seedPKJWTGrant persists a grant owned by the private_key_jwt client.
func (f *fixture) seedPKJWTGrant(tb testing.TB, id string) {
	tb.Helper()
	if err := f.store.Grants().Save(context.Background(), &store.Grant{
		ID:        id,
		Subject:   "user-gm",
		ClientID:  gmPKJWTClientID,
		Scope:     []string{"openid", "email"},
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		tb.Fatalf("Grants.Save: %v", err)
	}
}

// signGMAssertion mints an ES256 client_assertion for the fixture's
// private_key_jwt client.
func signGMAssertion(tb testing.TB, f *fixture, priv *ecdsa.PrivateKey, jti string) string {
	tb.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       priv,
				KeyID:     gmPKJWTKeyID,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		tb.Fatalf("NewSigner ES256: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": gmPKJWTClientID,
		"sub": gmPKJWTClientID,
		"aud": gmAssertionAudience,
		"jti": jti,
		"iat": f.clock.now.Unix(),
		"exp": f.clock.now.Add(2 * time.Minute).Unix(),
	}).Serialize()
	if err != nil {
		tb.Fatalf("Serialize ES256: %v", err)
	}
	return tok
}

// doPKJWT issues a bodyless grant-management request that authenticates
// through the query string, the only channel a GET / DELETE has.
func (f *fixture) doPKJWT(tb testing.TB, method, grantID, assertion string) *http.Response {
	tb.Helper()
	query := url.Values{}
	query.Set("client_id", gmPKJWTClientID)
	query.Set("client_assertion_type", clientauth.AssertionType)
	query.Set("client_assertion", assertion)
	target := f.endpoint + "/" + grantID + "?" + query.Encode()
	req, err := http.NewRequestWithContext(context.Background(), method, target, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// TestHandler_PrivateKeyJWT_QueryOperation drives the query (GET)
// operation end to end for a client that authenticates with
// private_key_jwt. The assertion travels in the query string because a
// GET has no form body to put it in, and the endpoint MUST honour it:
// otherwise grant management is unreachable for exactly the profiles
// that mandate private_key_jwt, even though the OP advertises the
// feature in its discovery document.
func TestHandler_PrivateKeyJWT_QueryOperation(t *testing.T) {
	t.Parallel()

	f, priv := pkjwtFixture(t)
	f.seedPKJWTGrant(t, "grant-pkjwt-query")

	resp := f.doPKJWT(t, http.MethodGet, "grant-pkjwt-query", signGMAssertion(t, f, priv, "ca-gm-query"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeError(t, resp))
	}
	var body struct {
		Scopes []struct {
			Scope string `json:"scope"`
		} `json:"scopes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode query response: %v", err)
	}
	if len(body.Scopes) != 1 || body.Scopes[0].Scope != "openid email" {
		t.Errorf("scopes=%+v want one entry with %q", body.Scopes, "openid email")
	}
}

// TestHandler_PrivateKeyJWT_RevokeOperation is the DELETE half: the
// same query-borne assertion authenticates the revoke, and the grant is
// gone afterwards.
func TestHandler_PrivateKeyJWT_RevokeOperation(t *testing.T) {
	t.Parallel()

	f, priv := pkjwtFixture(t)
	f.seedPKJWTGrant(t, "grant-pkjwt-revoke")

	resp := f.doPKJWT(t, http.MethodDelete, "grant-pkjwt-revoke", signGMAssertion(t, f, priv, "ca-gm-revoke"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d want 204", resp.StatusCode)
	}
	if _, err := f.store.Grants().Find(context.Background(), "grant-pkjwt-revoke"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("grant still present after revoke: err=%v want ErrNotFound", err)
	}
}

// TestHandler_PrivateKeyJWT_ReplayedAssertionRejected confirms the
// query channel inherits the RFC 7523 §3 replay defence unchanged: once
// an assertion's jti has been consumed by a successful request, a
// second request presenting it is rejected.
func TestHandler_PrivateKeyJWT_ReplayedAssertionRejected(t *testing.T) {
	t.Parallel()

	f, priv := pkjwtFixture(t)
	f.seedPKJWTGrant(t, "grant-pkjwt-replay-1")
	f.seedPKJWTGrant(t, "grant-pkjwt-replay-2")
	assertion := signGMAssertion(t, f, priv, "ca-gm-replay")

	first := f.doPKJWT(t, http.MethodGet, "grant-pkjwt-replay-1", assertion)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d want 200, body=%v", first.StatusCode, decodeError(t, first))
	}

	replay := f.doPKJWT(t, http.MethodGet, "grant-pkjwt-replay-2", assertion)
	defer replay.Body.Close()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status=%d want 401", replay.StatusCode)
	}
	if got := decodeError(t, replay)["error"]; got != "invalid_client" {
		t.Errorf("replay error=%v want invalid_client", got)
	}
}
