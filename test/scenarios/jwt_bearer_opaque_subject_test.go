package scenarios_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	jbosIssuer   = "https://idp-jbos.example.com"
	jbosClientID = "rp-jbos-pairwise"
	jbosSecret   = "rp-jbos-secret" //nolint:gosec // G101: test fixture, not a real credential.
	jbosCallback = "https://rp-jbos.example.com/cb"
	jbosUser     = "user-jbos"
)

var jbosSalt = []byte("jwt-bearer-opaque-subject-salt32")

// jbosRedeem builds a pairwise provider minting access tokens in format,
// redeems one jwt-bearer assertion for jbosUser and returns the provider
// and the issued access token.
func jbosRedeem(t *testing.T, issuerKey *pkjwtKeypair, format op.AccessTokenFormat) (*testkit.Provider, string) {
	t.Helper()
	tk := testkit.NewProvider(t, testkit.WithClock(dpopFixedClock{t: jbgNow}), testkit.WithOptions(
		op.WithPairwiseSubject(jbosSalt),
		op.WithAccessTokenFormat(format),
		op.WithFeature(feature.Introspect),
		op.WithJWTBearerGrant(op.JWTBearerGrant{
			Issuers: []op.AssertionIssuer{{
				Issuer:         jbosIssuer,
				JWKS:           issuerKey.PublicJWKSet(t),
				AllowedClients: []string{jbosClientID},
				Profile:        op.AssertionProfileJWT,
			}},
			ResolveSubject: func(context.Context, op.AssertionSubject) (string, error) { return jbosUser, nil },
		}),
	))
	hash, err := op.HashClientSecret(jbosSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      jbosClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{jbosCallback},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{jbgGrantType},
		Scopes:                  []string{"read"},
		SubjectType:             "pairwise",
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: jbosUser})

	assertion := jbgSign(t, issuerKey, map[string]any{
		"iss": jbosIssuer,
		"sub": "alice",
		"aud": tk.Issuer,
		"iat": jbgNow.Unix(),
		"exp": jbgNow.Add(2 * time.Minute).Unix(),
		"jti": "jbos-" + strconv.Itoa(int(format)),
	}, "", issuerKey.kid)
	form := url.Values{"grant_type": {jbgGrantType}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(jbosClientID, jbosSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("format %d: /token status=%d body=%s", format, resp.StatusCode, raw)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode /token: %v", err)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("format %d: no access_token in %s", format, raw)
	}
	return tk, at
}

// TestOpaqueAccessToken_JWTBearerIntrospectionCarriesPairwiseSub pins that a
// jwt-bearer access token, which no grant record backs, reports the same
// per-client subject at introspection in the opaque format as its JWT
// form carries — never the OP-internal identifier.
func TestOpaqueAccessToken_JWTBearerIntrospectionCarriesPairwiseSub(t *testing.T) {
	t.Parallel()

	issuerKey := newPKJWTKeypair(t, "jbos-issuer-key")

	_, jwtAT := jbosRedeem(t, issuerKey, op.AccessTokenFormatJWT)
	jwtSub, _ := scenariokit.DecodeJWSClaims(t, jwtAT)["sub"].(string)
	if jwtSub == "" || jwtSub == jbosUser {
		t.Fatalf("JWT sub=%q, want the pairwise pseudonym", jwtSub)
	}

	tk, opaqueAT := jbosRedeem(t, issuerKey, op.AccessTokenFormatOpaque)
	intro := int015Introspect(t, tk, jbosClientID, jbosSecret, opaqueAT, "access_token")
	if active, _ := intro["active"].(bool); !active {
		t.Fatalf("opaque jwt-bearer token introspected inactive: %v", intro)
	}
	if got, _ := intro["sub"].(string); got != jwtSub {
		t.Errorf("introspection sub=%q, want the JWT-format sub %q", got, jwtSub)
	}
}
