package scenarios_test

// Catalog: test/scenarios/catalog/authorization_details.yaml (RAR-NNN)
// Spec:
//   - RFC 9396 §2.1 (request structure), §5 (invalid_authorization_details)
//   - RFC 9396 §6 (token response), §9 (introspection), §10 (discovery)

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	rarClientID = "rp-rar"
	rarCallback = "https://rp.testkit.invalid/callback"
	rarSecret   = "rp-rar-secret" //nolint:gosec // test fixture: not a real credential.
	rarType     = "payment_initiation"
)

// rarDetails is the canonical valid authorization_details payload the
// tests push: one element of the registered type.
const rarDetails = `[{"type":"payment_initiation","actions":["initiate"]}]`

// rarProvider builds an OP that accepts the payment_initiation type (whose
// validator requires a non-empty "actions" array) and enables
// introspection, plus a confidential client that can drive token / refresh
// / introspection hops.
func rarProvider(t *testing.T) *testkit.Provider {
	t.Helper()
	hash, err := op.HashClientSecret(rarSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.Introspect),
		op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
			Type: rarType,
			Validate: func(_ context.Context, el map[string]any, _ *store.Client) error {
				if _, ok := el["actions"].([]any); !ok {
					return errors.New("payment_initiation requires an actions array")
				}
				return nil
			},
		}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      rarClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{rarCallback},
		Scopes:                  []string{"openid", "profile", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return tk
}

func rarAuthorize(t *testing.T, tk *testkit.Provider, details string) (scenariokit.CodeFlowResult, scenariokit.PKCEPair) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	params := scenariokit.AuthorizeParams{
		ClientID:    rarClientID,
		RedirectURI: rarCallback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
		Extra:       url.Values{"authorization_details": {details}},
	}
	return scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, params), pkce
}

// TestScenario_RAR_001_RegisteredTypeAcceptedAndGranted and
// TestScenario_RAR_010_TokenResponseEchoesDetails share a flow: a valid
// authorization_details is accepted, bound to the grant, and echoed on the
// token response.
func TestScenario_RAR_001_RegisteredTypeAcceptedAndGranted(t *testing.T) {
	t.Parallel()
	tk := rarProvider(t)
	flow, pkce := rarAuthorize(t, tk, rarDetails)
	if flow.Code == "" {
		t.Fatalf("authorize rejected a valid authorization_details: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: rarCallback, Verifier: pkce.Verifier,
		ClientID: rarClientID, ClientSecret: rarSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	assertSingleRARType(t, tok.Raw["authorization_details"])
}

func TestScenario_RAR_010_TokenResponseEchoesDetails(t *testing.T) {
	t.Parallel()
	tk := rarProvider(t)
	flow, pkce := rarAuthorize(t, tk, rarDetails)
	if flow.Code == "" {
		t.Fatalf("authorize rejected a valid authorization_details: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: rarCallback, Verifier: pkce.Verifier,
		ClientID: rarClientID, ClientSecret: rarSecret,
	})
	assertSingleRARType(t, tok.Raw["authorization_details"])
}

// TestScenario_RAR_002_UnknownTypeRejected pins the RFC 9396 §5 wire error
// for an authorization_details element naming an unregistered type.
func TestScenario_RAR_002_UnknownTypeRejected(t *testing.T) {
	t.Parallel()
	tk := rarProvider(t)
	flow, _ := rarAuthorize(t, tk, `[{"type":"unregistered_type"}]`)
	if flow.Code != "" {
		t.Fatalf("expected rejection, got code: %+v", flow)
	}
	if flow.Error != "invalid_authorization_details" {
		t.Errorf("error=%q want invalid_authorization_details", flow.Error)
	}
}

// TestScenario_RAR_011_RefreshEchoesDetails verifies a token minted by
// refreshing the grant carries the same authorization_details.
func TestScenario_RAR_011_RefreshEchoesDetails(t *testing.T) {
	t.Parallel()
	tk := rarProvider(t)
	flow, pkce := rarAuthorize(t, tk, rarDetails)
	if flow.Code == "" {
		t.Fatalf("authorize failed: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: rarCallback, Verifier: pkce.Verifier,
		ClientID: rarClientID, ClientSecret: rarSecret,
	})
	if tok.RefreshToken == "" {
		t.Fatal("offline_access requested but no refresh_token issued")
	}
	refreshed := rarRefresh(t, tk, tok.RefreshToken)
	assertSingleRARType(t, refreshed["authorization_details"])
}

// TestScenario_RAR_020_IntrospectionReturnsDetails verifies introspection
// of an active token descending from the grant returns its
// authorization_details.
func TestScenario_RAR_020_IntrospectionReturnsDetails(t *testing.T) {
	t.Parallel()
	tk := rarProvider(t)
	flow, pkce := rarAuthorize(t, tk, rarDetails)
	if flow.Code == "" {
		t.Fatalf("authorize failed: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: rarCallback, Verifier: pkce.Verifier,
		ClientID: rarClientID, ClientSecret: rarSecret,
	})
	if tok.RefreshToken == "" {
		t.Fatal("offline_access requested but no refresh_token issued")
	}
	status, body := postIntrospect(t, tk, tok.RefreshToken, rarClientID, rarSecret)
	if status != http.StatusOK {
		t.Fatalf("introspect status=%d", status)
	}
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("introspection reported inactive: %v", body)
	}
	assertSingleRARType(t, body["authorization_details"])
}

// TestScenario_RAR_030_DiscoveryAdvertisesTypes verifies the discovery
// document lists the registered type under
// authorization_details_types_supported.
func TestScenario_RAR_030_DiscoveryAdvertisesTypes(t *testing.T) {
	t.Parallel()
	tk := rarProvider(t)
	status, _, doc := fetchDiscovery(t, tk.Server.URL)
	if status != http.StatusOK {
		t.Fatalf("discovery status=%d", status)
	}
	types := toStrings(doc["authorization_details_types_supported"])
	if len(types) != 1 || types[0] != rarType {
		t.Errorf("authorization_details_types_supported=%v want [%q]", doc["authorization_details_types_supported"], rarType)
	}
}

// TestScenario_RAR_003_PushedThenReproducedAtAuthorize pushes
// authorization_details through /par, then presents the issued request_uri
// at /authorize. The pushed details must be validated at push time and
// reproduced on the resulting grant so the token response echoes them.
func TestScenario_RAR_003_PushedThenReproducedAtAuthorize(t *testing.T) {
	t.Parallel()
	hash, err := op.HashClientSecret(rarSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.PAR),
		op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
			Type: rarType,
			Validate: func(_ context.Context, el map[string]any, _ *store.Client) error {
				if _, ok := el["actions"].([]any); !ok {
					return errors.New("payment_initiation requires an actions array")
				}
				return nil
			},
		}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      rarClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{rarCallback},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	// Push the request, including authorization_details, to /par.
	pkce := scenariokit.NewPKCEPair("")
	pushForm := url.Values{
		"client_id":             {rarClientID},
		"response_type":         {"code"},
		"redirect_uri":          {rarCallback},
		"scope":                 {"openid profile"},
		"state":                 {"rar-par-state"},
		"nonce":                 {"rar-par-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		"authorization_details": {rarDetails},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/par", strings.NewReader(pushForm.Encode()))
	if err != nil {
		t.Fatalf("build /par request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rarClientID, rarSecret)
	pushResp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /par: %v", err)
	}
	pushBody := decodeJSONResp(t, pushResp)
	pushResp.Body.Close()
	requestURI, _ := pushBody["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("/par did not return a request_uri: %v", pushBody)
	}

	// Present the request_uri at /authorize; the PAR consumption path
	// restores the pushed snapshot (including authorization_details).
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rarClientID,
		RedirectURI: rarCallback,
		PKCE:        pkce,
		Extra:       url.Values{"request_uri": {requestURI}},
	})
	if flow.Code == "" {
		t.Fatalf("authorize via request_uri failed: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: rarCallback, Verifier: pkce.Verifier,
		ClientID: rarClientID, ClientSecret: rarSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	assertSingleRARType(t, tok.Raw["authorization_details"])
}

// TestScenario_RAR_004_RequestObjectDetailsMergedAndValidated carries the
// authorization_details value as a JSON array inside a signed request
// object. The JAR merge layer must re-encode that decoded JSON shape into
// the regular authorization_details parameter so the authorize parser
// validates it and the token response echoes the granted details.
func TestScenario_RAR_004_RequestObjectDetailsMergedAndValidated(t *testing.T) {
	t.Parallel()

	tk, priv, kid := rarJARProvider(t)
	claims := rarJARClaims(tk.Issuer)
	claims["authorization_details"] = []map[string]any{{
		"type":    rarType,
		"actions": []string{"initiate"},
	}}
	signed := signWithJOSE(t, josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       priv,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}, claims)

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    "rp-rar-jar",
		RedirectURI: rarCallback,
		PKCE:        scenariokit.PKCEPair{Verifier: jarPKCEVerifier, Challenge: jarPKCEChallenge, Method: "S256"},
		Extra:       url.Values{"request": {signed}},
	})
	if flow.Code == "" {
		t.Fatalf("authorize via request object failed: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:        flow.Code,
		RedirectURI: rarCallback,
		Verifier:    jarPKCEVerifier,
		Extra:       url.Values{"client_id": {"rp-rar-jar"}},
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	assertSingleRARType(t, tok.Raw["authorization_details"])
}

// rarRefresh runs a refresh_token grant with the confidential client's
// Basic credentials and returns the parsed token response.
func rarRefresh(t *testing.T, tk *testkit.Provider, refreshToken string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build refresh request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rarClientID, rarSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", resp.StatusCode, body)
	}
	return body
}

// assertSingleRARType asserts the decoded authorization_details value is a
// one-element array whose element carries the registered type.
func assertSingleRARType(t *testing.T, v any) {
	t.Helper()
	arr, ok := v.([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("authorization_details=%v want a single-element array", v)
	}
	el, ok := arr[0].(map[string]any)
	if !ok {
		t.Fatalf("authorization_details[0]=%v want an object", arr[0])
	}
	if el["type"] != rarType {
		t.Errorf("authorization_details[0].type=%v want %q", el["type"], rarType)
	}
}

func rarJARProvider(t *testing.T) (*testkit.Provider, *ecdsa.PrivateKey, string) {
	t.Helper()
	clock := jarFixedClock{t: jarAnchor}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.JAR),
			op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
				Type: rarType,
				Validate: func(_ context.Context, el map[string]any, _ *store.Client) error {
					if _, ok := el["actions"].([]any); !ok {
						return errors.New("payment_initiation requires an actions array")
					}
					return nil
				},
			}),
		),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-rar-jar-kid"
	jwksRaw, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal JWKS: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rp-rar-jar",
		PublicClient: true,
		RedirectURIs: []string{rarCallback},
		Scopes:       []string{"openid", "profile"},
	})
	updated := *rp
	updated.JWKs = jwksRaw
	if err := tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient(JWKs): %v", err)
	}
	return tk, priv, kid
}

func rarJARClaims(issuer string) map[string]any {
	now := jarAnchor
	return map[string]any{
		"iss":                   "rp-rar-jar",
		"aud":                   issuer,
		"exp":                   now.Add(2 * time.Minute).Unix(),
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"jti":                   freshJARScenarioJTI(),
		"client_id":             "rp-rar-jar",
		"response_type":         "code",
		"redirect_uri":          rarCallback,
		"scope":                 "openid profile",
		"state":                 "rar-jar-state",
		"nonce":                 "rar-jar-nonce",
		"code_challenge":        jarPKCEChallenge,
		"code_challenge_method": "S256",
	}
}
