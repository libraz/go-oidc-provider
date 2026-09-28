package scenarios_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// The opaque shadow row cannot say whether its subject is the
// OP-internal identifier or already the wire value; readers tell them
// apart by whether the row's GrantID names a Grant record. These tests
// pin that premise across the mint paths and the "sub" the readers
// report under pairwise subjects.

const (
	osCustomGrantURN = "urn:example:grant-type:opaque-subject-kind"
	osClientID       = "rp-opaque-subject"
	osClientSecret   = "rp-opaque-subject-secret" //nolint:gosec // G101: test fixture, not a real credential.
	osCallback       = "https://pairwise-rp.opaque.example.test/callback"
	osWireSubject    = "cg-wire-subject"
)

var osSalt = []byte("opaque-subject-kind-salt-32bytes")

// newOpaqueSubjectProvider builds a pairwise, opaque-format Provider
// serving every mint path the table covers, plus introspection and
// token exchange, and one pairwise client registered for all of them.
func newOpaqueSubjectProvider(t *testing.T) (*testkit.Provider, *store.Client) {
	t.Helper()
	handler := &recordingCustomGrant{
		name: osCustomGrantURN,
		response: op.CustomGrantResponse{
			BoundAccessToken:  &op.BoundAccessToken{},
			IssueRefreshToken: true,
			Subject:           op.Subject(osWireSubject),
			Scope:             []string{"openid", "read"},
		},
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(osSalt),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		op.WithFeature(feature.Introspect),
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials),
		op.WithCustomGrant(handler),
		op.RegisterTokenExchange(txAllowAllPolicy{}),
	))
	hash, err := op.HashClientSecret(osClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      osClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{osCallback},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{
			"authorization_code", "refresh_token", "client_credentials",
			osCustomGrantURN, txGrantType,
		},
		Scopes:      []string{"openid", "read"},
		Resources:   []string{txTargetAud},
		SubjectType: "pairwise",
	})
	return tk, client
}

// osPost submits form to path with the client's Basic credentials.
func osPost(t *testing.T, tk *testkit.Provider, path string, form url.Values) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(osClientID, osClientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status=%d body=%s", path, resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("POST %s body is not JSON: %v (raw=%s)", path, err, body)
	}
	return out
}

// osCustomGrantChain runs the custom grant, rotates its refresh token
// once, and returns the root response and the rotated access token.
func osCustomGrantChain(t *testing.T, tk *testkit.Provider) (root map[string]any, rotatedAT string) {
	t.Helper()
	root = osPost(t, tk, "/oidc/token", url.Values{"grant_type": {osCustomGrantURN}})
	rt, _ := root["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("custom grant issued no refresh_token: %v", root)
	}
	rotated := osPost(t, tk, "/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	rotatedAT, _ = rotated["access_token"].(string)
	if strings.Count(rotatedAT, ".") == 2 {
		t.Fatalf("rotated access token is a JWS; the opaque format did not apply")
	}
	return root, rotatedAT
}

// TestOpaqueAccessToken_MintPathsRecordSubjectKind pins the premise the
// shared opaque resolver relies on: a row whose GrantID names a Grant
// record carries the OP-internal subject, and every other row carries
// the wire subject. A new mint path that breaks the pairing fails here.
func TestOpaqueAccessToken_MintPathsRecordSubjectKind(t *testing.T) {
	t.Parallel()

	tk, _ := newOpaqueSubjectProvider(t)
	ctx := context.Background()

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID: osClientID, RedirectURI: osCallback, Scope: "openid read", PKCE: pkce,
	})
	code := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: osCallback, Verifier: pkce.Verifier,
		ClientID: osClientID, ClientSecret: osClientSecret,
	})
	if code.StatusCode != http.StatusOK || code.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with a refresh_token", code.StatusCode, code.Raw)
	}
	refreshed := osPost(t, tk, "/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {code.RefreshToken}})
	cc := osPost(t, tk, "/oidc/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}})
	_, customRotated := osCustomGrantChain(t, tk)

	cases := []struct {
		name        string
		token       string
		wantSubject string
		internal    bool
	}{
		{name: "authorization_code", token: code.AccessToken, wantSubject: scenariokit.DefaultSubject, internal: true},
		{name: "refresh of an OP-rooted chain", token: osString(refreshed["access_token"]), wantSubject: scenariokit.DefaultSubject, internal: true},
		{name: "client_credentials", token: osString(cc["access_token"]), wantSubject: osClientID},
		{name: "refresh of a custom-grant chain", token: customRotated, wantSubject: osWireSubject},
	}
	for _, tc := range cases {
		rec, err := tk.Store.OpaqueAccessTokens().Find(ctx, tc.token)
		if err != nil {
			t.Fatalf("%s: OpaqueAccessTokens.Find: %v", tc.name, err)
		}
		if rec.Subject != tc.wantSubject {
			t.Errorf("%s: recorded subject=%q want %q", tc.name, rec.Subject, tc.wantSubject)
		}
		grantBacked := false
		if rec.GrantID != "" {
			_, err := tk.Store.Grants().Find(ctx, rec.GrantID)
			switch {
			case err == nil:
				grantBacked = true
			case !errors.Is(err, store.ErrNotFound):
				t.Fatalf("%s: Grants.Find: %v", tc.name, err)
			}
		}
		if grantBacked != tc.internal {
			t.Errorf("%s: grant-backed=%v but internal subject=%v; readers would misclassify this row", tc.name, grantBacked, tc.internal)
		}
	}
}

// TestOpaqueAccessToken_CustomGrantChainKeepsItsSubject asserts that an
// opaque access token minted by rotating a custom-grant chain reports,
// at /introspect and through token exchange, the same "sub" the chain's
// JWT access token and id_token carry.
func TestOpaqueAccessToken_CustomGrantChainKeepsItsSubject(t *testing.T) {
	t.Parallel()

	tk, _ := newOpaqueSubjectProvider(t)
	root, rotated := osCustomGrantChain(t, tk)
	rootAT := osString(root["access_token"])
	if got := decodeTXJWTClaims(t, rootAT)["sub"]; got != osWireSubject {
		t.Fatalf("root JWT access token sub=%v want %q", got, osWireSubject)
	}
	if got := decodeTXJWTClaims(t, osString(root["id_token"]))["sub"]; got != osWireSubject {
		t.Fatalf("root id_token sub=%v want %q", got, osWireSubject)
	}

	intro := osPost(t, tk, "/oidc/introspect", url.Values{"token": {rotated}})
	if active, _ := intro["active"].(bool); !active {
		t.Fatalf("rotated opaque token introspected inactive: %v", intro)
	}
	if intro["sub"] != osWireSubject {
		t.Errorf("/introspect sub=%v want the chain's %q", intro["sub"], osWireSubject)
	}

	exchanged := osPost(t, tk, "/oidc/token", url.Values{
		"grant_type":         {txGrantType},
		"subject_token":      {rotated},
		"subject_token_type": {txTokenTypeAT},
		"resource":           {txTargetAud},
	})
	if got := decodeTXJWTClaims(t, osString(exchanged["access_token"]))["sub"]; got != osWireSubject {
		t.Errorf("token exchange sub=%v want the chain's %q", got, osWireSubject)
	}
}

// TestOpaqueAccessToken_SubjectsMatchUnderPairwise pins the two other
// halves of the rule: a client_credentials token introspects with
// sub=client_id, and a grant-backed token is still projected to the
// pairwise value its id_token carries.
func TestOpaqueAccessToken_SubjectsMatchUnderPairwise(t *testing.T) {
	t.Parallel()

	tk, client := newOpaqueSubjectProvider(t)

	cc := osPost(t, tk, "/oidc/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}})
	intro := osPost(t, tk, "/oidc/introspect", url.Values{"token": {osString(cc["access_token"])}})
	if intro["sub"] != osClientID {
		t.Errorf("client_credentials /introspect sub=%v want client_id %q", intro["sub"], osClientID)
	}

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID: osClientID, RedirectURI: osCallback, Scope: "openid read", PKCE: pkce,
	})
	code := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: osCallback, Verifier: pkce.Verifier,
		ClientID: osClientID, ClientSecret: osClientSecret,
	})
	if code.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", code.StatusCode, code.Raw)
	}
	want, err := subject.Pairwise(osSalt).Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: scenariokit.DefaultSubject,
		Client:         client,
	})
	if err != nil {
		t.Fatalf("Pairwise.Generate: %v", err)
	}
	if got := decodeTXJWTClaims(t, code.IDToken)["sub"]; got != string(want) {
		t.Fatalf("id_token sub=%v want pairwise %q", got, want)
	}
	intro = osPost(t, tk, "/oidc/introspect", url.Values{"token": {code.AccessToken}})
	if intro["sub"] != string(want) {
		t.Errorf("authorization_code /introspect sub=%v want the id_token's %q", intro["sub"], want)
	}
}

func osString(v any) string {
	s, _ := v.(string)
	return s
}
