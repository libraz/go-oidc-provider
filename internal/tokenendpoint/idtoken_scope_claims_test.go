package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	scopeClaimsClientID = "client-scope-claims"
	scopeClaimsSecret   = "scope-claims-secret"
	scopeClaimsSubject  = "user-scope-claims"
	scopeClaimsRedirect = "https://rp.example/cb"
	scopeClaimsCIBAURN  = "urn:openid:params:grant-type:ciba"
)

// scopeClaimsHarness wires a token endpoint over the in-memory store with
// one client allowed on all four built-in grants and one user holding the
// email, email_verified, tenant_id and name claims.
type scopeClaimsHarness struct {
	deps  tokenendpoint.Deps
	store *inmem.Store
	clock fixedClock
}

func newScopeClaimsHarness(t *testing.T, configured []string, withUserStore bool) *scopeClaimsHarness {
	t.Helper()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(scopeClaimsSecret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      scopeClaimsClientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{scopeClaimsRedirect},
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code", "refresh_token", devCodeGrantURN, scopeClaimsCIBAURN},
		Scopes:                  []string{"openid", "profile", "email", "tenant"},
	}
	if err := s.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	s.PutUser(context.Background(), &store.User{
		Subject: scopeClaimsSubject,
		Claims: map[string]any{
			"email":          "user@example.com",
			"email_verified": true,
			"tenant_id":      "t-1",
			"name":           "Alice",
		},
	})
	entry, err := keys.GenerateES256("scope-claims-kid")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	deps := tokenendpoint.Deps{
		Issuer:                 "https://op.example",
		Clients:                s,
		Codes:                  s.AuthorizationCodes(),
		RefreshTokens:          s.RefreshTokens(),
		Grants:                 s.Grants(),
		AccessTokens:           s.AccessTokens(),
		DeviceCodes:            s.DeviceCodes(),
		CIBARequests:           s.CIBARequests(),
		Keys:                   keySet,
		Clock:                  clock,
		ClaimsParameterEnabled: true,
		IDTokenScopeClaims:     configured,
		CustomScopeClaims:      map[string][]string{"tenant": {"tenant_id"}},
	}
	if withUserStore {
		deps.UserStore = s.Users()
	}
	return &scopeClaimsHarness{deps: deps, store: s, clock: clock}
}

func (h *scopeClaimsHarness) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(scopeClaimsClientID, scopeClaimsSecret)
	rec := httptest.NewRecorder()
	tokenendpoint.Handler(h.deps).ServeHTTP(rec, req)
	return rec
}

// redeem seeds the artefact of grant (scope granted, claims request
// claimsReq on the grants that carry one), redeems it, and returns the
// id_token claims. requested narrows a refresh_token exchange.
func (h *scopeClaimsHarness) redeem(
	t *testing.T, grantType string, granted []string, requested string, claimsReq map[string]any,
) map[string]any {
	t.Helper()
	ctx := context.Background()
	now := h.clock.now
	var rec *httptest.ResponseRecorder
	switch grantType {
	case "authorization_code":
		verifier, challenge := pkcePair()
		saveScopeClaimsGrant(t, h, granted)
		if err := h.store.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
			ID: "code-sc", ClientID: scopeClaimsClientID, Subject: scopeClaimsSubject, GrantID: "grant-sc",
			RedirectURI: scopeClaimsRedirect, Scope: granted,
			CodeChallenge: challenge, CodeChallengeMethod: "S256",
			ExpiresAt: now.Add(time.Minute), CreatedAt: now,
			Claims: claimsReq, AuthorizationRecorded: true,
		}); err != nil {
			t.Fatalf("AuthorizationCodes.Save: %v", err)
		}
		rec = h.post(t, authCodeForm("code-sc", scopeClaimsRedirect, verifier))
	case "refresh_token":
		saveScopeClaimsGrant(t, h, granted)
		if err := h.store.RefreshTokens().Save(ctx, &store.RefreshToken{
			ID: "rt-sc", ClientID: scopeClaimsClientID, Subject: scopeClaimsSubject, GrantID: "grant-sc",
			Scope: granted, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			Claims: claimsReq, AuthorizationRecorded: true,
		}); err != nil {
			t.Fatalf("RefreshTokens.Save: %v", err)
		}
		rec = h.post(t, refreshForm("rt-sc", requested))
	case "device_code":
		if err := h.store.DeviceCodes().Save(ctx, &store.DeviceCode{
			ID: "dc-sc", UserCode: "ABCD-EFGH", ClientID: scopeClaimsClientID, Scope: granted,
			IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
			Interval: devicecode.DefaultInterval, Status: store.DeviceCodeStatusPending,
		}); err != nil {
			t.Fatalf("DeviceCodes.Save: %v", err)
		}
		if err := h.store.DeviceCodes().Approve(ctx, "dc-sc", scopeClaimsSubject, time.Time{}); err != nil {
			t.Fatalf("DeviceCodes.Approve: %v", err)
		}
		rec = h.post(t, url.Values{"grant_type": {devCodeGrantURN}, "device_code": {"dc-sc"}})
	case "ciba":
		if err := h.store.CIBARequests().Save(ctx, &store.CIBARequest{
			ID: "ar-sc", ClientID: scopeClaimsClientID, Scope: granted,
			IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
			Interval: ciba.DefaultInterval, Status: store.CIBARequestStatusPending,
		}); err != nil {
			t.Fatalf("CIBARequests.Save: %v", err)
		}
		if err := h.store.CIBARequests().Approve(ctx, "ar-sc", scopeClaimsSubject, "", time.Time{}); err != nil {
			t.Fatalf("CIBARequests.Approve: %v", err)
		}
		rec = h.post(t, url.Values{"grant_type": {scopeClaimsCIBAURN}, "auth_req_id": {"ar-sc"}})
	default:
		t.Fatalf("unknown grant %q", grantType)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", grantType, rec.Code, rec.Body.String())
	}
	idToken, _ := decodeRecorderJSON(t, rec)["id_token"].(string)
	if idToken == "" {
		t.Fatalf("%s response carries no id_token: %s", grantType, rec.Body.String())
	}
	return decodeIDTokenClaims(t, idToken)
}

func saveScopeClaimsGrant(t *testing.T, h *scopeClaimsHarness, scope []string) {
	t.Helper()
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID: "grant-sc", Subject: scopeClaimsSubject, ClientID: scopeClaimsClientID, Scope: scope,
		CreatedAt: h.clock.now, UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
}

// idTokenClaimsParam encodes a claims request with the given id_token
// members.
func idTokenClaimsParam(spec map[string]authorize.ClaimSpec) map[string]any {
	return authorize.EncodeClaimsToGrant(&authorize.ClaimsRequest{IDToken: spec})
}

// TestIDTokenScopeClaims drives the four built-in grants through every
// combination of configured scope, granted scope and "claims" request.
func TestIDTokenScopeClaims(t *testing.T) {
	t.Parallel()

	var (
		scopeOnly   = []string{"openid"}
		scopeEmail  = []string{"openid", "email"}
		scopeTenant = []string{"openid", "tenant"}
		scopeAll    = []string{"openid", "email", "tenant"}

		cfgEmail  = []string{"email"}
		cfgTenant = []string{"tenant"}

		reqEmail    = idTokenClaimsParam(map[string]authorize.ClaimSpec{"email": {Essential: true}})
		reqTenantID = idTokenClaimsParam(map[string]authorize.ClaimSpec{"tenant_id": {Essential: true}})
		reqName     = idTokenClaimsParam(map[string]authorize.ClaimSpec{"name": {Essential: true}})
		reqOther    = idTokenClaimsParam(map[string]authorize.ClaimSpec{"email": {Value: "other@example.com"}})
	)

	cases := []struct {
		name        string
		grant       string
		configured  []string
		granted     []string
		requested   string
		claimsReq   map[string]any
		noUserStore bool
		want        []string
	}{
		{name: "row01", grant: "authorization_code", configured: cfgTenant, granted: scopeTenant, claimsReq: reqTenantID, want: []string{"tenant_id"}},
		{name: "row02", grant: "authorization_code", configured: cfgEmail, granted: scopeOnly, claimsReq: reqName, want: []string{"name"}},
		{name: "row03", grant: "authorization_code", granted: scopeOnly},
		{name: "row04", grant: "refresh_token", granted: scopeAll, claimsReq: reqName, want: []string{"name"}},
		{name: "row05", grant: "refresh_token", configured: cfgEmail, granted: scopeOnly, claimsReq: reqEmail, want: []string{"email"}},
		{name: "row06", grant: "device_code", configured: cfgEmail, granted: scopeEmail, want: []string{"email", "email_verified"}},
		{name: "row07", grant: "ciba", configured: cfgTenant, granted: scopeTenant, want: []string{"tenant_id"}},
		{name: "row08", grant: "refresh_token", configured: cfgTenant, granted: scopeTenant, claimsReq: reqName, want: []string{"tenant_id", "name"}},
		{name: "row09", grant: "refresh_token", configured: cfgTenant, granted: scopeOnly},
		{name: "row10", grant: "authorization_code", granted: scopeOnly, claimsReq: reqEmail, want: []string{"email"}},
		{name: "row11", grant: "device_code", configured: cfgTenant, granted: scopeOnly},
		{name: "row12", grant: "ciba", configured: cfgEmail, granted: scopeOnly},
		{name: "row13", grant: "device_code", granted: scopeAll},
		{name: "row14", grant: "ciba", granted: scopeOnly},
		// The chain carries email; the request narrows it away.
		{name: "e1", grant: "refresh_token", configured: cfgEmail, granted: scopeEmail, requested: "openid"},
		// The claims request names email and its value constraint fails, so
		// email is not added from the scope side; email_verified is not
		// named and follows the scope.
		{name: "e2", grant: "authorization_code", configured: cfgEmail, granted: scopeEmail, claimsReq: reqOther, want: []string{"email_verified"}},
		{name: "e3", grant: "authorization_code", configured: cfgEmail, granted: scopeEmail, noUserStore: true},
	}

	values := map[string]any{
		"email":          "user@example.com",
		"email_verified": true,
		"tenant_id":      "t-1",
		"name":           "Alice",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newScopeClaimsHarness(t, tc.configured, !tc.noUserStore)
			got := h.redeem(t, tc.grant, tc.granted, tc.requested, tc.claimsReq)
			for name, value := range values {
				present, isWanted := got[name], false
				for _, w := range tc.want {
					if w == name {
						isWanted = true
					}
				}
				_, has := got[name]
				switch {
				case isWanted && present != value:
					t.Errorf("%s=%v want %v", name, present, value)
				case !isWanted && has:
					t.Errorf("%s=%v present, want absent", name, present)
				}
			}
		})
	}
}
