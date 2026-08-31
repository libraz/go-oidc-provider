package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// customGrantAuditFixture builds a fixture whose Provider captures every
// audit event and registers the supplied custom grant. Extra options are
// appended after the audit logger so a test can reshape the provider
// (grant set, token format) without rebuilding the wiring.
func customGrantAuditFixture(tb testing.TB, handler op.CustomGrantHandler, extra ...op.Option) (*fixture, *auditCapture) {
	tb.Helper()
	capture := newAuditCapture()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	opts := append([]op.Option{
		op.WithAuditLogger(capture.logger()),
		op.WithCustomGrant(handler),
	}, extra...)
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(opts...),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}, capture
}

// customGrantRefreshClient registers a confidential client listing both
// the custom grant_type and refresh_token, so the client half of the
// refresh gate is satisfied and only the Provider half is under test.
func customGrantRefreshClient(tb testing.TB, prov *testkit.Provider, id, grantURN string, scopes, resources []string) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{grantURN, "refresh_token"},
		Scopes:                  scopes,
		Resources:               resources,
	})
	return client, secret
}

// auditExtras returns the extras map of the named audit event, failing
// the test when the event was never emitted.
func auditExtras(t *testing.T, capture *auditCapture, name string) map[string]any {
	t.Helper()
	rec := capture.findEvent(t, name)
	if rec == nil {
		t.Fatalf("%s not emitted; capture=%s", name, capture.buf.String())
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("%s carries no extras: %v", name, rec)
	}
	return extras
}

// TestCustomGrant_RefreshDroppedWhenProviderDisablesTheGrant pins the
// Provider half of the refresh gate on the custom-grant path. The client
// is registered for refresh_token but the deployment does not serve the
// grant, so the same token endpoint would answer unsupported_grant_type
// to the credential it is being asked to mint. Issuing it anyway would
// hand the client an unusable token, leave an unredeemable row behind,
// and contradict grant_types_supported.
func TestCustomGrant_RefreshDroppedWhenProviderDisablesTheGrant(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:refresh-provider-disabled"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken:       "test-access-token",
			IssueRefreshToken: true,
			Subject:           op.Subject("user-provider-disabled"),
			Scope:             []string{"read"},
		},
	}
	// The custom grant_type rides onto the enabled set automatically;
	// refresh_token is deliberately absent from it.
	f, capture := customGrantAuditFixture(t, handler, op.WithGrants(grant.AuthorizationCode))
	client, secret := customGrantRefreshClient(t, f.prov, "client-cg-provider-disabled", grantURN, []string{"read"}, nil)

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if rt, _ := body["refresh_token"].(string); rt != "" {
		t.Errorf("refresh_token=%q; the provider does not serve the refresh_token grant", rt)
	}
	if at, _ := body["access_token"].(string); at == "" {
		t.Error("access_token missing; a dropped refresh token must not fail the response")
	}

	extras := auditExtras(t, capture, "custom_grant.refresh_dropped")
	if got := extras["reason"]; got != "provider_grant_disabled" {
		t.Errorf("extras.reason=%v want provider_grant_disabled", got)
	}
	// token.issued fires exactly when a chain root is persisted, so its
	// absence is the observable proof that no row was written.
	if rec := capture.findEvent(t, "token.issued"); rec != nil {
		t.Errorf("token.issued emitted for a dropped refresh token: %v", rec)
	}
}

// TestCustomGrant_RefreshIssuanceEmitsTokenIssuedAudit pins the audit
// record on the successful custom-grant path. A refresh chain rooted in
// a custom grant is the longest-lived credential the grant produces;
// without the token.issued record the forensic question "when was this
// chain created" has no answer for delegation grants, and the metric
// partitioned by chain-creating grant loses the custom_grant series
// entirely.
func TestCustomGrant_RefreshIssuanceEmitsTokenIssuedAudit(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:refresh-audit"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken:       "test-access-token",
			IssueRefreshToken: true,
			Subject:           op.Subject("user-refresh-audit"),
			Scope:             []string{"read"},
		},
	}
	f, capture := customGrantAuditFixture(t, handler)
	client, secret := customGrantRefreshClient(t, f.prov, "client-cg-refresh-audit", grantURN, []string{"read"}, nil)

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("refresh_token missing: %v", body)
	}

	extras := auditExtras(t, capture, "token.issued")
	// The bridge that projects the metric label reads this key, so the
	// label the operator sees is exactly the origin persisted on the
	// chain.
	if got := extras["refresh_origin"]; got != string(store.RefreshOriginCustomGrant) {
		t.Errorf("extras.refresh_origin=%v want %q", got, store.RefreshOriginCustomGrant)
	}
	if got, _ := extras["grant_id"].(string); got == "" {
		t.Error("extras.grant_id missing; the record cannot be tied to the access token")
	}
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rt)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.Origin != store.RefreshOriginCustomGrant {
		t.Errorf("persisted origin=%q want %q", rec.Origin, store.RefreshOriginCustomGrant)
	}
}

// TestCustomGrant_RefreshDroppedWhenScopeEmpty pins the empty-scope gate.
// A refresh chain replays its scope onto every rotation, so a response
// without one cannot be represented as a chain root — but that is a
// response the OP declines to attach a refresh token to, not a failed
// request: the access token it already resolved must still reach the
// client.
func TestCustomGrant_RefreshDroppedWhenScopeEmpty(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:refresh-empty-scope"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken:       "test-access-token",
			IssueRefreshToken: true,
			Subject:           op.Subject("user-empty-scope"),
			Scope:             nil,
		},
	}
	f, capture := customGrantAuditFixture(t, handler)
	client, secret := customGrantRefreshClient(t, f.prov, "client-cg-empty-scope", grantURN, []string{"read"}, nil)

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if at, _ := body["access_token"].(string); at != "test-access-token" {
		t.Errorf("access_token=%v; the resolved access token must survive a dropped refresh token", body["access_token"])
	}
	if rt, _ := body["refresh_token"].(string); rt != "" {
		t.Errorf("refresh_token=%q want dropped for an empty scope", rt)
	}
	extras := auditExtras(t, capture, "custom_grant.refresh_dropped")
	if got := extras["reason"]; got != "empty_scope" {
		t.Errorf("extras.reason=%v want empty_scope", got)
	}
}

// TestCustomGrant_BoundAccessTokenClaimCollisionIsServerError pins the
// error class of a handler bug. A claim name colliding with the standard
// set is the OP failing to build its own response, not a defect of the
// grant the client presented, so collapsing it onto invalid_grant would
// send the embedder to debug client credentials for a bug in its
// handler.
func TestCustomGrant_BoundAccessTokenClaimCollisionIsServerError(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:bound-claim-collision"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			BoundAccessToken: &op.BoundAccessToken{
				Subject:     op.Subject("user-collision"),
				ExtraClaims: map[string]any{"scope": "smuggled"},
			},
			Scope: []string{"read"},
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}
	client, secret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "server_error" {
		t.Errorf("error=%v want server_error", got)
	}
}

// TestCustomGrant_IDTokenClaimCollisionIsServerError is the sibling of
// the access-token row above: the same handler mistake on the other
// ExtraClaims field of the same response object must produce the same
// error class.
func TestCustomGrant_IDTokenClaimCollisionIsServerError(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:idtoken-claim-collision"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken: "test-access-token",
			Subject:     op.Subject("user-collision"),
			Scope:       []string{"openid"},
			ExtraClaims: map[string]any{"iss": "https://attacker.example"},
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}
	client, secret := customGrantClient(t, prov, grantURN, []string{"openid"}, nil)

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "server_error" {
		t.Errorf("error=%v want server_error", got)
	}
}

// requireAuthTimeClient registers a client whose metadata demands an
// auth_time claim on every id_token it receives. The testkit fixture
// carries no field for it, so the record is written directly.
func requireAuthTimeClient(tb testing.TB, prov *testkit.Provider, id, grantURN string) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      id,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{grantURN},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		RequireAuthTime:         true,
	}
	if err := prov.Store.RegisterClient(context.Background(), client); err != nil {
		tb.Fatalf("RegisterClient(%q): %v", id, err)
	}
	return client, secret
}

// TestCustomGrant_IDTokenRequiresAuthTimeWhenClientRequiresIt pins the
// fail-closed reading of require_auth_time on the custom-grant path. The
// claim is omitempty, so a zero auth_time would ship an id_token that
// silently lacks it — and a relying party whose session policy keys on
// auth_time reads the absence as "recently authenticated".
func TestCustomGrant_IDTokenRequiresAuthTimeWhenClientRequiresIt(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:require-auth-time"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken: "test-access-token",
			Subject:     op.Subject("user-auth-time"),
			Scope:       []string{"openid"},
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}
	client, secret := requireAuthTimeClient(t, prov, "client-cg-require-auth-time", grantURN)

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "server_error" {
		t.Errorf("error=%v want server_error", got)
	}
}

// TestCustomGrant_IDTokenCarriesAuthTimeWhenHandlerStatesIt is the
// positive half: the gate refuses a missing auth_time, it does not
// refuse the client.
func TestCustomGrant_IDTokenCarriesAuthTimeWhenHandlerStatesIt(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:auth-time-stated"
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	authTime := clock.now.Add(-5 * time.Minute)
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken: "test-access-token",
			Subject:     op.Subject("user-auth-time"),
			AuthTime:    authTime,
			Scope:       []string{"openid"},
		},
	}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCustomGrant(handler)),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token", clock: clock}
	client, secret := requireAuthTimeClient(t, prov, "client-cg-auth-time-stated", grantURN)

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	idToken, _ := decodeJSON(t, resp)["id_token"].(string)
	if idToken == "" {
		t.Fatal("id_token missing from an openid-scoped custom-grant response")
	}
	claims := decodeJWTPayload(t, idToken)
	got, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time missing or not numeric: %v", claims["auth_time"])
	}
	if int64(got) != authTime.Unix() {
		t.Errorf("auth_time=%d want %d", int64(got), authTime.Unix())
	}
}

// TestCustomGrant_BoundAccessTokenStaysJWTUnderOpaqueFormat pins the
// documented reach of the opaque format option. The grants the OP
// implements itself follow the configured format; a BoundAccessToken
// does not, because its audience set and its handler-stated claims have
// nowhere to live on the opaque shadow row. Both halves run against the
// same Provider so the assertion is about the format policy rather than
// about two differently-configured deployments.
func TestCustomGrant_BoundAccessTokenStaysJWTUnderOpaqueFormat(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:opaque-deployment"
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			BoundAccessToken: &op.BoundAccessToken{
				Subject:     op.Subject("user-opaque-deployment"),
				TTL:         2 * time.Minute,
				ExtraClaims: map[string]any{"act": map[string]any{"sub": "actor-1"}},
			},
			Scope: []string{"read"},
		},
	}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
			op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials),
			op.WithCustomGrant(handler),
		),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token", clock: clock}

	customClient, customSecret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)
	ccClient, ccSecret := clientCredsClient(t, prov, []string{"read"})

	ccResp := f.post(t, url.Values{"grant_type": []string{"client_credentials"}}, ccClient.ID, ccSecret)
	defer ccResp.Body.Close()
	if ccResp.StatusCode != http.StatusOK {
		t.Fatalf("client_credentials status=%d want 200 body=%v", ccResp.StatusCode, decodeJSON(t, ccResp))
	}
	ccToken, _ := decodeJSON(t, ccResp)["access_token"].(string)
	if strings.Count(ccToken, ".") == 2 {
		t.Errorf("client_credentials access token is JWT-shaped under the opaque format: %q", ccToken)
	}
	if _, err := prov.Store.OpaqueAccessTokens().Find(context.Background(), ccToken); err != nil {
		t.Errorf("opaque shadow row missing for the built-in grant: %v", err)
	}

	cgResp := f.post(t, url.Values{"grant_type": []string{grantURN}}, customClient.ID, customSecret)
	defer cgResp.Body.Close()
	if cgResp.StatusCode != http.StatusOK {
		t.Fatalf("custom grant status=%d want 200 body=%v", cgResp.StatusCode, decodeJSON(t, cgResp))
	}
	cgToken, _ := decodeJSON(t, cgResp)["access_token"].(string)
	parsed, _, err := (&tokens.AccessTokenVerifier{
		Keys:   mustKeySet(t, prov),
		Issuer: prov.Issuer,
		Clock:  clock,
	}).Verify(context.Background(), cgToken)
	if err != nil {
		t.Fatalf("BoundAccessToken must stay a verifiable JWT under the opaque format: %v", err)
	}
	if parsed.Subject != "user-opaque-deployment" {
		t.Errorf("sub=%q want user-opaque-deployment", parsed.Subject)
	}
	if _, ok := decodeJWTPayload(t, cgToken)["act"].(map[string]any); !ok {
		t.Error("act claim missing; the handler-stated claims are the reason this path stays JWT")
	}
}
