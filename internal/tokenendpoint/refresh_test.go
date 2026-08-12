package tokenendpoint_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

var (
	errInjectedOpaqueRevoke = errors.New("injected opaque revoke failure")
	errInjectedGrantFind    = errors.New("injected grant lookup failure")
)

type revokeFailsOpaqueAccessTokenStore struct {
	store.OpaqueAccessTokenStore
}

func (s revokeFailsOpaqueAccessTokenStore) RevokeByGrant(context.Context, string) (int, error) {
	return 0, errInjectedOpaqueRevoke
}

type opaqueRevokeFailStore struct {
	store.Store
}

func (s opaqueRevokeFailStore) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return revokeFailsOpaqueAccessTokenStore{OpaqueAccessTokenStore: s.Store.OpaqueAccessTokens()}
}

// opaqueRevokeFailTransactionalStore keeps the real in-memory transaction
// semantics while injecting the same opaque-AT revoke fault into the
// transaction-bound substore. This lets the retryability test distinguish a
// committed non-Tx Consume from a rollbackable Tx Consume.
type opaqueRevokeFailTransactionalStore struct {
	store.Store
	transactional store.Transactional
}

func (s opaqueRevokeFailTransactionalStore) BeginTx(ctx context.Context) (store.Tx, error) {
	tx, err := s.transactional.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return opaqueRevokeFailTx{Tx: tx}, nil
}

type opaqueRevokeFailTx struct {
	store.Tx
}

func (t opaqueRevokeFailTx) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return revokeFailsOpaqueAccessTokenStore{OpaqueAccessTokenStore: t.Tx.OpaqueAccessTokens()}
}

// failOnceGrantStore is a deterministic fault-injection decorator over the
// real in-memory GrantStore. It fails the first Find only; all persistence and
// subsequent reads remain owned by the reference adapter.
type failOnceGrantStore struct {
	store.GrantStore
	failed atomic.Bool
}

func (s *failOnceGrantStore) Find(ctx context.Context, id string) (*store.Grant, error) {
	if s.failed.CompareAndSwap(false, true) {
		return nil, errInjectedGrantFind
	}
	return s.GrantStore.Find(ctx, id)
}

type grantFindFailsOnceStore struct {
	store.Store
	grants        store.GrantStore
	transactional store.Transactional
	beginCount    *atomic.Int32
	beforeBegin   func()
}

func (s grantFindFailsOnceStore) Grants() store.GrantStore {
	return s.grants
}

func (s grantFindFailsOnceStore) BeginTx(ctx context.Context) (store.Tx, error) {
	s.beginCount.Add(1)
	if s.beforeBegin != nil {
		s.beforeBegin()
	}
	return s.transactional.BeginTx(ctx)
}

// refreshForm builds the canonical refresh_token form body. scope is
// optional; an empty string omits the parameter.
func refreshForm(token, scope string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token)
	if scope != "" {
		form.Set("scope", scope)
	}
	return form
}

// TestRefresh_HappyPath_OIDC seeds an OIDC refresh token and exchanges
// it. The response must rotate the refresh token, mint a new id_token,
// and echo the original scope.
func TestRefresh_HappyPath_OIDC(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-happy"
	const subject = "user-1"
	const grantID = "grant-rt"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "email"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == refreshID {
		t.Errorf("refresh_token must be rotated; got %q (input %q)", rotated, refreshID)
	}
	if _, hasID := body["id_token"]; !hasID {
		t.Errorf("id_token must be issued for openid-scoped refresh")
	}
	if got := body["scope"]; got != "openid email" {
		t.Errorf("scope=%v want openid email", got)
	}
}

func TestRefresh_RequireAuthTime_EmitsAuthTime(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	client.RequireAuthTime = true
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	const refreshID = "rt-require-auth-time"
	const subject = "user-1"
	const grantID = "grant-rt-require-auth-time"
	authTime := f.clock.now.Add(-3 * time.Minute)

	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   subject,
		ClientID:  client.ID,
		Scope:     []string{"openid", "offline_access"},
		AuthTime:  authTime,
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "offline_access"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got := idClaims["auth_time"]; got != float64(authTime.Unix()) {
		t.Fatalf("auth_time=%v want %d", got, authTime.Unix())
	}
}

func TestRefresh_UsesRefreshRecordAuthContextWithoutGrant(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	client.RequireAuthTime = true
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	const refreshID = "rt-record-auth-context"
	authTime := f.clock.now.Add(-7 * time.Minute)
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                   refreshID,
		ClientID:             client.ID,
		Subject:              "user-1",
		GrantID:              "missing-grant-record-context",
		Scope:                []string{"openid", "offline_access"},
		AuthTime:             authTime,
		ACR:                  "urn:acr:pwd",
		AMR:                  []string{"pwd", "otp"},
		AuthorizationDetails: []map[string]any{{"type": "payment"}},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idClaims := decodeIDTokenClaims(t, body["id_token"].(string))
	if got := idClaims["auth_time"]; got != float64(authTime.Unix()) {
		t.Fatalf("auth_time=%v want %d", got, authTime.Unix())
	}
	if got := idClaims["acr"]; got != "urn:acr:pwd" {
		t.Fatalf("acr=%v want urn:acr:pwd", got)
	}
	if _, ok := body["authorization_details"]; !ok {
		t.Fatalf("authorization_details missing from refresh response: %v", body)
	}
}

func TestRefresh_AuthorizationDetailsCanBeReducedAtTokenEndpoint(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-rar-reduce"
	const subject = "user-rar-reduce"
	const grantID = "grant-rar-reduce"
	granted := []map[string]any{
		{"type": "payment", "amount": "100"},
		{"type": "payment", "amount": "200"},
	}
	f.seedGrant(t, &store.Grant{
		ID:                   grantID,
		Subject:              subject,
		ClientID:             client.ID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: granted,
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                   refreshID,
		ClientID:             client.ID,
		Subject:              subject,
		GrantID:              grantID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: granted,
	})

	form := refreshForm(refreshID, "")
	form.Set("authorization_details", `[{"type":"payment","amount":"100"}]`)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	details, ok := body["authorization_details"].([]any)
	if !ok || len(details) != 1 {
		t.Fatalf("authorization_details=%T %[1]v want one reduced element", body["authorization_details"])
	}
	rotated, _ := body["refresh_token"].(string)
	got, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("RefreshTokens.Find(rotated): %v", err)
	}
	if len(got.AuthorizationDetails) != 1 || got.AuthorizationDetails[0]["amount"] != "100" {
		t.Fatalf("rotated authorization_details=%v want amount=100 only", got.AuthorizationDetails)
	}
}

func TestRefresh_AuthorizationDetailsGrantWinsOverStaleRefreshSnapshot(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-rar-stale-snapshot"
	const subject = "user-rar-stale-snapshot"
	const grantID = "grant-rar-stale-snapshot"
	oldDetails := []map[string]any{{"type": "payment", "amount": "100000"}}
	currentDetails := []map[string]any{{"type": "payment", "amount": "10"}}
	f.seedGrant(t, &store.Grant{
		ID:                   grantID,
		Subject:              subject,
		ClientID:             client.ID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: currentDetails,
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                   refreshID,
		ClientID:             client.ID,
		Subject:              subject,
		GrantID:              grantID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: oldDetails,
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	details, ok := body["authorization_details"].([]any)
	if !ok || len(details) != 1 {
		t.Fatalf("authorization_details=%T %[1]v want one current element", body["authorization_details"])
	}
	el, _ := details[0].(map[string]any)
	if el["amount"] != "10" {
		t.Fatalf("response authorization_details=%v want grant amount=10", details)
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	atDetails, ok := claims["authorization_details"].([]any)
	if !ok || len(atDetails) != 1 {
		t.Fatalf("access token authorization_details=%T %[1]v want one current element", claims["authorization_details"])
	}
	atEl, _ := atDetails[0].(map[string]any)
	if atEl["amount"] != "10" {
		t.Fatalf("access token authorization_details=%v want grant amount=10", atDetails)
	}
	rotated, _ := body["refresh_token"].(string)
	got, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("RefreshTokens.Find(rotated): %v", err)
	}
	if len(got.AuthorizationDetails) != 1 || got.AuthorizationDetails[0]["amount"] != "10" {
		t.Fatalf("rotated authorization_details=%v want grant amount=10", got.AuthorizationDetails)
	}
}

func TestRefresh_AuthorizationDetailsOutsideGrantRejected(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-rar-reject"
	const subject = "user-rar-reject"
	const grantID = "grant-rar-reject"
	granted := []map[string]any{{"type": "payment", "amount": "100"}}
	f.seedGrant(t, &store.Grant{
		ID:                   grantID,
		Subject:              subject,
		ClientID:             client.ID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: granted,
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                   refreshID,
		ClientID:             client.ID,
		Subject:              subject,
		GrantID:              grantID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: granted,
	})

	form := refreshForm(refreshID, "")
	form.Set("authorization_details", `[{"type":"payment","amount":"999"}]`)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_authorization_details" {
		t.Fatalf("error=%v want invalid_authorization_details", got)
	}

	rejected, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find(rejected predecessor): %v", err)
	}
	if rejected.ConsumedAt != nil {
		t.Fatalf("authorization_details mismatch consumed predecessor at %v", rejected.ConsumedAt)
	}

	retryForm := refreshForm(refreshID, "")
	retryForm.Set("authorization_details", `[{"type":"payment","amount":"100"}]`)
	retry := f.post(t, retryForm, client.ID, secret)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("conforming retry status=%d want 200 body=%v", retry.StatusCode, decodeJSON(t, retry))
	}
	retryBody := decodeJSON(t, retry)
	retryDetails, ok := retryBody["authorization_details"].([]any)
	if !ok || len(retryDetails) != 1 {
		t.Fatalf("conforming retry authorization_details=%T %[1]v want one detail", retryBody["authorization_details"])
	}
}

func TestRefresh_AuthorizationDetailsStaleSnapshotMismatchDoesNotConsume(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-rar-stale-reject"
	const subject = "user-rar-stale-reject"
	const grantID = "grant-rar-stale-reject"
	staleDetails := []map[string]any{{"type": "payment", "amount": "100000"}}
	currentDetails := []map[string]any{{"type": "payment", "amount": "10"}}
	f.seedGrant(t, &store.Grant{
		ID:                   grantID,
		Subject:              subject,
		ClientID:             client.ID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: currentDetails,
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                   refreshID,
		ClientID:             client.ID,
		Subject:              subject,
		GrantID:              grantID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: staleDetails,
	})

	form := refreshForm(refreshID, "")
	form.Set("authorization_details", `[{"type":"payment","amount":"100000"}]`)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_authorization_details" {
		t.Fatalf("error=%v want invalid_authorization_details", got)
	}
	rejected, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find(rejected predecessor): %v", err)
	}
	if rejected.ConsumedAt != nil {
		t.Fatalf("stale-snapshot mismatch consumed predecessor at %v", rejected.ConsumedAt)
	}

	retry := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("retry status=%d want 200 body=%v", retry.StatusCode, decodeJSON(t, retry))
	}
	retryBody := decodeJSON(t, retry)
	details, ok := retryBody["authorization_details"].([]any)
	if !ok || len(details) != 1 {
		t.Fatalf("retry authorization_details=%T %[1]v want live Grant detail", retryBody["authorization_details"])
	}
	detail, _ := details[0].(map[string]any)
	if detail["amount"] != "10" {
		t.Fatalf("retry authorization_details=%v want live Grant amount=10", details)
	}
}

func TestRefresh_AuthorizationDetailsGrantLookupFaultAndTxBarrierDoNotConsume(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	backing := inmem.New(inmem.WithClock(clock))
	faultingGrants := &failOnceGrantStore{GrantStore: backing.Grants()}
	var beginCount atomic.Int32
	var narrowAtBegin atomic.Bool
	beforeBegin := func() {
		if !narrowAtBegin.CompareAndSwap(false, true) {
			return
		}
		grant, err := backing.Grants().Find(context.Background(), "grant-rar-grant-fault")
		if err != nil {
			panic(fmt.Sprintf("barrier grant lookup: %v", err))
		}
		grant.AuthorizationDetails = []map[string]any{{"type": "payment", "amount": "200"}}
		if err := backing.Grants().Save(context.Background(), grant); err != nil {
			panic(fmt.Sprintf("barrier grant narrow: %v", err))
		}
	}
	provider, err := op.New(testkit.MinimalOptions(t,
		op.WithStore(grantFindFailsOnceStore{
			Store:         backing,
			grants:        faultingGrants,
			transactional: backing,
			beginCount:    &beginCount,
			beforeBegin:   beforeBegin,
		}),
		op.WithClock(clock),
		// Keep this fixture on the transactional refresh path. The
		// authorization-details preflight must fail before BeginTx, so a
		// transient grant lookup fault cannot establish a stale SQL snapshot.
		op.WithGrants(grant.RefreshToken),
		paymentAuthorizationDetailsOption(),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	server := httptest.NewServer(provider)
	t.Cleanup(server.Close)

	const secret = "rar-grant-fault-secret" //nolint:gosec // G101: fixture client secret for a test provider, never a live credential.
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      "client-rar-grant-fault",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid", "offline_access"},
	}
	if err := backing.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const refreshID = "rt-rar-grant-fault"
	const grantID = "grant-rar-grant-fault"
	details := []map[string]any{
		{"type": "payment", "amount": "100"},
		{"type": "payment", "amount": "200"},
	}
	if err := backing.Grants().Save(context.Background(), &store.Grant{
		ID:                   grantID,
		Subject:              "user-rar-grant-fault",
		ClientID:             client.ID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: details,
		CreatedAt:            clock.now,
		UpdatedAt:            clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	if err := backing.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID:                   refreshID,
		ClientID:             client.ID,
		Subject:              "user-rar-grant-fault",
		GrantID:              grantID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: details,
		CreatedAt:            clock.now,
		ExpiresAt:            clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}

	post := func(form url.Values) *http.Response {
		t.Helper()
		req, requestErr := http.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			server.URL+"/oidc/token",
			strings.NewReader(form.Encode()),
		)
		if requestErr != nil {
			t.Fatalf("NewRequest: %v", requestErr)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(client.ID, secret)
		resp, requestErr := server.Client().Do(req)
		if requestErr != nil {
			t.Fatalf("POST /token: %v", requestErr)
		}
		return resp
	}

	form := refreshForm(refreshID, "")
	form.Set("authorization_details", `[{"type":"payment","amount":"100"}]`)
	resp := post(form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("fault status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "server_error" {
		t.Fatalf("fault error=%v want server_error", got)
	}
	if got := beginCount.Load(); got != 0 {
		t.Fatalf("BeginTx called before authorization-details preflight failed: %d", got)
	}
	rejected, err := backing.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find(after fault): %v", err)
	}
	if rejected.ConsumedAt != nil {
		t.Fatalf("grant lookup fault consumed predecessor at %v", rejected.ConsumedAt)
	}

	// The next attempt passes the outer preflight, then narrows the Grant
	// before BeginTx/Consume. The in-transaction barrier must reject the
	// stale requested detail and roll Consume back, rather than committing a
	// response based on the preflight snapshot.
	retry := post(form)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusBadRequest {
		t.Fatalf("barrier retry status=%d want 400 body=%v", retry.StatusCode, decodeJSON(t, retry))
	}
	barrierBody := decodeJSON(t, retry)
	if barrierBody["error"] != "invalid_authorization_details" {
		t.Fatalf("barrier error=%v want invalid_authorization_details", barrierBody["error"])
	}
	rejected, err = backing.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find(after barrier): %v", err)
	}
	if rejected.ConsumedAt != nil {
		t.Fatalf("authorization-details barrier consumed predecessor at %v", rejected.ConsumedAt)
	}

	// The current Grant now authorizes amount=200. A matching retry proves
	// the rollback left the predecessor usable and the barrier did not leak
	// a partial rotation.
	form.Set("authorization_details", `[{"type":"payment","amount":"200"}]`)
	retry = post(form)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("conforming retry status=%d want 200 body=%v", retry.StatusCode, decodeJSON(t, retry))
	}
}

func TestRefresh_RequireAuthTime_MissingAuthTimeFails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	client.RequireAuthTime = true
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	const refreshID = "rt-require-auth-time-missing"
	const subject = "user-1"
	const grantID = "grant-rt-require-auth-time-missing"

	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:       grantID,
		Subject:  subject,
		ClientID: client.ID,
		Scope:    []string{"openid", "offline_access"},
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "offline_access"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "server_error" {
		t.Fatalf("error=%v want server_error", got)
	}
	stored, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("Find after 500: %v", err)
	}
	if stored.ConsumedAt != nil {
		t.Fatalf("refresh token consumed after assembly failure: %+v", stored)
	}
	client.RequireAuthTime = false
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient retry config: %v", err)
	}
	retry := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("retry status=%d want 200 body=%v", retry.StatusCode, decodeJSON(t, retry))
	}
}

// TestRefresh_HappyPath_NonOIDC verifies that a refresh whose original
// grant did not carry "openid" produces no id_token.
func TestRefresh_HappyPath_NonOIDC(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-nooidc"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-nooidc",
		Scope:    []string{"profile"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if _, hasID := body["id_token"]; hasID {
		t.Errorf("id_token must NOT be issued without openid scope")
	}
}

func TestRefresh_ResourcePreservesAudienceAndRotation(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-resource"
	const subject = "user-1"
	const grantID = "grant-rt-resource"
	const resource = "https://api.example.com"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email", "offline_access"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "email", "offline_access"},
		Resource: resource,
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier.Verify(context.Background(), at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != resource {
		t.Fatalf("aud=%v want [%q]", claims.Audience, resource)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" {
		t.Fatal("refresh_token missing")
	}
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.Resource != resource {
		t.Fatalf("refresh resource=%q want %q", rec.Resource, resource)
	}
}

// movableClock advances by mutating a shared time.Time so the OP and
// the test see the same wall-clock readings even after the test has
// stepped forward.
type movableClock struct{ cur *time.Time }

func (c movableClock) Now() time.Time { return *c.cur }

// TestRefresh_Replay verifies that, once the RFC 9700 §2.2.2 grace
// window has elapsed, re-using an already-consumed refresh token
// surfaces invalid_grant AND chain-wide replay defence revokes every
// descendant. The grace path itself is covered by
// TestRefresh_GraceWindow below.
func TestRefresh_Replay(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	prov := testkit.NewProvider(t, testkit.WithClock(movableClock{cur: &cur}))
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: cur},
	}
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-replay"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-replay",
		Scope:    []string{"openid"},
	})

	// First exchange must succeed.
	first := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d want 200", first.StatusCode)
	}
	body := decodeJSON(t, first)
	first.Body.Close()
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" {
		t.Fatal("first exchange did not return a rotated refresh token")
	}

	// Step well past the default 30-second grace window so the second
	// presentation falls onto the strict replay path.
	cur = cur.Add(2 * time.Minute)

	// Replay of the original token must fail and revoke the chain.
	second := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400", second.StatusCode)
	}
	if got := decodeJSON(t, second); got["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got["error"])
	}

	// The freshly-rotated refresh token MUST also fail because the
	// chain-wide revocation walked the descendants.
	third := f.post(t, refreshForm(rotated, ""), client.ID, secret)
	defer third.Body.Close()
	if third.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-revoke status=%d want 400", third.StatusCode)
	}
	if got := decodeJSON(t, third); got["error"] != "invalid_grant" {
		t.Errorf("post-revoke error=%v want invalid_grant", got["error"])
	}
}

// TestRefresh_GraceWindow exercises the RFC 9700 §2.2.2 grace path
// end-to-end at the HTTP layer: a refresh token presented again
// within the configured window re-emits the exact first response, including
// the canonical successor refresh token. This is the recovery guarantee for a
// response lost after the first rotation commit: the retry neither creates a
// second successor nor strands the client after the old token expires.
func TestRefresh_GraceWindow(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	prov := testkit.NewProvider(t, testkit.WithClock(movableClock{cur: &cur}))
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: cur},
	}
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-grace"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-grace",
		Scope:    []string{"openid"},
	})

	first := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d want 200", first.StatusCode)
	}
	firstBody := decodeJSON(t, first)
	first.Body.Close()
	firstAccess, _ := firstBody["access_token"].(string)
	if firstAccess == "" {
		t.Fatal("first response missing access_token")
	}
	firstRefresh, _ := firstBody["refresh_token"].(string)
	if firstRefresh == "" {
		t.Fatal("first response must rotate a refresh token")
	}

	// Step inside the grace window (default 30s).
	cur = cur.Add(5 * time.Second)

	second := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("grace status=%d want 200", second.StatusCode)
	}
	secondBody := decodeJSON(t, second)
	if got, _ := secondBody["refresh_token"].(string); got != firstRefresh {
		t.Errorf("grace refresh_token=%q want canonical successor %q", got, firstRefresh)
	}
	if got, _ := secondBody["access_token"].(string); got == "" {
		t.Error("grace response must include access_token")
	} else if got != firstAccess {
		t.Error("grace response must re-emit the original access_token")
	}
}

// keylessRefreshFixture drives [tokenendpoint.Handler] with a Deps that
// carries no retry-response encryption keys. That is not an incomplete
// wiring: those keys are the cookie keys, which are mandatory only for
// the authorization-code grant, so an OP built around CIBA, the device
// flow, or a custom grant runs without them and its rotations never
// cache a response to replay.
type keylessRefreshFixture struct {
	deps   tokenendpoint.Deps
	store  *inmem.Store
	client *store.Client
	secret string
}

func newKeylessRefreshFixture(t *testing.T, clock movableClock) *keylessRefreshFixture {
	t.Helper()

	const secret = "keyless-refresh-secret"
	s := inmem.New(inmem.WithClock(clock))
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      "client-keyless-refresh",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{grant.RefreshToken.String()},
		Scopes:                  []string{"openid"},
	}
	if err := s.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	entry, err := keys.GenerateES256("keyless-refresh-kid")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	return &keylessRefreshFixture{
		deps: tokenendpoint.Deps{
			Issuer:        "https://op.example",
			Clients:       s,
			Codes:         s.AuthorizationCodes(),
			RefreshTokens: s.RefreshTokens(),
			Grants:        s.Grants(),
			UserStore:     s.Users(),
			AccessTokens:  s.AccessTokens(),
			Keys:          keySet,
			Clock:         clock,
		},
		store:  s,
		client: client,
		secret: secret,
	}
}

func (f *keylessRefreshFixture) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ID, f.secret)
	rec := httptest.NewRecorder()
	tokenendpoint.Handler(f.deps).ServeHTTP(rec, req)
	return rec
}

// decodeRecorderJSON parses a recorded response body as a JSON object.
func decodeRecorderJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := jsonUnmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return body
}

// TestRefresh_GraceWindow_WithoutRetryCache covers the grace window on a
// deployment that has no retry-response cache at all. The window is a
// property of the refresh grant, so it opens for these deployments too,
// but there is nothing cached to re-emit. The retry must then earn the
// same invalid_grant a presentation past the window earns — a spent
// token is spent — rather than a 500 that reads as an OP fault and
// tells the client to try again.
func TestRefresh_GraceWindow_WithoutRetryCache(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newKeylessRefreshFixture(t, movableClock{cur: &cur})
	const refreshID = "rt-keyless-grace"
	if err := f.store.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID:        refreshID,
		ClientID:  f.client.ID,
		Subject:   "user-1",
		GrantID:   "grant-keyless-grace",
		Scope:     []string{"openid"},
		CreatedAt: cur,
		ExpiresAt: cur.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}

	first := f.post(t, refreshForm(refreshID, ""))
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d want 200, body=%s", first.Code, first.Body.String())
	}
	successor, _ := decodeRecorderJSON(t, first)["refresh_token"].(string)
	if successor == "" {
		t.Fatal("first exchange did not rotate a refresh token")
	}

	// Step inside the default 30-second grace window.
	cur = cur.Add(5 * time.Second)

	second := f.post(t, refreshForm(refreshID, ""))
	if second.Code == http.StatusInternalServerError {
		t.Fatalf("grace retry without a cache returned 500: %s", second.Body.String())
	}
	if second.Code != http.StatusBadRequest {
		t.Fatalf("grace retry status=%d want 400, body=%s", second.Code, second.Body.String())
	}
	if got := decodeRecorderJSON(t, second)["error"]; got != "invalid_grant" {
		t.Errorf("grace retry error=%v want invalid_grant", got)
	}

	// The refused retry must leave the chain alone: the successor the
	// first exchange handed out is still the live token.
	third := f.post(t, refreshForm(successor, ""))
	if third.Code != http.StatusOK {
		t.Fatalf("successor status=%d want 200 (the refused retry must not revoke the chain), body=%s",
			third.Code, third.Body.String())
	}
}

// TestRefresh_ScopeWidening enforces RFC 6749 §6.
func TestRefresh_ScopeWidening(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-widen"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-widen",
		Scope:    []string{"openid"},
	})

	resp := f.post(t, refreshForm(refreshID, "openid email"), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp); got["error"] != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got["error"])
	}
}

// TestRefresh_ScopeNarrowing returns 200 with the narrowed scope echoed
// back to the caller.
func TestRefresh_ScopeNarrowing(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-narrow"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-narrow",
		Scope:    []string{"openid", "email", "profile"},
	})

	resp := f.post(t, refreshForm(refreshID, "openid"), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["scope"]; got != "openid" {
		t.Errorf("scope=%v want openid", got)
	}
}

// scopedFixture builds a fresh fixture whose op.Provider has a custom
// scope registered with an AllowedClients allowlist that excludes the
// confidential test client. The lookup is plumbed through op.New →
// scoperegistry.New → tokenendpoint.Deps.Scopes; this exercises the
// full wire-up rather than the ExchangerConfig in isolation.
func scopedFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithScope(op.Scope{
			Name:           "billing:write",
			Public:         true,
			AllowedClients: []string{"svc-billing"},
		})),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// TestRefresh_ScopeAllowedClients_Rejected verifies that the
// /token endpoint enforces the AllowedClients allowlist. The
// confidential client requests a scope locked to a different client and
// MUST be rejected with invalid_scope before the refresh token is
// consumed.
func TestRefresh_ScopeAllowedClients_Rejected(t *testing.T) {
	t.Parallel()

	f := scopedFixture(t)
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "client-conf",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid", "profile", "email", "billing:write"},
	})

	const refreshID = "rt-allowlist"
	f.seedGrant(t, &store.Grant{
		ID: "grant-allowlist", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "billing:write"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-allowlist",
		Scope:    []string{"openid", "billing:write"},
	})

	resp := f.post(t, refreshForm(refreshID, "openid billing:write"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}

	// The presented refresh token MUST still be intact: the allowlist
	// check runs before refresh.Exchanger.Exchange, so the record's
	// ConsumedAt should remain nil and a subsequent allowlist-clean
	// request must succeed against the same token.
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find after rejection: %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Fatalf("refresh token must not be consumed on allowlist rejection (ConsumedAt=%v)", rec.ConsumedAt)
	}
}

// TestRefresh_ScopeAllowedClients_RejectedWhenScopeOmitted verifies the
// token endpoint enforces AllowedClients on the final refreshed scope,
// even when the request omits the optional scope parameter and reuses
// the refresh token's bound scope.
func TestRefresh_ScopeAllowedClients_RejectedWhenScopeOmitted(t *testing.T) {
	t.Parallel()

	f := scopedFixture(t)
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "client-conf",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid", "profile", "email", "billing:write"},
	})
	const refreshID = "rt-allowlist-omitted"
	f.seedGrant(t, &store.Grant{
		ID: "grant-allowlist-omitted", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "billing:write"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-allowlist-omitted",
		Scope:    []string{"openid", "billing:write"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find after rejection: %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Fatalf("refresh token must not be consumed on omitted-scope allowlist rejection (ConsumedAt=%v)", rec.ConsumedAt)
	}
}

// TestRefresh_ScopeAllowedClients_Permitted is the positive
// counterpart: the same registry, but the requesting client is on the
// allowlist. The refresh succeeds and the rotated token is returned.
func TestRefresh_ScopeAllowedClients_Permitted(t *testing.T) {
	t.Parallel()

	f := scopedFixture(t)
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "svc-billing",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid", "billing:write"},
	})

	const refreshID = "rt-allowlist-ok"
	f.seedGrant(t, &store.Grant{
		ID: "grant-allowlist-ok", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "billing:write"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-allowlist-ok",
		Scope:    []string{"openid", "billing:write"},
	})

	resp := f.post(t, refreshForm(refreshID, "openid billing:write"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got, _ := body["refresh_token"].(string); got == "" {
		t.Errorf("refresh_token must rotate on allowlist-permitted refresh: %v", body)
	}
}

// Note: authorization_code grant does not accept a scope reduction at
// /token (the granted scope is bound to the issued code at /authorize).
// The AllowedClients allowlist is therefore enforced upstream by the
// authorize endpoint; no /token-side authcode test is required for
// allowlist coverage.

// TestRefresh_HonoursClaimsRequest_IDToken verifies that an OIDC Core
// 1.0 §5.5 "claims" request payload persisted on the originating grant
// is honoured by the refresh-derived id_token. The grant carries an
// id_token request for "email"; the user store has the matching value;
// the refreshed id_token MUST surface the claim. Without the projector
// wired through the refresh path the claim was silently dropped.
func TestRefresh_HonoursClaimsRequest_IDToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-claims"
	const subject = "user-claims"
	const grantID = "grant-claims"

	f.prov.Store.PutUser(context.Background(), &store.User{
		Subject: subject,
		Claims:  map[string]any{"email": "user@example.com"},
	})
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
		Claims: map[string]any{
			"request": map[string]any{
				"id_token": map[string]any{
					"email": map[string]any{"essential": true},
				},
			},
		},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got := idClaims["email"]; got != "user@example.com" {
		t.Errorf("id_token.email=%v want user@example.com (claims request not honoured on refresh path)", got)
	}
}

func TestRefresh_IDTokenOmitsACRWhenClaimsRequestDisallowsStoredACR(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-claims-acr"
	const subject = "user-claims-acr"
	const grantID = "grant-claims-acr"

	f.seedGrant(t, &store.Grant{
		ID:       grantID,
		Subject:  subject,
		ClientID: client.ID,
		Scope:    []string{"openid"},
		ACR:      "urn:acr:low",
		Claims: map[string]any{
			"request": map[string]any{
				"id_token": map[string]any{
					"acr": map[string]any{
						"essential": true,
						"values":    []any{"urn:acr:high"},
					},
				},
			},
		},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got, ok := idClaims["acr"]; ok {
		t.Errorf("id_token acr=%v should be omitted when stored acr fails claims constraint", got)
	}
}

// opaqueRefreshFixture builds a refresh-token fixture wired with the
// opaque access-token format option. Tests use it to verify that
// rotation revokes the prior opaque AT atomically with the new mint,
// and to pin that the JWT-path regression test below sees no such
// revocation.
func opaqueRefreshFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithAccessTokenFormat(op.AccessTokenFormatOpaque)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// TestRefresh_OpaqueFormat_RotationRevokesPriorAT pins the
// Refresh-rotation revocation of prior AT contract: when the chain is
// opaque-format, rotation revokes every opaque AT bound to the
// originating GrantID atomically with the new mint, so the
// stolen-but-still-valid window collapses to clock-skew. The JWT path
// is covered by the regression test below to confirm the new
// behaviour does not bleed across formats.
func TestRefresh_OpaqueFormat_RotationRevokesPriorAT(t *testing.T) {
	t.Parallel()

	f := opaqueRefreshFixture(t)
	client, secret := f.confidentialClientFixture(t)

	const refreshID = "rt-opaque-rotate"
	const subject = "user-opaque-rotate"
	const grantID = "grant-opaque-rotate"
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	// Pre-seed an opaque AT row tied to the same grant so the rotation
	// has a "prior AT" to revoke. In production the seed lands during
	// the originating /authorize → /token exchange; the test pre-seeds
	// to keep the assertion focused on the rotation step alone.
	const priorAT = "prior-opaque-token-prior-opaque-token-12345"
	if err := f.prov.Store.OpaqueAccessTokens().Save(context.Background(), &store.OpaqueAccessToken{
		ID:        priorAT,
		GrantID:   grantID,
		Subject:   subject,
		ClientID:  client.ID,
		Scope:     []string{"openid"},
		Audience:  f.prov.Issuer,
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	newAT, _ := body["access_token"].(string)
	if newAT == "" {
		t.Fatal("access_token missing")
	}
	if newAT == priorAT {
		t.Fatal("rotation must mint a fresh access token")
	}

	// Prior AT row MUST now be revoked.
	prior, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), priorAT)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(prior): %v", err)
	}
	if !prior.Revoked {
		t.Errorf("prior opaque AT must be revoked after rotation (Revoked=%v)", prior.Revoked)
	}

	// New AT row MUST be active.
	fresh, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), newAT)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(new): %v", err)
	}
	if fresh.Revoked {
		t.Errorf("freshly-minted opaque AT must be active (Revoked=%v)", fresh.Revoked)
	}
	if fresh.GrantID != grantID {
		t.Errorf("fresh.GrantID=%q want %q", fresh.GrantID, grantID)
	}
}

// TestRefresh_OpaqueRevokeFailureDoesNotMintFreshAT pins the fail-closed
// side of opaque refresh rotation. A failed prior-token cascade must surface
// as a server error before the endpoint creates and returns a second live
// bearer credential.
func TestRefresh_OpaqueRevokeFailureDoesNotMintFreshAT(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	backing := inmem.New(inmem.WithClock(clock))
	capture := newAuditCapture()
	provider, err := op.New(testkit.MinimalOptions(t,
		op.WithStore(opaqueRevokeFailStore{Store: backing}),
		op.WithClock(clock),
		op.WithAuditLogger(capture.logger()),
		// Exercise the non-transactional fault decorator. Enabling the
		// browser authorization-code flow would correctly require the
		// wrapper to advertise store.Transactional.
		op.WithGrants(grant.RefreshToken),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	server := httptest.NewServer(provider)
	t.Cleanup(server.Close)

	const secret = "opaque-revoke-failure-secret" //nolint:gosec // G101: fixture client secret for a test provider, never a live credential.
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      "client-opaque-revoke-failure",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid"},
	}
	if err := backing.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const grantID = "grant-opaque-revoke-failure"
	const refreshID = "rt-opaque-revoke-failure"
	const priorAT = "prior-opaque-revoke-failure-token-123456"
	if err := backing.Grants().Save(context.Background(), &store.Grant{
		ID: grantID, Subject: "user-opaque-revoke-failure", ClientID: client.ID,
		Scope: []string{"openid"}, CreatedAt: clock.now, UpdatedAt: clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	if err := backing.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID: refreshID, ClientID: client.ID, Subject: "user-opaque-revoke-failure",
		GrantID: grantID, Scope: []string{"openid"}, CreatedAt: clock.now,
		ExpiresAt: clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}
	if err := backing.OpaqueAccessTokens().Save(context.Background(), &store.OpaqueAccessToken{
		ID: priorAT, GrantID: grantID, Subject: "user-opaque-revoke-failure",
		ClientID: client.ID, Scope: []string{"openid"}, Audience: testkit.DefaultIssuer,
		IssuedAt: clock.now, ExpiresAt: clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}

	form := refreshForm(refreshID, "")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, secret)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if body["error"] != "server_error" {
		t.Errorf("error=%v want server_error", body["error"])
	}
	if _, ok := body["access_token"]; ok {
		t.Errorf("response must not contain a fresh access_token: %v", body)
	}
	prior, err := backing.OpaqueAccessTokens().Find(context.Background(), priorAT)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(prior): %v", err)
	}
	if prior.Revoked {
		t.Error("injected revoke failure must not claim the prior token was revoked")
	}
	rec := capture.findEvent(t, "refresh.prior_access_token_revoke_failed")
	if rec == nil {
		t.Fatalf("prior access-token revoke failure audit event missing: %s", capture.buf.String())
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil || extras["failure_stage"] != "prior_access_token_revoke" || extras["retryable"] != false {
		t.Fatalf("failure audit extras=%v want fixed stage/retryable=false on committed non-Tx consume", extras)
	}
	for key := range extras {
		if key == "error" || strings.Contains(key, "token") || strings.Contains(key, "secret") {
			t.Errorf("failure audit carries sensitive extra %q", key)
		}
	}
}

// TestRefresh_OpaqueRevokeFailureInTxIsRetryable pins the transactional
// counterpart: the prior opaque-AT revoke fails after Consume, but the whole
// exchange is still staged. The deferred rollback leaves the predecessor
// redeemable, so the audit event may truthfully mark recovery as retryable.
func TestRefresh_OpaqueRevokeFailureInTxIsRetryable(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	backing := inmem.New(inmem.WithClock(clock))
	capture := newAuditCapture()
	provider, err := op.New(testkit.MinimalOptions(t,
		op.WithStore(opaqueRevokeFailTransactionalStore{
			Store:         backing,
			transactional: backing,
		}),
		op.WithClock(clock),
		op.WithAuditLogger(capture.logger()),
		op.WithGrants(grant.RefreshToken),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	server := httptest.NewServer(provider)
	t.Cleanup(server.Close)

	const secret = "opaque-revoke-failure-tx-secret" //nolint:gosec // G101: test fixture credential.
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      "client-opaque-revoke-failure-tx",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid"},
	}
	if err := backing.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const grantID = "grant-opaque-revoke-failure-tx"
	const refreshID = "rt-opaque-revoke-failure-tx"
	const priorAT = "prior-opaque-revoke-failure-tx-token-123456"
	if err := backing.Grants().Save(context.Background(), &store.Grant{
		ID: grantID, Subject: "user-opaque-revoke-failure-tx", ClientID: client.ID,
		Scope: []string{"openid"}, CreatedAt: clock.now, UpdatedAt: clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	if err := backing.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID: refreshID, ClientID: client.ID, Subject: "user-opaque-revoke-failure-tx",
		GrantID: grantID, Scope: []string{"openid"}, CreatedAt: clock.now,
		ExpiresAt: clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}
	if err := backing.OpaqueAccessTokens().Save(context.Background(), &store.OpaqueAccessToken{
		ID: priorAT, GrantID: grantID, Subject: "user-opaque-revoke-failure-tx",
		ClientID: client.ID, Scope: []string{"openid"}, Audience: testkit.DefaultIssuer,
		IssuedAt: clock.now, ExpiresAt: clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}

	form := refreshForm(refreshID, "")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, secret)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if body := decodeJSON(t, resp); body["access_token"] != nil {
		t.Fatalf("response must not contain a fresh access_token: %v", body)
	}
	rec, err := backing.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find(predecessor): %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Fatalf("transactional revoke failure consumed predecessor at %v", rec.ConsumedAt)
	}
	prior, err := backing.OpaqueAccessTokens().Find(context.Background(), priorAT)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(prior): %v", err)
	}
	if prior.Revoked {
		t.Fatal("rolled-back revoke failure must not claim the prior token was revoked")
	}
	record := capture.findEvent(t, "refresh.prior_access_token_revoke_failed")
	if record == nil {
		t.Fatalf("prior access-token revoke failure audit event missing: %s", capture.buf.String())
	}
	extras, _ := record["extras"].(map[string]any)
	if extras == nil || extras["failure_stage"] != "prior_access_token_revoke" || extras["retryable"] != true {
		t.Fatalf("failure audit extras=%v want fixed stage/retryable=true in Tx", extras)
	}
}

// TestRefresh_JWTFormat_RotationDoesNotRevokePriorAT is the
// regression pin for the asymmetry in refresh-rotation revocation:
// only the opaque path revokes the prior access token. The JWT path
// deliberately leaves it alive, because revoking it would force
// resource servers to call introspection on every JWT — defeating the
// registry-driven optimisation that is the whole reason to issue JWT
// access tokens. The test seeds a registry row, runs a refresh
// rotation under the JWT default, and asserts the prior row's Revoked
// flag stayed false.
func TestRefresh_JWTFormat_RotationDoesNotRevokePriorAT(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)

	const refreshID = "rt-jwt-rotate"
	const subject = "user-jwt-rotate"
	const grantID = "grant-jwt-rotate"
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	const priorJTI = "prior-jti-jwt-rotation-test"
	if err := f.prov.Store.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
		JTI:       priorJTI,
		GrantID:   grantID,
		Subject:   subject,
		ClientID:  client.ID,
		Scopes:    []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AccessTokens.Register: %v", err)
	}

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}

	// JWT path: prior registry row stays active. Verify by finding the
	// row and checking the Revoked flag.
	prior, err := f.prov.Store.AccessTokens().Find(context.Background(), priorJTI)
	if err != nil {
		t.Fatalf("AccessTokens.Find: %v", err)
	}
	if prior.Revoked {
		t.Errorf("prior JWT registry row must NOT be revoked on JWT-path rotation (Revoked=%v)", prior.Revoked)
	}
}

// TestRefresh_GrantTombstoned_MintRefused pins the mint- refusal
// contract: under [op.RevocationStrategyGrantTombstone] (the default)
// a refresh request whose underlying grant has been tombstoned MUST
// fail with invalid_grant BEFORE a fresh access token is signed. This
// closes the race window where a refresh racing a code-replay or
// end-session cascade could slip a fresh AT through ahead of the
// tombstone's observable effect on resource-server lookups.
//
// The test seeds a refresh token whose CreatedAt anchors the chain's
// IssuedAt, writes a tombstone whose RevokedAt is at-or-after that
// anchor, and verifies the next /token call returns invalid_grant.
// The exchanger consumes the refresh token before the mint-refusal
// check fires, so the response code is invalid_grant per RFC 6749
// §5.2 (the grant was legitimately revoked, not a request-shape
// fault).
func TestRefresh_GrantTombstoned_MintRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-tombstoned"
	const grantID = "grant-tombstoned-mint-refused"
	const subject = "user-tombstoned"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:        refreshID,
		ClientID:  client.ID,
		Subject:   subject,
		GrantID:   grantID,
		Scope:     []string{"openid", "offline_access"},
		CreatedAt: f.clock.now.Add(-time.Minute),
	})

	// Pre-tombstone the grant. RevokedAt is the same instant the test
	// clock reads, which is at-or-after the refresh token's CreatedAt
	// (one minute earlier), so the verifier's "iat <= RevokedAt" rule
	// trips on the consumed chain.
	if err := f.prov.Store.GrantRevocations().RevokeGrant(context.Background(), store.GrantTombstone{
		GrantID:   grantID,
		RevokedAt: f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
		Reason:    "operator",
	}); err != nil {
		t.Fatalf("GrantRevocations.RevokeGrant: %v", err)
	}

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
	// The response MUST NOT carry an access_token: the mint-refusal
	// check fires before signing.
	if _, has := body["access_token"]; has {
		t.Errorf("access_token must not be present after mint-refusal: %v", body)
	}
}

// TestRefresh_GrantNotTombstoned_MintAllowed is the negative
// counterpart to TestRefresh_GrantTombstoned_MintRefused: a refresh
// whose underlying grant has NO tombstone proceeds normally under
// the default [op.RevocationStrategyGrantTombstone]. The check
// returns false from IsRevoked and the issuance path runs to
// completion.
func TestRefresh_GrantNotTombstoned_MintAllowed(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-not-tombstoned"
	const grantID = "grant-not-tombstoned"
	const subject = "user-not-tombstoned"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if at, _ := body["access_token"].(string); at == "" {
		t.Errorf("access_token missing on un-tombstoned refresh: %v", body)
	}
}

// TestRefresh_GidClaim_PresentOnRotatedAT pins the wire invariant on
// the refresh path: the rotated access token carries the originating
// GrantID in its "gid" private claim, identically to the
// authorization_code-derived AT (see
// TestAuthCode_GidClaim_PresentOnIssuedAT). The claim survives
// rotation because the strategy controls Register / cascade behaviour
// only, not the claim, and the originating GrantID is preserved on
// the refresh-token record across rotations.
func TestRefresh_GidClaim_PresentOnRotatedAT(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const refreshID = "rt-gid"
	const grantID = "grant-rt-gid"
	const subject = "user-rt-gid"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier.Verify(context.Background(), at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	if claims.GrantID != grantID {
		t.Errorf("gid claim=%q want %q", claims.GrantID, grantID)
	}
}

// TestRefresh_NoncePreservedAcrossRotation asserts that the rotated
// id_token carries the original authorize-time nonce. OpenID Connect
// Core 1.0 §12 mandates: "if a nonce value was sent in the
// Authentication Request, a nonce Claim MUST be present and its value
// checked to verify that it is the same value as the one that was
// sent". The seeded refresh token records the originating nonce; the
// handler MUST stamp it onto the rotated id_token AND propagate it
// onto the next-generation refresh-token record so the chain survives
// arbitrarily many rotations.
func TestRefresh_NoncePreservedAcrossRotation(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const (
		refreshID = "rt-nonce-preserve"
		subject   = "user-1"
		grantID   = "grant-rt-nonce-preserve"
		nonce     = "n-0S6_WzA2Mj-original"
	)

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "offline_access"},
		Nonce:    nonce,
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got := idClaims["nonce"]; got != nonce {
		t.Fatalf("rotated id_token nonce=%v want %q", got, nonce)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == refreshID {
		t.Fatalf("refresh_token was not rotated: got %q (input %q)", rotated, refreshID)
	}
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.Nonce != nonce {
		t.Fatalf("rotated refresh-token record Nonce=%q want %q (chain must propagate)", rec.Nonce, nonce)
	}
}

// TestRefresh_NonceAbsent_OmitsClaim asserts that a refresh-token
// chain whose originating authorize request did not carry a nonce
// produces an id_token without a nonce claim. OIDC Core 1.0 §12 only
// requires the claim "if a nonce value was sent"; emitting an empty
// nonce on the wire would be a spec violation in the opposite
// direction.
func TestRefresh_NonceAbsent_OmitsClaim(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const (
		refreshID = "rt-no-nonce"
		subject   = "user-1"
		grantID   = "grant-rt-no-nonce"
	)

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
		// Nonce intentionally empty.
	})

	resp := f.post(t, refreshForm(refreshID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got, present := idClaims["nonce"]; present {
		t.Fatalf("id_token must omit nonce when chain has none; got %v", got)
	}
}

// TestRefresh_MissingToken yields invalid_request when the body omits
// refresh_token.
func TestRefresh_MissingToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp); got["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got["error"])
	}
}
