package revokeendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/revokeendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// errLookupFault is the sentinel a find-faulty substore returns from
// Find, simulating a transport/backend fault at the lookup step
// itself (as opposed to the flip/revoke step [faultyRefreshStore] and
// [faultyAccessTokenRegistry] already cover).
var errLookupFault = errors.New("simulated lookup outage")

// findFaultRefreshStore wraps an inmem RefreshTokenStore and replaces
// Find with a deterministic non-ErrNotFound error. The old handler
// collapsed any Find error onto the same silent miss as ErrNotFound,
// so a store brown-out at the lookup step never reached the audit
// channel.
type findFaultRefreshStore struct {
	inner store.RefreshTokenStore
}

func (f *findFaultRefreshStore) Save(ctx context.Context, token *store.RefreshToken) error {
	return f.inner.Save(ctx, token)
}

func (f *findFaultRefreshStore) Find(context.Context, string) (*store.RefreshToken, error) {
	return nil, errLookupFault
}

func (f *findFaultRefreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	return f.inner.Consume(ctx, id)
}

func (f *findFaultRefreshStore) RevokeChain(ctx context.Context, rootID string) error {
	return f.inner.RevokeChain(ctx, rootID)
}

func (f *findFaultRefreshStore) RevokeByGrant(ctx context.Context, grantID string) error {
	return f.inner.RevokeByGrant(ctx, grantID)
}

// findFaultOpaqueAccessTokenStore is the opaque-access-token analogue
// of [findFaultRefreshStore].
type findFaultOpaqueAccessTokenStore struct {
	inner store.OpaqueAccessTokenStore
}

func (f *findFaultOpaqueAccessTokenStore) Save(ctx context.Context, tok *store.OpaqueAccessToken) error {
	return f.inner.Save(ctx, tok)
}

func (f *findFaultOpaqueAccessTokenStore) Find(context.Context, string) (*store.OpaqueAccessToken, error) {
	return nil, errLookupFault
}

func (f *findFaultOpaqueAccessTokenStore) RevokeByID(ctx context.Context, id string) error {
	return f.inner.RevokeByID(ctx, id)
}

func (f *findFaultOpaqueAccessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	return f.inner.RevokeByGrant(ctx, grantID)
}

func (f *findFaultOpaqueAccessTokenStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	return f.inner.GC(ctx, cutoff)
}

// TestHandler_RefreshTokenLookup_StoreFault_EmitsAudit pins the
// lookup-step half of the GHSA-7mqr-2v3q-v2wm invariant
// [TestHandler_RefreshToken_StoreFault_EmitsAudit] pins for the
// revoke-step: a RefreshTokens.Find fault must not be collapsed onto
// the same silent miss as ErrNotFound. The wire response stays 200
// (RFC 7009 §2.2), but token.revoke_failed must fire so a store
// brown-out that leaves the token live and unrevoked is observable.
func TestHandler_RefreshTokenLookup_StoreFault_EmitsAudit(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	keyset, err := keys.NewSet([]keys.Entry{{KeyID: "audit-2", Signer: priv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}

	innerStore := inmem.New(inmem.WithClock(clock))

	const clientID = "client-lookup-fault"
	const secret = "lookup-fault-secret"
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	if err := innerStore.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"refresh_token"},
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	capture := newRevokeAuditCapture()
	deps := revokeendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       innerStore.Clients(),
		RefreshTokens: &findFaultRefreshStore{inner: innerStore.RefreshTokens()},
		Keys:          keyset,
		Clock:         clock,
		Audit:         capture.emitter(),
	}
	form := url.Values{
		"token":           {"refresh-lookup-fault-1"},
		"token_type_hint": {"refresh_token"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()

	revokeendpoint.Handler(deps).ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode=%d want 200 (RFC 7009 §2.2)", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("body=%q want empty", body)
	}

	auditRec := capture.findEvent("token.revoke_failed")
	if auditRec == nil {
		t.Fatalf("expected audit event token.revoke_failed, captured=%s", capture.dump())
	}
	if got, _ := auditRec["client_id"].(string); got != clientID {
		t.Errorf("audit client_id=%q want %q", got, clientID)
	}
	extras, ok := auditRec["extras"].(map[string]any)
	if !ok {
		t.Fatalf("audit record missing extras: %v", auditRec)
	}
	if got, _ := extras["surface"].(string); got != "refresh_token_lookup" {
		t.Errorf("extras.surface=%q want refresh_token_lookup", got)
	}
	if got, _ := extras["err"].(string); !strings.Contains(got, errLookupFault.Error()) {
		t.Errorf("extras.err=%q want it to contain %q", got, errLookupFault.Error())
	}
}

// TestHandler_OpaqueAccessTokenLookup_StoreFault_EmitsAudit is the
// opaque-access-token analogue of
// [TestHandler_RefreshTokenLookup_StoreFault_EmitsAudit].
func TestHandler_OpaqueAccessTokenLookup_StoreFault_EmitsAudit(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	keyset, err := keys.NewSet([]keys.Entry{{KeyID: "audit-3", Signer: priv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}

	innerStore := inmem.New(inmem.WithClock(clock))

	const clientID = "client-opaque-lookup-fault"
	const secret = "opaque-lookup-fault-secret" //nolint:gosec // G101: test fixture, not a real credential.
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	if err := innerStore.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"refresh_token"},
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	capture := newRevokeAuditCapture()
	deps := revokeendpoint.Deps{
		Issuer:             "https://op.example",
		Clients:            innerStore.Clients(),
		OpaqueAccessTokens: &findFaultOpaqueAccessTokenStore{inner: innerStore.OpaqueAccessTokens()},
		Keys:               keyset,
		Clock:              clock,
		Audit:              capture.emitter(),
	}
	form := url.Values{
		"token":           {"opaque-lookup-fault-1"},
		"token_type_hint": {"access_token"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()

	revokeendpoint.Handler(deps).ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode=%d want 200 (RFC 7009 §2.2)", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("body=%q want empty", body)
	}

	auditRec := capture.findEvent("token.revoke_failed")
	if auditRec == nil {
		t.Fatalf("expected audit event token.revoke_failed, captured=%s", capture.dump())
	}
	if got, _ := auditRec["client_id"].(string); got != clientID {
		t.Errorf("audit client_id=%q want %q", got, clientID)
	}
	extras, ok := auditRec["extras"].(map[string]any)
	if !ok {
		t.Fatalf("audit record missing extras: %v", auditRec)
	}
	if got, _ := extras["surface"].(string); got != "opaque_access_token_lookup" {
		t.Errorf("extras.surface=%q want opaque_access_token_lookup", got)
	}
	if got, _ := extras["err"].(string); !strings.Contains(got, errLookupFault.Error()) {
		t.Errorf("extras.err=%q want it to contain %q", got, errLookupFault.Error())
	}
}

// secondFindFaultRefreshStore lets the first Find call through to the
// inner store and fails every subsequent Find with errLookupFault.
// revokeOpaque's own RefreshTokens.Find (the first call) has to
// succeed so the handler reaches [findChainRoot], whose walk re-reads
// the same record by ID as hop 0 of the chain walk — this isolates
// that re-lookup's fault from the handler's initial one.
type secondFindFaultRefreshStore struct {
	inner     store.RefreshTokenStore
	findCalls atomic.Int32
}

func (s *secondFindFaultRefreshStore) Save(ctx context.Context, token *store.RefreshToken) error {
	return s.inner.Save(ctx, token)
}

func (s *secondFindFaultRefreshStore) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	if s.findCalls.Add(1) > 1 {
		return nil, errLookupFault
	}
	return s.inner.Find(ctx, id)
}

func (s *secondFindFaultRefreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	return s.inner.Consume(ctx, id)
}

func (s *secondFindFaultRefreshStore) RevokeChain(ctx context.Context, rootID string) error {
	return s.inner.RevokeChain(ctx, rootID)
}

func (s *secondFindFaultRefreshStore) RevokeByGrant(ctx context.Context, grantID string) error {
	return s.inner.RevokeByGrant(ctx, grantID)
}

// TestHandler_ChainRootLookup_StoreFault_EmitsAudit pins the third
// lookup path the invariant names: a hop-0 store fault inside
// [findChainRoot]'s walk (as opposed to the handler's own initial
// RefreshTokens.Find) must not be collapsed into the same silent
// false as a legitimate empty walk. On the old code findChainRoot
// (and the [refreshchain.FindRoot] it wraps) had no error return at
// all, so this fault could never reach the audit channel.
func TestHandler_ChainRootLookup_StoreFault_EmitsAudit(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	keyset, err := keys.NewSet([]keys.Entry{{KeyID: "audit-4", Signer: priv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}

	innerStore := inmem.New(inmem.WithClock(clock))

	const clientID = "client-chain-root-fault"
	const secret = "chain-root-fault-secret"
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	if err := innerStore.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"refresh_token"},
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const refreshID = "refresh-chain-root-fault-1"
	if err := innerStore.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID:        refreshID,
		ClientID:  clientID,
		Subject:   "user-1",
		GrantID:   "grant-chain-root-fault-1",
		CreatedAt: clock.now,
		ExpiresAt: clock.now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}

	capture := newRevokeAuditCapture()
	deps := revokeendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       innerStore.Clients(),
		RefreshTokens: &secondFindFaultRefreshStore{inner: innerStore.RefreshTokens()},
		Keys:          keyset,
		Clock:         clock,
		Audit:         capture.emitter(),
	}
	form := url.Values{
		"token":           {refreshID},
		"token_type_hint": {"refresh_token"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()

	revokeendpoint.Handler(deps).ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode=%d want 200 (RFC 7009 §2.2)", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("body=%q want empty", body)
	}

	auditRec := capture.findEvent("token.revoke_failed")
	if auditRec == nil {
		t.Fatalf("expected audit event token.revoke_failed, captured=%s", capture.dump())
	}
	if got, _ := auditRec["client_id"].(string); got != clientID {
		t.Errorf("audit client_id=%q want %q", got, clientID)
	}
	extras, ok := auditRec["extras"].(map[string]any)
	if !ok {
		t.Fatalf("audit record missing extras: %v", auditRec)
	}
	if got, _ := extras["surface"].(string); got != "refresh_chain_walk" {
		t.Errorf("extras.surface=%q want refresh_chain_walk", got)
	}
	if got, _ := extras["err"].(string); !strings.Contains(got, errLookupFault.Error()) {
		t.Errorf("extras.err=%q want it to contain %q", got, errLookupFault.Error())
	}
}
