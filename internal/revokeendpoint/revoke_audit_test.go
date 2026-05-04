package revokeendpoint_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/revokeendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// errStoreFault is the sentinel a faultyRefreshStore.RevokeChain
// returns; the test asserts the audit event surfaces this exact
// error string in the Extras map.
var errStoreFault = errors.New("simulated storage outage")

// faultyRefreshStore wraps an inmem RefreshTokenStore and replaces
// RevokeChain with a deterministic non-nil error, simulating the
// fosite GHSA-7mqr-2v3q-v2wm class: the OP claims revocation success
// while persistence broke. The other methods delegate verbatim so the
// handler's lookup / chain walk reach the RevokeChain call site.
type faultyRefreshStore struct {
	inner store.RefreshTokenStore
}

type faultyAccessTokenRegistry struct {
	inner store.AccessTokenRegistry
}

func (f *faultyRefreshStore) Save(ctx context.Context, token *store.RefreshToken) error {
	return f.inner.Save(ctx, token)
}

func (f *faultyRefreshStore) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	return f.inner.Find(ctx, id)
}

func (f *faultyRefreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	return f.inner.Consume(ctx, id)
}

func (f *faultyRefreshStore) RevokeChain(_ context.Context, _ string) error {
	return errStoreFault
}

func (f *faultyRefreshStore) RevokeByGrant(_ context.Context, _ string) error {
	return errStoreFault
}

func (f *faultyAccessTokenRegistry) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	return f.inner.Register(ctx, rec)
}

func (f *faultyAccessTokenRegistry) Find(ctx context.Context, jti string) (*store.AccessTokenRecord, error) {
	return f.inner.Find(ctx, jti)
}

func (f *faultyAccessTokenRegistry) RevokeByJTI(_ context.Context, _ string) error {
	return errStoreFault
}

func (f *faultyAccessTokenRegistry) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	return f.inner.RevokeByGrant(ctx, grantID)
}

func (f *faultyAccessTokenRegistry) GC(ctx context.Context, cutoff time.Time) (int, error) {
	return f.inner.GC(ctx, cutoff)
}

// TestHandler_RefreshToken_StoreFault_EmitsAudit pins the structural
// mitigation for the fosite "revoke silently swallowed storage errors"
// class: when RefreshTokenStore.RevokeChain returns a non-NotFound
// error, the wire response stays HTTP 200 (RFC 7009 §2.2 mandates
// this — disclosure equivalence between "unknown token" and "store
// fault" prevents enumeration), but the OP MUST raise the
// "token.revoke_failed" audit event so SOC tooling can detect that a
// revoke request was acknowledged on the wire while persistence broke.
//
// Tracks: GHSA-7mqr-2v3q-v2wm (ory/fosite) — the original advisory
// pre-dates audit-emitter plumbing in fosite; the structural defect
// is "no observable signal that revocation failed". The library's
// posture (CLAUDE.md "ライブラリ性の核": observability for OIDC-domain
// events is the OP's responsibility) forbids the silent-swallow path
// even though RFC 7009 §2.2 still requires the wire 200.
//
// The two halves of the assertion:
//
//  1. resp.StatusCode == 200, body empty, Cache-Control: no-store —
//     RFC 7009 §2.2 wire compliance preserved.
//  2. capture.findEvent("token.revoke_failed") != nil with matching
//     client_id and the error string carried in Extras["err"] —
//     proves the silent-swallow path is observable to operators.
func TestHandler_RefreshToken_StoreFault_EmitsAudit(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	keyset, err := keys.NewSet([]keys.Entry{{KeyID: "audit-1", Signer: priv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}

	innerStore := inmem.New(inmem.WithClock(clock))

	const clientID = "client-revoke-fault"
	const secret = "revoke-fault-secret"
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

	// Seed a refresh token whose ID we will revoke. The inmem store
	// hashes the bearer string into the ID column; the bearer string
	// itself is the wire value the test posts.
	const refreshID = "refresh-fault-1"
	const grantID = "grant-fault-1"
	if err := innerStore.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID:        refreshID,
		ClientID:  clientID,
		Subject:   "user-1",
		GrantID:   grantID,
		CreatedAt: clock.now,
		ExpiresAt: clock.now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}

	capture := newRevokeAuditCapture()
	deps := revokeendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       innerStore.Clients(),
		RefreshTokens: &faultyRefreshStore{inner: innerStore.RefreshTokens()},
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

	// RFC 7009 §2.2 wire compliance: wire stays 200 even though
	// persistence broke. A regression that flips this to 5xx would
	// also be a defect (it leaks the failure mode to a cross-client
	// revoker), so we pin both halves.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode=%d want 200 (RFC 7009 §2.2)", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("body=%q want empty", body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}

	// Audit event MUST surface so SOC tooling can detect the
	// silent-swallow path. Without this assertion the test passes
	// even if the handler regresses to fosite's defect.
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
	if got, _ := extras["surface"].(string); got != "refresh_chain" {
		t.Errorf("extras.surface=%q want refresh_chain", got)
	}
	if got, _ := extras["err"].(string); !strings.Contains(got, errStoreFault.Error()) {
		t.Errorf("extras.err=%q want it to contain %q", got, errStoreFault.Error())
	}
	if got, _ := auditRec["level"].(string); !strings.EqualFold(got, "ERROR") {
		t.Errorf("audit level=%q want ERROR", got)
	}
}

func TestHandler_JWTAccessToken_StoreFault_EmitsAudit(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	keyset, err := keys.NewSet([]keys.Entry{{KeyID: "audit-jwt-1", Signer: priv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	innerStore := inmem.New(inmem.WithClock(clock))

	const clientID = "client-revoke-jwt-fault"
	const secret = "revoke-jwt-fault-secret" //nolint:gosec // not a credential — opaque test fixture secret.
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	if err := innerStore.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const jti = "jwt-fault-jti-1"
	const grantID = "jwt-fault-grant-1"
	if err := innerStore.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
		JTI:       jti,
		GrantID:   grantID,
		Subject:   "user-1",
		ClientID:  clientID,
		Scopes:    []string{"openid"},
		IssuedAt:  clock.now,
		ExpiresAt: clock.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AccessTokens.Register: %v", err)
	}
	raw, err := tokens.SignAccessToken(tokens.SigningKey{KeyID: "audit-jwt-1", Signer: priv}, tokens.AccessTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-1",
		Audience:  []string{"https://op.example"},
		ClientID:  clientID,
		IssuedAt:  clock.now.Unix(),
		ExpiresAt: clock.now.Add(time.Hour).Unix(),
		JTI:       jti,
		GrantID:   grantID,
		Scope:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	capture := newRevokeAuditCapture()
	deps := revokeendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       innerStore.Clients(),
		RefreshTokens: innerStore.RefreshTokens(),
		Keys:          keyset,
		Clock:         clock,
		AccessTokens:  &faultyAccessTokenRegistry{inner: innerStore.AccessTokens()},
		Audit:         capture.emitter(),
	}

	form := url.Values{"token": {raw}, "token_type_hint": {"access_token"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()

	revokeendpoint.Handler(deps).ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
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
	if got, _ := extras["surface"].(string); got != "jwt_access_token" {
		t.Errorf("extras.surface=%q want jwt_access_token", got)
	}
	if got, _ := extras["err"].(string); !strings.Contains(got, errStoreFault.Error()) {
		t.Errorf("extras.err=%q want it to contain %q", got, errStoreFault.Error())
	}
}

// revokeAuditCapture wraps a slog logger that emits audit events as
// JSON records into a bytes.Buffer. Mirrors the auditCapture pattern
// in internal/tokenendpoint/audit_test.go but is local to the revoke
// suite so the two test packages stay independent.
type revokeAuditCapture struct {
	buf *bytes.Buffer
}

func newRevokeAuditCapture() *revokeAuditCapture {
	return &revokeAuditCapture{buf: &bytes.Buffer{}}
}

func (c *revokeAuditCapture) emitter() audit.Emitter {
	return audit.Slog(slog.New(slog.NewJSONHandler(c.buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

func (c *revokeAuditCapture) findEvent(name string) map[string]any {
	dec := json.NewDecoder(strings.NewReader(c.buf.String()))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			return nil
		}
		if rec["audit"] != "true" {
			continue
		}
		if rec["event"] == name {
			return rec
		}
	}
	return nil
}

func (c *revokeAuditCapture) dump() string { return c.buf.String() }
