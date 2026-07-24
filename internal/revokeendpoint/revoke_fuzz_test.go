package revokeendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/revokeendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// FuzzRevokeFormBody exercises only the unauthenticated request envelope:
// method/content-type checks, the bounded form parser, duplicate detection, and
// client-credential parsing. It intentionally cannot claim token-verifier or
// store reachability because no client is registered. The authenticated token
// and cascade paths belong to [FuzzRevokeAuthenticatedToken].
func FuzzRevokeFormBody(f *testing.F) {
	server := newRevokeParserFuzzServer(f)

	for _, seed := range revokeFormSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body string) {
		resp := postRevokeFuzzBody(t, server, body)
		defer resp.Body.Close()
		defer drainRevokeFuzzResponse(resp)

		assertRevokeFuzzStatus(t, resp, body,
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusRequestEntityTooLarge,
		)
		assertRevokeFuzzNoStore(t, resp, body)
	})
}

// FuzzRevokeAuthenticatedToken authenticates a registered public client
// before feeding mutated token bytes and hints to the revocation dispatcher.
// The in-memory reference store is the observable:
//
//   - a live signed AT must pass JWT verification and flip its JTI row;
//   - an expired signed AT must fail verification and leave its JTI row live;
//   - a live RT root must revoke its descendant plus JWT and opaque ATs issued
//     under the same grant;
//   - an already-consumed RT must still be located and receive the same
//     grant-wide cascade.
//
// These state assertions make a future regression that stops at client
// authentication or at token-shape dispatch fail even though RFC 7009 keeps
// every wire response disclosure-equivalent.
func FuzzRevokeAuthenticatedToken(f *testing.F) {
	fixture := newAuthenticatedRevokeFuzzFixture(f)

	f.Add(fixture.liveJWT, "access_token")
	f.Add(fixture.expiredJWT, "access_token")
	f.Add(fixture.liveRT, "refresh_token")
	f.Add(fixture.consumedRT, "refresh_token")
	f.Add("eyJhbGciOiJub25lIn0.e30.", "access_token")
	f.Add(strings.Repeat("X", 1<<14), "unknown")

	f.Fuzz(func(t *testing.T, token, hint string) {
		form := url.Values{
			"client_id": {fixture.clientID},
			"token":     {token},
		}
		if hint != "" {
			form.Set("token_type_hint", hint)
		}
		encoded := form.Encode()
		resp := postRevokeFuzzBody(t, fixture.server, encoded)
		defer resp.Body.Close()
		defer drainRevokeFuzzResponse(resp)

		if token == "" {
			assertRevokeFuzzStatus(t, resp, encoded, http.StatusBadRequest)
			assertRevokeFuzzNoStore(t, resp, encoded)
			return
		}
		if isRevokeReachabilitySeed(fixture, token) {
			assertRevokeFuzzStatus(t, resp, encoded, http.StatusOK)
		} else {
			assertRevokeFuzzStatus(t, resp, encoded,
				http.StatusOK,
				http.StatusRequestEntityTooLarge,
			)
		}
		assertRevokeFuzzNoStore(t, resp, encoded)
		if resp.StatusCode != http.StatusOK {
			return
		}

		switch token {
		case fixture.liveJWT:
			assertRevokeFuzzAccessToken(t, fixture.mem, liveJWTJTI, true)
		case fixture.expiredJWT:
			assertRevokeFuzzAccessToken(t, fixture.mem, expiredJWTJTI, false)
		case fixture.liveRT:
			assertRevokeFuzzCascade(t, fixture.mem, liveRTID, liveRTChildID,
				liveRTGrantID, liveRTCascadeJTI, liveRTOpaqueID)
		case fixture.consumedRT:
			assertRevokeFuzzCascade(t, fixture.mem, consumedRTID, "",
				consumedRTGrantID, consumedRTCascadeJTI, consumedRTOpaqueID)
		}
	})
}

const (
	liveJWTJTI           = "fuzz-live-jwt"
	expiredJWTJTI        = "fuzz-expired-jwt"
	liveRTID             = "fuzz-live-rt-root"
	liveRTChildID        = "fuzz-live-rt-child"
	liveRTGrantID        = "fuzz-live-rt-grant"
	liveRTCascadeJTI     = "fuzz-live-rt-cascade-jti"
	liveRTOpaqueID       = "fuzz-live-rt-opaque-at"
	consumedRTID         = "fuzz-consumed-rt"
	consumedRTGrantID    = "fuzz-consumed-rt-grant"
	consumedRTCascadeJTI = "fuzz-consumed-rt-cascade-jti"
	consumedRTOpaqueID   = "fuzz-consumed-rt-opaque-at"
)

type authenticatedRevokeFuzzFixture struct {
	server     *httptest.Server
	mem        *inmem.Store
	clientID   string
	liveJWT    string
	expiredJWT string
	liveRT     string
	consumedRT string
}

func newRevokeParserFuzzServer(tb testing.TB) *httptest.Server {
	tb.Helper()
	clock, keyset, _ := newRevokeFuzzCrypto(tb)
	mem := inmem.New(inmem.WithClock(clock))
	server := httptest.NewServer(revokeendpoint.Handler(revokeendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       mem.Clients(),
		RefreshTokens: mem.RefreshTokens(),
		AccessTokens:  mem.AccessTokens(),
		Keys:          keyset,
		Clock:         clock,
	}))
	tb.Cleanup(server.Close)
	return server
}

func newAuthenticatedRevokeFuzzFixture(tb testing.TB) authenticatedRevokeFuzzFixture {
	tb.Helper()
	clock, keyset, signer := newRevokeFuzzCrypto(tb)
	mem := inmem.New(inmem.WithClock(clock))
	const clientID = "fuzz-revoke-client"
	mustRegisterRevokeFuzzClient(tb, mem, clientID)

	liveJWT := signRevokeFuzzJWT(tb, signer, clock, clientID, liveJWTJTI, time.Hour)
	expiredJWT := signRevokeFuzzJWT(tb, signer, clock, clientID, expiredJWTJTI, -time.Hour)
	mustRegisterRevokeFuzzAccessToken(tb, mem, clock, clientID, "", liveJWTJTI)
	mustRegisterRevokeFuzzAccessToken(tb, mem, clock, clientID, "", expiredJWTJTI)

	liveParent := liveRTID
	mustSaveRevokeFuzzRefresh(tb, mem, &store.RefreshToken{
		ID:        liveRTID,
		ClientID:  clientID,
		Subject:   "fuzz-live-rt-subject",
		GrantID:   liveRTGrantID,
		Scope:     []string{"openid"},
		ExpiresAt: clock.now.Add(time.Hour),
		CreatedAt: clock.now,
	})
	mustSaveRevokeFuzzRefresh(tb, mem, &store.RefreshToken{
		ID:        liveRTChildID,
		ClientID:  clientID,
		Subject:   "fuzz-live-rt-subject",
		GrantID:   liveRTGrantID,
		Scope:     []string{"openid"},
		ParentID:  &liveParent,
		ExpiresAt: clock.now.Add(time.Hour),
		CreatedAt: clock.now,
	})
	mustSeedRevokeFuzzCascade(tb, mem, clock, clientID,
		liveRTGrantID, liveRTCascadeJTI, liveRTOpaqueID)

	consumedAt := clock.now
	mustSaveRevokeFuzzRefresh(tb, mem, &store.RefreshToken{
		ID:         consumedRTID,
		ClientID:   clientID,
		Subject:    "fuzz-consumed-rt-subject",
		GrantID:    consumedRTGrantID,
		Scope:      []string{"openid"},
		ConsumedAt: &consumedAt,
		ExpiresAt:  clock.now.Add(time.Hour),
		CreatedAt:  clock.now,
	})
	mustSeedRevokeFuzzCascade(tb, mem, clock, clientID,
		consumedRTGrantID, consumedRTCascadeJTI, consumedRTOpaqueID)

	server := httptest.NewServer(revokeendpoint.Handler(revokeendpoint.Deps{
		Issuer:             "https://op.example",
		Clients:            mem.Clients(),
		RefreshTokens:      mem.RefreshTokens(),
		AccessTokens:       mem.AccessTokens(),
		OpaqueAccessTokens: mem.OpaqueAccessTokens(),
		Keys:               keyset,
		Clock:              clock,
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
		AccessTokenTTL:     time.Hour,
	}))
	tb.Cleanup(server.Close)
	return authenticatedRevokeFuzzFixture{
		server:     server,
		mem:        mem,
		clientID:   clientID,
		liveJWT:    liveJWT,
		expiredJWT: expiredJWT,
		liveRT:     liveRTID,
		consumedRT: consumedRTID,
	}
}

func revokeFormSeeds() []string {
	return []string{
		"",
		"token=abc",
		"token=abc&token_type_hint=access_token",
		"token=abc&token_type_hint=refresh_token",
		"token=abc&token_type_hint=unknown",
		"token=" + strings.Repeat("X", 1<<14),
		"token=&token_type_hint=refresh_token",
		"%%%",
		"token=abc&token=def",
		"token=abc\x00",
		"token=eyJhbGciOiJub25lIn0.e30.",
		"token=eyJhbGciOiJIUzI1NiJ9.e30.sig",
		strings.Repeat("token=abc&", 1<<14),
		strings.Repeat("a=b&", 1<<15),
		"token_type_hint=" + strings.Repeat("a", 1<<14),
	}
}

func newRevokeFuzzCrypto(tb testing.TB) (fuzzClock, *keys.Set, tokens.SigningKey) {
	tb.Helper()
	clock := fuzzClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa key: %v", err)
	}
	keyset, err := keys.NewSet([]keys.Entry{{KeyID: "fuzz-1", Signer: priv}})
	if err != nil {
		tb.Fatalf("keys.NewSet: %v", err)
	}
	return clock, keyset, tokens.SigningKey{KeyID: "fuzz-1", Signer: priv}
}

func signRevokeFuzzJWT(
	tb testing.TB,
	signer tokens.SigningKey,
	clock fuzzClock,
	clientID, jti string,
	expiryDelta time.Duration,
) string {
	tb.Helper()
	raw, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "fuzz-subject",
		Audience:  []string{"https://op.example"},
		ClientID:  clientID,
		IssuedAt:  clock.now.Add(-2 * time.Hour).Unix(),
		ExpiresAt: clock.now.Add(expiryDelta).Unix(),
		JTI:       jti,
		Scope:     []string{"openid"},
	})
	if err != nil {
		tb.Fatalf("SignAccessToken: %v", err)
	}
	return raw
}

func mustRegisterRevokeFuzzClient(tb testing.TB, mem *inmem.Store, clientID string) {
	tb.Helper()
	err := mem.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		tb.Fatalf("RegisterClient: %v", err)
	}
}

func mustRegisterRevokeFuzzAccessToken(
	tb testing.TB,
	mem *inmem.Store,
	clock fuzzClock,
	clientID, grantID, jti string,
) {
	tb.Helper()
	err := mem.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
		JTI:       jti,
		GrantID:   grantID,
		Subject:   "fuzz-subject",
		ClientID:  clientID,
		Scopes:    []string{"openid"},
		IssuedAt:  clock.now,
		ExpiresAt: clock.now.Add(time.Hour),
	})
	if err != nil {
		tb.Fatalf("AccessTokens.Register: %v", err)
	}
}

func mustSaveRevokeFuzzRefresh(tb testing.TB, mem *inmem.Store, rec *store.RefreshToken) {
	tb.Helper()
	if err := mem.RefreshTokens().Save(context.Background(), rec); err != nil {
		tb.Fatalf("RefreshTokens.Save: %v", err)
	}
}

func mustSeedRevokeFuzzCascade(
	tb testing.TB,
	mem *inmem.Store,
	clock fuzzClock,
	clientID, grantID, jti, opaqueID string,
) {
	tb.Helper()
	mustRegisterRevokeFuzzAccessToken(tb, mem, clock, clientID, grantID, jti)
	err := mem.OpaqueAccessTokens().Save(context.Background(), &store.OpaqueAccessToken{
		ID:        opaqueID,
		GrantID:   grantID,
		Subject:   "fuzz-subject",
		ClientID:  clientID,
		Scope:     []string{"openid"},
		IssuedAt:  clock.now,
		ExpiresAt: clock.now.Add(time.Hour),
	})
	if err != nil {
		tb.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}
}

func postRevokeFuzzBody(tb testing.TB, server *httptest.Server, body string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL,
		strings.NewReader(body),
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := server.Client().Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

func assertRevokeFuzzStatus(tb testing.TB, resp *http.Response, input string, allowed ...int) {
	tb.Helper()
	for _, status := range allowed {
		if resp.StatusCode == status {
			return
		}
	}
	tb.Fatalf("unexpected status %d for input %q",
		resp.StatusCode, truncateForFuzz(input, 64))
}

func assertRevokeFuzzNoStore(tb testing.TB, resp *http.Response, input string) {
	tb.Helper()
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		tb.Fatalf("Cache-Control=%q want no-store (status=%d input=%q)",
			got, resp.StatusCode, truncateForFuzz(input, 64))
	}
	if got := resp.Header.Get("Pragma"); !strings.Contains(got, "no-cache") {
		tb.Fatalf("Pragma=%q want no-cache (status=%d input=%q)",
			got, resp.StatusCode, truncateForFuzz(input, 64))
	}
}

func drainRevokeFuzzResponse(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
}

func isRevokeReachabilitySeed(fixture authenticatedRevokeFuzzFixture, token string) bool {
	return token == fixture.liveJWT ||
		token == fixture.expiredJWT ||
		token == fixture.liveRT ||
		token == fixture.consumedRT
}

func assertRevokeFuzzAccessToken(
	tb testing.TB,
	mem *inmem.Store,
	jti string,
	wantRevoked bool,
) {
	tb.Helper()
	rec, err := mem.AccessTokens().Find(context.Background(), jti)
	if err != nil {
		tb.Fatalf("AccessTokens.Find(%q): %v", jti, err)
	}
	if rec == nil {
		tb.Fatalf("AccessTokens.Find(%q) returned nil", jti)
		return
	}
	if rec.Revoked != wantRevoked {
		tb.Fatalf("AccessTokens.Find(%q).Revoked=%v want %v", jti, rec.Revoked, wantRevoked)
	}
}

func assertRevokeFuzzCascade(
	tb testing.TB,
	mem *inmem.Store,
	rootID, childID, grantID, jti, opaqueID string,
) {
	tb.Helper()
	assertRevokeFuzzRefreshRevoked(tb, mem, rootID)
	if childID != "" {
		assertRevokeFuzzRefreshRevoked(tb, mem, childID)
	}
	assertRevokeFuzzAccessToken(tb, mem, jti, true)
	opaque, err := mem.OpaqueAccessTokens().Find(context.Background(), opaqueID)
	if err != nil {
		tb.Fatalf("OpaqueAccessTokens.Find(%q): %v", opaqueID, err)
	}
	if opaque == nil || !opaque.Revoked {
		tb.Fatalf("opaque cascade for grant %q did not revoke %q", grantID, opaqueID)
	}
}

func assertRevokeFuzzRefreshRevoked(tb testing.TB, mem *inmem.Store, id string) {
	tb.Helper()
	rec, err := mem.RefreshTokens().Find(context.Background(), id)
	if err != nil {
		tb.Fatalf("RefreshTokens.Find(%q): %v", id, err)
	}
	if rec == nil || rec.ConsumedAt == nil || !rec.Revoked {
		tb.Fatalf("refresh token %q was not cascade-revoked: %+v", id, rec)
	}
}

type fuzzClock struct{ now time.Time }

func (c fuzzClock) Now() time.Time { return c.now }

func truncateForFuzz(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
