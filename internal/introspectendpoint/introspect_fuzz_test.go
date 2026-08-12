package introspectendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// FuzzIntrospectFormBody exercises only the unauthenticated request envelope:
// method/content-type checks, the bounded form parser, duplicate detection, and
// client-credential parsing. Token parsing deliberately is not claimed here;
// without a registered client this target must stop at client authentication.
// [FuzzIntrospectAuthenticatedToken] owns the post-authentication surface.
func FuzzIntrospectFormBody(f *testing.F) {
	server := newIntrospectParserFuzzServer(f)

	for _, seed := range introspectFormSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body string) {
		resp := postFuzzBody(t, server, body)
		defer resp.Body.Close()
		defer drainFuzzResponse(resp)

		assertFuzzStatus(t, resp, body,
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusRequestEntityTooLarge,
		)
		assertFuzzNoStore(t, resp, body)
	})
}

// FuzzIntrospectAuthenticatedToken authenticates a registered confidential
// client before feeding mutated token bytes and hints to the token dispatcher. Its
// seed corpus pins four independently observable deep paths:
//
//   - a live JWT AT must verify, hit the JTI registry, and return active;
//   - a registry-revoked JWT AT must verify, hit the same registry, and return
//     inactive;
//   - a live RT must be found in the refresh store and return active;
//   - a consumed RT must be found but return inactive.
//
// Any other mutated token is disclosure-equivalent and therefore returns an
// inactive RFC 7662 response rather than a parser error.
func FuzzIntrospectAuthenticatedToken(f *testing.F) {
	fixture := newAuthenticatedIntrospectFuzzFixture(f)

	f.Add(fixture.liveJWT, "access_token")
	f.Add(fixture.revokedJWT, "access_token")
	f.Add(fixture.liveRT, "refresh_token")
	f.Add(fixture.consumedRT, "refresh_token")
	f.Add("eyJhbGciOiJub25lIn0.e30.", "access_token")
	f.Add(strings.Repeat("A", 1<<14), "unknown")

	f.Fuzz(func(t *testing.T, token, hint string) {
		form := url.Values{
			"client_id":     {fixture.clientID},
			"client_secret": {fuzzClientSecret},
			"token":         {token},
		}
		if hint != "" {
			form.Set("token_type_hint", hint)
		}
		resp := postFuzzBody(t, fixture.server, form.Encode())
		defer resp.Body.Close()
		defer drainFuzzResponse(resp)

		if token == "" {
			assertFuzzStatus(t, resp, form.Encode(), http.StatusBadRequest)
			assertFuzzNoStore(t, resp, form.Encode())
			return
		}
		if isIntrospectReachabilitySeed(fixture, token) {
			assertFuzzStatus(t, resp, form.Encode(), http.StatusOK)
		} else {
			assertFuzzStatus(t, resp, form.Encode(),
				http.StatusOK,
				http.StatusRequestEntityTooLarge,
			)
		}
		assertFuzzNoStore(t, resp, form.Encode())
		if resp.StatusCode != http.StatusOK {
			return
		}
		active := decodeFuzzActive(t, resp)
		switch token {
		case fixture.liveJWT, fixture.liveRT:
			if !active {
				t.Fatalf("seed token reached inactive response; want active (hint=%q)", hint)
			}
		case fixture.revokedJWT, fixture.consumedRT:
			if active {
				t.Fatalf("inactive seed returned active (hint=%q)", hint)
			}
		}
	})
}

const fuzzClientSecret = "fuzz-introspect-secret" //nolint:gosec // G101: fuzz-only fixture credential.

type authenticatedIntrospectFuzzFixture struct {
	server     *httptest.Server
	clientID   string
	liveJWT    string
	revokedJWT string
	liveRT     string
	consumedRT string
}

func newIntrospectParserFuzzServer(tb testing.TB) *httptest.Server {
	tb.Helper()
	clock, keyset, signer := newIntrospectFuzzCrypto(tb)
	mem := inmem.New(inmem.WithClock(clock))
	server := httptest.NewServer(introspectendpoint.Handler(introspectendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       mem.Clients(),
		RefreshTokens: mem.RefreshTokens(),
		AccessTokens:  mem.AccessTokens(),
		Keys:          keyset,
		Clock:         clock,
		SigningKey:    signer,
	}))
	tb.Cleanup(server.Close)
	return server
}

func newAuthenticatedIntrospectFuzzFixture(tb testing.TB) authenticatedIntrospectFuzzFixture {
	tb.Helper()
	clock, keyset, signer := newIntrospectFuzzCrypto(tb)
	mem := inmem.New(inmem.WithClock(clock))
	const clientID = "fuzz-introspect-client"
	mustRegisterFuzzClient(tb, mem, clientID)

	liveJWT := signIntrospectFuzzJWT(tb, signer, clock, clientID, "fuzz-live-at")
	revokedJWT := signIntrospectFuzzJWT(tb, signer, clock, clientID, "fuzz-revoked-at")
	mustRegisterFuzzAccessToken(tb, mem, clock, clientID, "fuzz-live-at", false)
	mustRegisterFuzzAccessToken(tb, mem, clock, clientID, "fuzz-revoked-at", true)

	const (
		liveRT     = "fuzz-live-rt"
		consumedRT = "fuzz-consumed-rt"
	)
	mustSaveIntrospectFuzzRefresh(tb, mem, &store.RefreshToken{
		ID:        liveRT,
		ClientID:  clientID,
		Subject:   "fuzz-live-subject",
		Scope:     []string{"openid"},
		ExpiresAt: clock.now.Add(time.Hour),
		CreatedAt: clock.now,
	})
	consumedAt := clock.now
	mustSaveIntrospectFuzzRefresh(tb, mem, &store.RefreshToken{
		ID:         consumedRT,
		ClientID:   clientID,
		Subject:    "fuzz-consumed-subject",
		Scope:      []string{"openid"},
		ConsumedAt: &consumedAt,
		ExpiresAt:  clock.now.Add(time.Hour),
		CreatedAt:  clock.now,
	})

	server := httptest.NewServer(introspectendpoint.Handler(introspectendpoint.Deps{
		Issuer:             "https://op.example",
		Clients:            mem.Clients(),
		RefreshTokens:      mem.RefreshTokens(),
		AccessTokens:       mem.AccessTokens(),
		Keys:               keyset,
		Clock:              clock,
		SigningKey:         signer,
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
	}))
	tb.Cleanup(server.Close)
	return authenticatedIntrospectFuzzFixture{
		server:     server,
		clientID:   clientID,
		liveJWT:    liveJWT,
		revokedJWT: revokedJWT,
		liveRT:     liveRT,
		consumedRT: consumedRT,
	}
}

func introspectFormSeeds() []string {
	return []string{
		"",
		"token=abc",
		"token=abc&token_type_hint=access_token",
		"token=abc&token_type_hint=refresh_token",
		"token=abc&token_type_hint=unknown",
		"token=" + strings.Repeat("A", 1<<14),
		"token=&token_type_hint=access_token",
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

func newIntrospectFuzzCrypto(tb testing.TB) (fuzzClock, *keys.Set, tokens.SigningKey) {
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

func signIntrospectFuzzJWT(
	tb testing.TB,
	signer tokens.SigningKey,
	clock fuzzClock,
	clientID, jti string,
) string {
	tb.Helper()
	raw, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "fuzz-subject",
		Audience:  []string{"https://op.example"},
		ClientID:  clientID,
		IssuedAt:  clock.now.Unix(),
		ExpiresAt: clock.now.Add(time.Hour).Unix(),
		JTI:       jti,
		Scope:     []string{"openid"},
	})
	if err != nil {
		tb.Fatalf("SignAccessToken: %v", err)
	}
	return raw
}

func mustRegisterFuzzClient(tb testing.TB, mem *inmem.Store, clientID string) {
	tb.Helper()
	hash, err := (&clientauth.Argon2id{}).Hash(fuzzClientSecret)
	if err != nil {
		tb.Fatalf("hash fuzz client secret: %v", err)
	}
	err = mem.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		tb.Fatalf("RegisterClient: %v", err)
	}
}

func mustRegisterFuzzAccessToken(
	tb testing.TB,
	mem *inmem.Store,
	clock fuzzClock,
	clientID, jti string,
	revoked bool,
) {
	tb.Helper()
	err := mem.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
		JTI:       jti,
		Subject:   "fuzz-subject",
		ClientID:  clientID,
		Scopes:    []string{"openid"},
		IssuedAt:  clock.now,
		ExpiresAt: clock.now.Add(time.Hour),
		Revoked:   revoked,
	})
	if err != nil {
		tb.Fatalf("AccessTokens.Register: %v", err)
	}
}

func mustSaveIntrospectFuzzRefresh(tb testing.TB, mem *inmem.Store, rec *store.RefreshToken) {
	tb.Helper()
	if err := mem.RefreshTokens().Save(context.Background(), rec); err != nil {
		tb.Fatalf("RefreshTokens.Save: %v", err)
	}
}

func postFuzzBody(tb testing.TB, server *httptest.Server, body string) *http.Response {
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

func assertFuzzStatus(tb testing.TB, resp *http.Response, input string, allowed ...int) {
	tb.Helper()
	for _, status := range allowed {
		if resp.StatusCode == status {
			return
		}
	}
	tb.Fatalf("unexpected status %d for input %q", resp.StatusCode, truncateForFuzz(input, 64))
}

func assertFuzzNoStore(tb testing.TB, resp *http.Response, input string) {
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

func decodeFuzzActive(tb testing.TB, resp *http.Response) bool {
	tb.Helper()
	var body struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		tb.Fatalf("decode introspection response: %v", err)
	}
	return body.Active
}

func drainFuzzResponse(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
}

func isIntrospectReachabilitySeed(fixture authenticatedIntrospectFuzzFixture, token string) bool {
	return token == fixture.liveJWT ||
		token == fixture.revokedJWT ||
		token == fixture.liveRT ||
		token == fixture.consumedRT
}

type fuzzClock struct{ now time.Time }

func (c fuzzClock) Now() time.Time { return c.now }

func truncateForFuzz(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
