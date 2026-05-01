package scenarios_test

// Catalog: test/scenarios/catalog/byo_userstore.yaml (BUS-NNN)
// Spec:
//   - OIDC Core 1.0 §5.3 — UserInfo Endpoint
//   - OIDC Core 1.0 §5.4 — Requesting Claims using Scope Values
//   - OIDC Core 1.0 §5.5 — Requesting Claims using the "claims" Parameter
//   - OIDC Core 1.0 §2 — ID Token
//   - RFC 6750 §3 — Bearer Token error responses
//   - implementation contract — store.UserStore consumed by the OP

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	busClientID     = "rp-bus"
	busCallback     = "https://rp.testkit.invalid/callback"
	busClientSecret = "rp-bus-secret" //nolint:gosec // G101: test fixture, not a real credential.
	busSubject      = "user-bus"
)

// busRecorder wraps a delegate store.UserStore (which may be nil to
// always return store.ErrNotFound) and counts every FindBySubject
// invocation. The same recorder type is used by every BUS-NNN row to
// observe whether the OP actually reached store.Users().FindBySubject
// at each call site.
type busRecorder struct {
	delegate store.UserStore
	calls    atomic.Int32
	last     atomic.Pointer[string]
	// override, when non-nil, replaces delegate for this call. Used
	// by BUS-008 to return the same backing map across calls without
	// the inmem store's defensive clone.
	override func(ctx context.Context, sub string) (*store.User, error)
}

func (r *busRecorder) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	r.calls.Add(1)
	captured := sub
	r.last.Store(&captured)
	if r.override != nil {
		return r.override(ctx, sub)
	}
	if r.delegate == nil {
		return nil, store.ErrNotFound
	}
	return r.delegate.FindBySubject(ctx, sub)
}

// busHybridStore is the embedding wrapper the BUS rows exercise. It
// embeds an aggregate inmem.Store and shadows Users() with a
// busRecorder, mirroring the pattern an embedder uses to plug an
// existing users table into the OP without forking the rest of the
// substores.
type busHybridStore struct {
	*inmem.Store
	users store.UserStore
}

func (h *busHybridStore) Users() store.UserStore { return h.users }

// busFixture bundles the testkit Provider, the embedder-side aggregate
// store (the same instance the hybrid wraps), the recorder, and the
// registered client so the per-row tests can drive flows without
// repeating wiring.
type busFixture struct {
	tk       *testkit.Provider
	base     *inmem.Store
	recorder *busRecorder
	client   *store.Client
}

func newBUSFixture(t *testing.T, opts ...op.Option) *busFixture {
	t.Helper()
	base := inmem.New()
	rec := &busRecorder{delegate: base.Users()}
	hybrid := &busHybridStore{Store: base, users: rec}

	full := append([]op.Option{op.WithStore(hybrid)}, opts...)
	tk := testkit.NewProvider(t, testkit.WithOptions(full...))

	hash, err := op.HashClientSecret(busClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := &store.Client{
		ID:                      busClientID,
		RedirectURIs:            []string{busCallback},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
	}
	if err := base.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	return &busFixture{tk: tk, base: base, recorder: rec, client: rp}
}

func (f *busFixture) putUser(t *testing.T, u *store.User) {
	t.Helper()
	f.base.PutUser(context.Background(), u)
}

func (f *busFixture) runCodeFlow(t *testing.T, scope string, extra url.Values) scenariokit.TokenResponse {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, f.tk, busSubject, scenariokit.AuthorizeParams{
		ClientID:    f.client.ID,
		RedirectURI: busCallback,
		Scope:       scope,
		PKCE:        pkce,
		Extra:       extra,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, f.tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  busCallback,
		Verifier:     pkce.Verifier,
		ClientID:     f.client.ID,
		ClientSecret: busClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	return tok
}

// callUserinfo issues GET /oidc/userinfo with the supplied bearer
// token and returns the response status, headers, and decoded body.
// Errors during transport / decode fail the test fast.
func callUserinfo(t *testing.T, tk *testkit.Provider, accessToken string) (int, http.Header, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("build /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("/userinfo body: %v", err)
	}
	out := map[string]any{}
	if len(body) > 0 && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("/userinfo decode %q: %v", string(body), err)
		}
	}
	return resp.StatusCode, resp.Header, out
}

// decodeBUSJWTClaims pulls the payload claims out of a JWS Compact
// Serialisation. It is intentionally tolerant of unknown fields so the
// id_token Extra claims surface as map[string]any entries.
func decodeBUSJWTClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("jwt parts=%d want 3 (value=%q)", len(parts), jws)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		tb.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// newBUSSigningKey returns a fresh ECDSA P-256 signer wrapped in
// op.SigningKey. The helper is duplicated rather than borrowed from
// testkit because BUS-010 builds its provider through op.New directly
// (testkit pre-installs WithAuthenticators, which is mutually
// exclusive with WithLoginFlow).
func newBUSSigningKey(tb testing.TB) op.SigningKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate signing key: %v", err)
	}
	return op.SigningKey{KeyID: "bus-sig-1", Signer: priv}
}

// newBUSCookieKey returns a fresh 32-byte cookie key for op.WithCookieKey.
func newBUSCookieKey(tb testing.TB) []byte {
	tb.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("generate cookie key: %v", err)
	}
	return key
}

// claimsRequestExtra returns the url.Values carrying the supplied
// OIDC Core §5.5 "claims" parameter as JSON. The function fails the
// test on marshal error so each row stays free of boilerplate.
func claimsRequestExtra(tb testing.TB, payload any) url.Values {
	tb.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		tb.Fatalf("marshal claims param: %v", err)
	}
	return url.Values{"claims": []string{string(encoded)}}
}

// TestScenario_BUS_001_UserInfoCallsStoreUsers checks that a /userinfo
// call routes through store.Users().FindBySubject on the value passed
// to op.WithStore — there is no internal claim cache that would let
// the OP short-circuit the lookup.
//
// Spec: OIDC Core §5.3.
func TestScenario_BUS_001_UserInfoCallsStoreUsers(t *testing.T) {
	t.Parallel()
	f := newBUSFixture(t)
	f.putUser(t, &store.User{
		Subject: busSubject,
		Claims: map[string]any{
			"email":          "alice@example.test",
			"email_verified": true,
		},
	})
	tok := f.runCodeFlow(t, "openid email", nil)
	if tok.AccessToken == "" {
		t.Fatal("/token returned empty access_token")
	}
	before := f.recorder.calls.Load()

	status, _, body := callUserinfo(t, f.tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d body=%v", status, body)
	}
	if got, want := body["sub"], busSubject; got != want {
		t.Errorf("/userinfo sub=%v want %q", got, want)
	}
	after := f.recorder.calls.Load()
	if after <= before {
		t.Fatalf("recorder.calls did not advance during /userinfo (before=%d after=%d)", before, after)
	}
	if last := f.recorder.last.Load(); last == nil || *last != busSubject {
		t.Errorf("recorder.last=%v want %q", last, busSubject)
	}
}

// TestScenario_BUS_002_IDTokenAssemblyCallsStoreUsers checks that
// projecting a §5.5 "claims" payload addressed to the id_token at the
// token endpoint routes through store.Users().FindBySubject. Standard
// id_token claims are not exercised here — the library issues those
// directly.
//
// Spec: OIDC Core §2 / §5.5.
func TestScenario_BUS_002_IDTokenAssemblyCallsStoreUsers(t *testing.T) {
	t.Parallel()
	f := newBUSFixture(t)
	f.putUser(t, &store.User{
		Subject: busSubject,
		Claims: map[string]any{
			"email":          "alice@example.test",
			"email_verified": true,
		},
	})
	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
	})

	before := f.recorder.calls.Load()
	tok := f.runCodeFlow(t, "openid email", extra)
	after := f.recorder.calls.Load()
	if after <= before {
		t.Fatalf("recorder.calls did not advance during /token §5.5 projection (before=%d after=%d)",
			before, after)
	}
	claims := decodeBUSJWTClaims(t, tok.IDToken)
	if got := claims["email"]; got != "alice@example.test" {
		t.Errorf("id_token email=%v want alice@example.test", got)
	}
}

// TestScenario_BUS_003_EmbeddingOverrideShadowsBaseUsers checks that
// when an aggregate store.Store is embedded by a wrapper with its own
// Users() method, the OP observes the wrapper's override at every
// call site that reads end-user claims. The base store's Users() is
// never reached.
//
// Spec: implementation contract.
func TestScenario_BUS_003_EmbeddingOverrideShadowsBaseUsers(t *testing.T) {
	t.Parallel()
	base := inmem.New()
	baseRecorder := &busRecorder{delegate: base.Users()}
	override := &busRecorder{delegate: base.Users()}
	hybrid := &busHybridStore{Store: base, users: override}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStore(hybrid)))

	hash, err := op.HashClientSecret(busClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := &store.Client{
		ID:                      busClientID,
		RedirectURIs:            []string{busCallback},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
	}
	if err := base.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	base.PutUser(context.Background(), &store.User{
		Subject: busSubject,
		Claims:  map[string]any{"email": "alice@example.test"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, busSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: busCallback,
		Scope:       "openid email",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  busCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: busClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if status, _, _ := callUserinfo(t, tk, tok.AccessToken); status != http.StatusOK {
		t.Fatalf("/userinfo status=%d", status)
	}
	if override.calls.Load() == 0 {
		t.Error("override Users() never reached")
	}
	if baseRecorder.calls.Load() != 0 {
		t.Errorf("base recorder reached %d times — embedding shadow leaked", baseRecorder.calls.Load())
	}
}

// TestScenario_BUS_004_UserInfoNotFoundReturnsInvalidToken checks that
// when store.Users().FindBySubject returns store.ErrNotFound at the
// /userinfo endpoint, the OP responds with 401 + WWW-Authenticate
// error="invalid_token" — never 500.
//
// Spec: RFC 6750 §3.1 / OIDC Core §5.3.
func TestScenario_BUS_004_UserInfoNotFoundReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	f := newBUSFixture(t)
	// Seed so the code flow itself succeeds (token issuance does not
	// require a user record outside §5.5 projection).
	f.putUser(t, &store.User{Subject: busSubject})
	tok := f.runCodeFlow(t, "openid email", nil)

	// Force /userinfo to observe ErrNotFound.
	f.recorder.override = func(_ context.Context, _ string) (*store.User, error) {
		return nil, store.ErrNotFound
	}

	status, header, _ := callUserinfo(t, f.tk, tok.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("/userinfo status=%d want 401", status)
	}
	wwwAuth := header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q does not carry invalid_token", wwwAuth)
	}
}

// TestScenario_BUS_005_IDTokenAssemblyNotFoundOmitsClaims checks the
// silent-omit policy at the token endpoint: when §5.5 projection
// observes store.ErrNotFound, the OP issues the id_token without the
// affected claims and the grant exchange still succeeds (no 500, no
// invalid_grant).
//
// Spec: OIDC Core §5.5 / implementation contract.
func TestScenario_BUS_005_IDTokenAssemblyNotFoundOmitsClaims(t *testing.T) {
	t.Parallel()
	f := newBUSFixture(t)
	f.putUser(t, &store.User{Subject: busSubject})
	// Stub Users() so §5.5 projection at /token cannot resolve the
	// user, while authorize-time persistence is still satisfied by
	// the seeded record.
	f.recorder.override = func(_ context.Context, _ string) (*store.User, error) {
		return nil, store.ErrNotFound
	}
	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
	})
	tok := f.runCodeFlow(t, "openid email", extra)
	if tok.IDToken == "" {
		t.Fatal("id_token missing from successful /token response")
	}
	claims := decodeBUSJWTClaims(t, tok.IDToken)
	if _, ok := claims["email"]; ok {
		t.Errorf("id_token carried email=%v despite ErrNotFound projection", claims["email"])
	}
	if got, want := claims["sub"], busSubject; got != want {
		t.Errorf("id_token sub=%v want %q", got, want)
	}
}

// TestScenario_BUS_006_UnauthorisedClaimsAreFiltered checks that
// claim names returned in User.Claims that the granted scopes do not
// authorise are filtered out of /userinfo. Embedders MAY return a
// richer Claims universe; the OP is the projector.
//
// Spec: OIDC Core §5.4.
func TestScenario_BUS_006_UnauthorisedClaimsAreFiltered(t *testing.T) {
	t.Parallel()
	f := newBUSFixture(t)
	f.putUser(t, &store.User{
		Subject: busSubject,
		Claims: map[string]any{
			"email":          "alice@example.test",
			"email_verified": true,
			"tenant_id":      "tenant-42",
			"member_status":  "active",
		},
	})
	tok := f.runCodeFlow(t, "openid email", nil)
	_, _, body := callUserinfo(t, f.tk, tok.AccessToken)

	if got, want := body["sub"], busSubject; got != want {
		t.Errorf("/userinfo sub=%v want %q", got, want)
	}
	if got := body["email"]; got != "alice@example.test" {
		t.Errorf("/userinfo email=%v want alice@example.test", got)
	}
	for _, forbidden := range []string{"tenant_id", "member_status"} {
		if _, ok := body[forbidden]; ok {
			t.Errorf("/userinfo leaked unauthorised claim %q=%v", forbidden, body[forbidden])
		}
	}
}

// TestScenario_BUS_007_UpdatedAtMappedFromUserStruct checks the
// User.UpdatedAt → "updated_at" claim projection. With the "profile"
// scope a non-zero UpdatedAt becomes Unix-seconds in /userinfo; with
// a zero UpdatedAt the claim is omitted entirely.
//
// Spec: OIDC Core §5.1 / §5.4.
func TestScenario_BUS_007_UpdatedAtMappedFromUserStruct(t *testing.T) {
	t.Parallel()

	t.Run("nonzero", func(t *testing.T) {
		t.Parallel()
		f := newBUSFixture(t)
		ts := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
		f.putUser(t, &store.User{
			Subject:   busSubject,
			Claims:    map[string]any{"name": "Alice"},
			UpdatedAt: ts,
		})
		tok := f.runCodeFlow(t, "openid profile", nil)
		_, _, body := callUserinfo(t, f.tk, tok.AccessToken)
		got, ok := body["updated_at"]
		if !ok {
			t.Fatalf("/userinfo missing updated_at; body=%v", body)
		}
		// json.Unmarshal decodes JSON numbers as float64.
		gotF, isFloat := got.(float64)
		if !isFloat {
			t.Fatalf("/userinfo updated_at type=%T value=%v want number", got, got)
		}
		if int64(gotF) != ts.Unix() {
			t.Errorf("/userinfo updated_at=%d want %d", int64(gotF), ts.Unix())
		}
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		f := newBUSFixture(t)
		f.putUser(t, &store.User{
			Subject: busSubject,
			Claims:  map[string]any{"name": "Bob"},
		})
		tok := f.runCodeFlow(t, "openid profile", nil)
		_, _, body := callUserinfo(t, f.tk, tok.AccessToken)
		if _, ok := body["updated_at"]; ok {
			t.Errorf("/userinfo emitted updated_at for zero UpdatedAt: body=%v", body)
		}
	})
}

// TestScenario_BUS_008_LibraryTreatsClaimsMapReadOnly checks that the
// OP never mutates User.Claims handed back from FindBySubject. A
// backend that returns the same backing map across two successive
// lookups MUST observe the map intact between calls.
//
// Spec: implementation contract.
func TestScenario_BUS_008_LibraryTreatsClaimsMapReadOnly(t *testing.T) {
	t.Parallel()
	shared := map[string]any{
		"email":          "alice@example.test",
		"email_verified": true,
		"tenant_id":      "tenant-42",
	}
	snapshot := make(map[string]any, len(shared))
	for k, v := range shared {
		snapshot[k] = v
	}

	f := newBUSFixture(t)
	f.recorder.override = func(_ context.Context, sub string) (*store.User, error) {
		return &store.User{Subject: sub, Claims: shared}, nil
	}

	tok := f.runCodeFlow(t, "openid email", nil)
	if status, _, _ := callUserinfo(t, f.tk, tok.AccessToken); status != http.StatusOK {
		t.Fatalf("/userinfo status=%d", status)
	}
	if status, _, _ := callUserinfo(t, f.tk, tok.AccessToken); status != http.StatusOK {
		t.Fatalf("/userinfo (second call) status=%d", status)
	}
	if !reflect.DeepEqual(shared, snapshot) {
		t.Errorf("library mutated User.Claims: got=%v want=%v", shared, snapshot)
	}
}

// TestScenario_BUS_009_TxInterfaceDoesNotExposeUsers checks that the
// transactional handle returned by Transactional.BeginTx does NOT
// expose a Users() accessor. Embedders MAY route Users to a backend
// that does not implement store.Transactional without breaking
// authorization-code exchange or refresh-token rotation atomicity.
//
// Spec: implementation contract.
func TestScenario_BUS_009_TxInterfaceDoesNotExposeUsers(t *testing.T) {
	t.Parallel()
	tx, err := inmem.New().BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, ok := any(tx).(interface{ Users() store.UserStore }); ok {
		t.Fatal("store.Tx must NOT expose Users(); UserStore is outside the transactional cluster")
	}
	// Reflect-based confirmation against the static interface so a
	// future addition of Users() to store.Tx would still trip the
	// assertion even if a concrete backend exposed the method by
	// accident on a wider type.
	rt := reflect.TypeOf((*store.Tx)(nil)).Elem()
	if _, found := rt.MethodByName("Users"); found {
		t.Fatal("store.Tx interface declares Users() — would couple Users to the Tx cluster")
	}
}

// TestScenario_BUS_010_PrimaryPasswordStoreIndependentOfUsers checks
// that op.PrimaryPassword{Store: A} and Store.Users() = B are
// accepted by op.New as independent values: the library does NOT
// require the password lookup store to be the same instance as the
// aggregate Users() backend, as long as both honour the contract for
// their own subject space.
//
// Spec: implementation contract.
func TestScenario_BUS_010_PrimaryPasswordStoreIndependentOfUsers(t *testing.T) {
	t.Parallel()
	primaryStore := inmem.New() // backs PrimaryPassword.Store
	usersBacking := inmem.New() // backs aggregate store.Users() via embedding
	hybrid := &busHybridStore{Store: usersBacking, users: usersBacking.Users()}

	if primaryStore.UserPasswords() == hybrid.Users() {
		t.Fatal("primary and aggregate user stores accidentally point at the same instance")
	}

	// op.New is invoked directly (not via testkit.NewProvider) because
	// WithLoginFlow is mutually exclusive with WithAuthenticators, and
	// the testkit pre-installs SubjectAuthenticator. The construction
	// outcome — not flow execution — is the BUS-010 contract.
	signKey := newBUSSigningKey(t)
	cookieKey := newBUSCookieKey(t)
	provider, err := op.New(
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(hybrid),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKey(cookieKey),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: primaryStore.UserPasswords()},
		}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatal("op.New returned nil Provider despite independent password / aggregate user stores")
	}
}

// TestScenario_BUS_011_EmptyClaimsYieldsBareSubResponse checks that
// when the User record carries a nil/empty Claims map and the granted
// scopes authorise no other claims, the /userinfo response is the
// bare JSON object {"sub": "..."} — the OP never synthesises
// placeholder claims.
//
// Spec: OIDC Core §5.3.
func TestScenario_BUS_011_EmptyClaimsYieldsBareSubResponse(t *testing.T) {
	t.Parallel()
	f := newBUSFixture(t)
	f.putUser(t, &store.User{Subject: busSubject})
	tok := f.runCodeFlow(t, "openid", nil)
	status, _, body := callUserinfo(t, f.tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d body=%v", status, body)
	}
	if got, want := body["sub"], busSubject; got != want {
		t.Errorf("/userinfo sub=%v want %q", got, want)
	}
	if len(body) != 1 {
		t.Errorf("/userinfo body has %d keys, want only \"sub\": body=%v", len(body), body)
	}
}

// TestScenario_BUS_012_CompositeUsersRouteEquivalentToEmbedding checks
// that when an embedder routes Users via composite.With(Users, b)
// where b implements store.Store, the OP reads end-user claims from
// b.Users() at the same call sites BUS-001 / BUS-002 cover. Composite
// routing and the embedding-wrapper pattern are observationally
// equivalent.
//
// Spec: implementation contract.
func TestScenario_BUS_012_CompositeUsersRouteEquivalentToEmbedding(t *testing.T) {
	t.Parallel()
	primary := inmem.New() // owns Clients / AuthorizationCodes / Sessions / ...
	users := inmem.New()   // hosts Users only via composite routing

	rec := &busRecorder{delegate: users.Users()}
	usersHybrid := &busHybridStore{Store: users, users: rec}

	routed, err := composite.New(
		composite.WithDefault(primary),
		composite.With(composite.Users, usersHybrid),
	)
	if err != nil {
		t.Fatalf("composite.New: %v", err)
	}

	hash, err := op.HashClientSecret(busClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := &store.Client{
		ID:                      busClientID,
		RedirectURIs:            []string{busCallback},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
	}
	if err := primary.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient (primary): %v", err)
	}
	users.PutUser(context.Background(), &store.User{
		Subject: busSubject,
		Claims:  map[string]any{"email": "alice@example.test"},
	})

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStore(routed)))

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, busSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: busCallback,
		Scope:       "openid email",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  busCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: busClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if _, _, body := callUserinfo(t, tk, tok.AccessToken); body["email"] != "alice@example.test" {
		t.Errorf("/userinfo email=%v want alice@example.test", body["email"])
	}
	if rec.calls.Load() == 0 {
		t.Error("composite-routed Users() never called")
	}
}
