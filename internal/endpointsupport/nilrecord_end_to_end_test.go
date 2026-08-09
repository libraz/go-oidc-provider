package endpointsupport_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// nilRecordSecret is the fixture secret the store-contract clients
// authenticate with.
//
//nolint:gosec // G101: test fixture, not a real credential.
const nilRecordSecret = "rp-nil-record-secret"

// nilRecordAnchor pins the clock so seeded records have deterministic
// lifetimes relative to the requests the assertions drive.
var nilRecordAnchor = time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

type nilRecordClock struct{}

func (nilRecordClock) Now() time.Time { return nilRecordAnchor }

// brokenSubstores names the substores [nilRecordStore] should break.
type brokenSubstores struct {
	clients       bool
	refreshTokens bool
	authCodes     bool
	pars          bool
	users         bool
}

// nilRecordStore decorates a conforming backend so the named substores
// answer every lookup with the (nil, nil) pair op/store's contract forbids:
// a nil error promises a non-nil record, and "absent" is spelled
// [store.ErrNotFound].
//
// This is a test double of the store interface, not a database mock. Every
// method other than the deliberately broken lookups is served by the
// in-memory reference adapter, so the records under test really are present
// — only the read path lies about them. The decoration is applied to the
// transaction handles too, because the token endpoint reads through
// transaction-bound substores.
type nilRecordStore struct {
	*inmem.Store
	broken brokenSubstores
}

func (s nilRecordStore) Clients() store.ClientStore {
	if s.broken.clients {
		return nilClientStore{ClientStore: s.Store.Clients()}
	}
	return s.Store.Clients()
}

func (s nilRecordStore) RefreshTokens() store.RefreshTokenStore {
	if s.broken.refreshTokens {
		return nilRefreshTokenStore{refreshTokenBackend: s.Store.RefreshTokens().(refreshTokenBackend)}
	}
	return s.Store.RefreshTokens()
}

func (s nilRecordStore) AuthorizationCodes() store.AuthorizationCodeStore {
	if s.broken.authCodes {
		return nilAuthCodeStore{AuthorizationCodeStore: s.Store.AuthorizationCodes()}
	}
	return s.Store.AuthorizationCodes()
}

func (s nilRecordStore) PushedAuthRequests() store.PushedAuthRequestStore {
	if s.broken.pars {
		return nilPARStore{PushedAuthRequestStore: s.Store.PushedAuthRequests()}
	}
	return s.Store.PushedAuthRequests()
}

func (s nilRecordStore) Users() store.UserStore {
	if s.broken.users {
		return nilUserStore{UserStore: s.Store.Users()}
	}
	return s.Store.Users()
}

func (s nilRecordStore) BeginTx(ctx context.Context) (store.Tx, error) {
	tx, err := s.Store.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return nilRecordTx{Tx: tx, broken: s.broken}, nil
}

type nilRecordTx struct {
	store.Tx
	broken brokenSubstores
}

func (t nilRecordTx) RefreshTokens() store.RefreshTokenStore {
	if t.broken.refreshTokens {
		return nilRefreshTokenStore{refreshTokenBackend: t.Tx.RefreshTokens().(refreshTokenBackend)}
	}
	return t.Tx.RefreshTokens()
}

func (t nilRecordTx) AuthorizationCodes() store.AuthorizationCodeStore {
	if t.broken.authCodes {
		return nilAuthCodeStore{AuthorizationCodeStore: t.Tx.AuthorizationCodes()}
	}
	return t.Tx.AuthorizationCodes()
}

func (t nilRecordTx) PushedAuthRequests() store.PushedAuthRequestStore {
	if t.broken.pars {
		return nilPARStore{PushedAuthRequestStore: t.Tx.PushedAuthRequests()}
	}
	return t.Tx.PushedAuthRequests()
}

type nilClientStore struct{ store.ClientStore }

//nolint:nilnil // the (nil, nil) pair is the store-contract violation under test.
func (nilClientStore) GetClient(context.Context, string) (*store.Client, error) { return nil, nil }

// refreshTokenBackend is the capability set the refresh substore carries in
// the reference adapter. The double advertises the same set so the
// decoration does not change what op.New accepts or which rotation path the
// token endpoint takes.
type refreshTokenBackend interface {
	store.RefreshTokenStore
	store.RefreshRetryResponseStore
}

type nilRefreshTokenStore struct{ refreshTokenBackend }

//nolint:nilnil // the (nil, nil) pair is the store-contract violation under test.
func (nilRefreshTokenStore) Find(context.Context, string) (*store.RefreshToken, error) {
	return nil, nil
}

//nolint:nilnil // the (nil, nil) pair is the store-contract violation under test.
func (nilRefreshTokenStore) Consume(context.Context, string) (*store.RefreshToken, error) {
	return nil, nil
}

type nilAuthCodeStore struct{ store.AuthorizationCodeStore }

//nolint:nilnil // the (nil, nil) pair is the store-contract violation under test.
func (nilAuthCodeStore) Find(context.Context, string) (*store.AuthorizationCode, error) {
	return nil, nil
}

//nolint:nilnil // the (nil, nil) pair is the store-contract violation under test.
func (nilAuthCodeStore) Consume(context.Context, string) (*store.AuthorizationCode, error) {
	return nil, nil
}

type nilPARStore struct{ store.PushedAuthRequestStore }

//nolint:nilnil // the (nil, nil) pair is the store-contract violation under test.
func (nilPARStore) Find(context.Context, string) (*store.PushedAuthRequest, error) {
	return nil, nil
}

type nilUserStore struct{ store.UserStore }

//nolint:nilnil // the (nil, nil) pair is the store-contract violation under test.
func (nilUserStore) FindBySubject(context.Context, string) (*store.User, error) { return nil, nil }

// nilRecordFixture is one OP wired over a backend whose named substores
// break the contract, together with the conforming handle tests seed
// records through.
type nilRecordFixture struct {
	server  *httptest.Server
	backing *inmem.Store
}

// newNilRecordFixture builds an OP whose store breaks the named substores.
// Records are seeded through the returned backing handle, which is the
// undecorated reference adapter — so the record genuinely exists and only
// the OP's read path is lied to.
func newNilRecordFixture(t *testing.T, broken brokenSubstores, extra ...op.Option) *nilRecordFixture {
	t.Helper()
	clock := nilRecordClock{}
	backing := inmem.New(inmem.WithClock(clock))
	opts := append([]op.Option{
		op.WithStore(nilRecordStore{Store: backing, broken: broken}),
		op.WithClock(clock),
	}, extra...)
	provider, err := op.New(testkit.MinimalOptions(t, opts...)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)
	return &nilRecordFixture{server: srv, backing: backing}
}

// seedClient registers the confidential fixture client on the backing
// store.
func (f *nilRecordFixture) seedClient(t *testing.T, id string, grantTypes, scopes []string) {
	t.Helper()
	hash, err := op.HashClientSecret(nilRecordSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	err = f.backing.RegisterClient(context.Background(), &store.Client{
		ID:                      id,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		GrantTypes:              grantTypes,
		ResponseTypes:           []string{"code"},
		Scopes:                  scopes,
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("RegisterClient(%q): %v", id, err)
	}
}

// seedRefreshToken persists a live refresh token on the backing store.
func (f *nilRecordFixture) seedRefreshToken(t *testing.T, rt *store.RefreshToken) {
	t.Helper()
	rt.CreatedAt = nilRecordAnchor
	rt.ExpiresAt = nilRecordAnchor.Add(time.Hour)
	if err := f.backing.RefreshTokens().Save(context.Background(), rt); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}
}

// seedAuthCode persists a live authorization code on the backing store.
func (f *nilRecordFixture) seedAuthCode(t *testing.T, ac *store.AuthorizationCode) {
	t.Helper()
	ac.CreatedAt = nilRecordAnchor
	ac.ExpiresAt = nilRecordAnchor.Add(time.Minute)
	if err := f.backing.AuthorizationCodes().Save(context.Background(), ac); err != nil {
		t.Fatalf("AuthorizationCodes.Save: %v", err)
	}
}

// seedPushedRequest persists a live pushed authorization request whose
// parameters would drive a complete authorization had the record been
// readable.
func (f *nilRecordFixture) seedPushedRequest(t *testing.T, uri, clientID string) {
	t.Helper()
	raw := []byte(`{"client_id":"` + clientID + `",` +
		`"redirect_uri":"https://rp.testkit.invalid/callback",` +
		`"response_type":"code","scope":["openid"],"state":"state-nil-record"}`)
	err := f.backing.PushedAuthRequests().Save(context.Background(), &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  clientID,
		RawParams: raw,
		CreatedAt: nilRecordAnchor,
		ExpiresAt: nilRecordAnchor.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("PushedAuthRequests.Save: %v", err)
	}
}

// nilRecordResponse is the part of an endpoint answer the store-contract
// assertions compare. The challenge is carried alongside the body because
// the bearer-protected endpoints state their refusal there rather than in
// the payload.
type nilRecordResponse struct {
	status    int
	challenge string
	body      string
}

// post submits form to path under client_secret_basic authentication.
func (f *nilRecordFixture) post(t *testing.T, path string, form url.Values, clientID string) nilRecordResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build %s request: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, nilRecordSecret)
	return f.do(t, req)
}

// get issues a GET against path with the supplied query, asking for JSON so
// the pre-redirect error envelope is comparable across runs.
func (f *nilRecordFixture) get(t *testing.T, path string, query url.Values) nilRecordResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.server.URL+path+"?"+query.Encode(), nil)
	if err != nil {
		t.Fatalf("build %s request: %v", path, err)
	}
	req.Header.Set("Accept", "application/json")
	return f.do(t, req)
}

func (f *nilRecordFixture) do(t *testing.T, req *http.Request) nilRecordResponse {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	//nolint:gosec // G704: the request targets this test's own httptest server.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", req.URL.Path, err)
	}
	return nilRecordResponse{
		status:    resp.StatusCode,
		challenge: resp.Header.Get("WWW-Authenticate"),
		body:      string(raw),
	}
}

// assertSameAsAbsent fails when the answer produced against a
// contract-breaking store differs from the answer the same request gets
// when the record is genuinely absent. Equality is the whole point: a
// backend that cannot produce a record has not proven the presented
// credential is valid, so the OP must reject it exactly as it rejects an
// unknown one — and must not crash on the way.
func assertSameAsAbsent(t *testing.T, absent, broken nilRecordResponse) {
	t.Helper()
	if absent != broken {
		t.Errorf("nil-record answer differs from absent-record answer:\n absent: %+v\n broken: %+v",
			absent, broken)
	}
}

// accessTokenFromTokenResponse pulls the access_token out of a successful
// token-endpoint envelope.
func accessTokenFromTokenResponse(t *testing.T, body string) string {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("/token body is not JSON: %v (raw=%s)", err, body)
	}
	at, _ := env["access_token"].(string)
	if at == "" {
		t.Fatalf("/token returned no access_token; body=%s", body)
	}
	return at
}

// userInfoWithBearer presents bearer at /userinfo. The endpoint states its
// refusal in the WWW-Authenticate challenge, which [nilRecordResponse]
// carries alongside the body.
func userInfoWithBearer(t *testing.T, f *nilRecordFixture, bearer string) nilRecordResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.server.URL+"/oidc/userinfo", nil)
	if err != nil {
		t.Fatalf("build /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return f.do(t, req)
}

// TestNilRecordStore_TokenEndpoint drives /token against a store that
// answers the refresh-token, authorization-code and client lookups with
// (nil, nil). Each grant must be refused with the same envelope an unknown
// credential earns rather than panicking the OP: /token is reachable by an
// unauthenticated caller, so a crash there is a denial of service.
func TestNilRecordStore_TokenEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("refresh_token", func(t *testing.T) {
		t.Parallel()
		const clientID = "rp-nil-refresh"
		const tokenID = "rt-nil-record" //nolint:gosec // fixture token ID, not a credential.
		const grantID = "grant-nil-refresh"
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokenID}}

		absentFixture := newNilRecordFixture(t, brokenSubstores{})
		absentFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		absent := absentFixture.post(t, "/oidc/token", form, clientID)

		brokenFixture := newNilRecordFixture(t, brokenSubstores{refreshTokens: true})
		brokenFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		brokenFixture.seedRefreshToken(t, &store.RefreshToken{
			ID: tokenID, ClientID: clientID, Subject: "user-1", GrantID: grantID,
			Scope: []string{"openid"},
		})
		broken := brokenFixture.post(t, "/oidc/token", form, clientID)

		if absent.status != http.StatusBadRequest {
			t.Fatalf("absent-record /token status=%d want 400; body=%s", absent.status, absent.body)
		}
		assertSameAsAbsent(t, absent, broken)
	})

	t.Run("authorization_code", func(t *testing.T) {
		t.Parallel()
		const clientID = "rp-nil-authcode"
		const codeID = "code-nil-record"
		form := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {codeID},
			"redirect_uri": {"https://rp.testkit.invalid/callback"},
		}

		absentFixture := newNilRecordFixture(t, brokenSubstores{})
		absentFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		absent := absentFixture.post(t, "/oidc/token", form, clientID)

		brokenFixture := newNilRecordFixture(t, brokenSubstores{authCodes: true})
		brokenFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		brokenFixture.seedAuthCode(t, &store.AuthorizationCode{
			ID: codeID, ClientID: clientID, Subject: "user-1",
			RedirectURI: "https://rp.testkit.invalid/callback",
			Scope:       []string{"openid"},
		})
		broken := brokenFixture.post(t, "/oidc/token", form, clientID)

		if absent.status != http.StatusBadRequest {
			t.Fatalf("absent-record /token status=%d want 400; body=%s", absent.status, absent.body)
		}
		assertSameAsAbsent(t, absent, broken)
	})

	t.Run("client_authentication", func(t *testing.T) {
		t.Parallel()
		const clientID = "rp-nil-client"
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"whatever"}}

		absentFixture := newNilRecordFixture(t, brokenSubstores{})
		absent := absentFixture.post(t, "/oidc/token", form, clientID)

		brokenFixture := newNilRecordFixture(t, brokenSubstores{clients: true})
		brokenFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		broken := brokenFixture.post(t, "/oidc/token", form, clientID)

		if absent.status != http.StatusUnauthorized {
			t.Fatalf("absent-client /token status=%d want 401; body=%s", absent.status, absent.body)
		}
		assertSameAsAbsent(t, absent, broken)
	})
}

// TestNilRecordStore_IntrospectEndpoint drives RFC 7662 introspection
// against a store that cannot produce the presented refresh token, and
// against one that cannot produce the authenticating client.
func TestNilRecordStore_IntrospectEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("token_lookup", func(t *testing.T) {
		t.Parallel()
		const clientID = "rp-nil-introspect"
		const tokenID = "rt-nil-introspect" //nolint:gosec // fixture token ID, not a credential.
		form := url.Values{"token": {tokenID}}

		absentFixture := newNilRecordFixture(t, brokenSubstores{}, op.WithFeature(feature.Introspect))
		absentFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		absent := absentFixture.post(t, "/oidc/introspect", form, clientID)

		brokenFixture := newNilRecordFixture(t, brokenSubstores{refreshTokens: true},
			op.WithFeature(feature.Introspect))
		brokenFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		brokenFixture.seedRefreshToken(t, &store.RefreshToken{
			ID: tokenID, ClientID: clientID, Subject: "user-1",
			Scope: []string{"openid"},
		})
		broken := brokenFixture.post(t, "/oidc/introspect", form, clientID)

		if absent.status != http.StatusOK {
			t.Fatalf("absent-record /introspect status=%d want 200; body=%s", absent.status, absent.body)
		}
		assertSameAsAbsent(t, absent, broken)
	})

	t.Run("client_authentication", func(t *testing.T) {
		t.Parallel()
		const clientID = "rp-nil-introspect-client"
		form := url.Values{"token": {"whatever"}}

		absentFixture := newNilRecordFixture(t, brokenSubstores{}, op.WithFeature(feature.Introspect))
		absent := absentFixture.post(t, "/oidc/introspect", form, clientID)

		brokenFixture := newNilRecordFixture(t, brokenSubstores{clients: true},
			op.WithFeature(feature.Introspect))
		brokenFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		broken := brokenFixture.post(t, "/oidc/introspect", form, clientID)

		if absent.status != http.StatusUnauthorized {
			t.Fatalf("absent-client /introspect status=%d want 401; body=%s", absent.status, absent.body)
		}
		assertSameAsAbsent(t, absent, broken)
	})
}

// TestNilRecordStore_RevokeEndpoint drives RFC 7009 revocation against a
// store that cannot produce the presented refresh token. The endpoint's
// "always 200" posture must survive the contract violation.
func TestNilRecordStore_RevokeEndpoint(t *testing.T) {
	t.Parallel()

	const clientID = "rp-nil-revoke"
	const tokenID = "rt-nil-revoke" //nolint:gosec // fixture token ID, not a credential.
	form := url.Values{"token": {tokenID}}

	absentFixture := newNilRecordFixture(t, brokenSubstores{}, op.WithFeature(feature.Revoke))
	absentFixture.seedClient(t, clientID,
		[]string{"authorization_code", "refresh_token"}, []string{"openid"})
	absent := absentFixture.post(t, "/oidc/revoke", form, clientID)

	brokenFixture := newNilRecordFixture(t, brokenSubstores{refreshTokens: true},
		op.WithFeature(feature.Revoke))
	brokenFixture.seedClient(t, clientID,
		[]string{"authorization_code", "refresh_token"}, []string{"openid"})
	brokenFixture.seedRefreshToken(t, &store.RefreshToken{
		ID: tokenID, ClientID: clientID, Subject: "user-1",
		Scope: []string{"openid"},
	})
	broken := brokenFixture.post(t, "/oidc/revoke", form, clientID)

	if absent.status != http.StatusOK || absent.body != "" {
		t.Fatalf("absent-record /revoke status=%d body=%q want 200 + empty", absent.status, absent.body)
	}
	assertSameAsAbsent(t, absent, broken)
}

// TestNilRecordStore_UserInfoEndpoint presents a genuinely valid access
// token at /userinfo while the user substore refuses to produce the
// subject's record. The endpoint must answer with the invalid_token
// challenge an unknown subject earns rather than releasing a claim set
// assembled from nothing.
func TestNilRecordStore_UserInfoEndpoint(t *testing.T) {
	t.Parallel()

	const clientID = "rp-nil-userinfo"
	const tokenID = "rt-nil-userinfo" //nolint:gosec // fixture token ID, not a credential.
	const subject = "user-nil-userinfo"

	mint := func(f *nilRecordFixture) string {
		f.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		f.seedRefreshToken(t, &store.RefreshToken{
			ID: tokenID, ClientID: clientID, Subject: subject,
			Scope: []string{"openid"},
		})
		res := f.post(t, "/oidc/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokenID},
		}, clientID)
		if res.status != http.StatusOK {
			t.Fatalf("/token status=%d want 200; body=%s", res.status, res.body)
		}
		return accessTokenFromTokenResponse(t, res.body)
	}

	// Absent baseline: a conforming store that simply has no row for the
	// subject. The user substore is never seeded in either fixture, so the
	// two runs differ only in how the miss is reported.
	absentFixture := newNilRecordFixture(t, brokenSubstores{})
	absent := userInfoWithBearer(t, absentFixture, mint(absentFixture))

	brokenFixture := newNilRecordFixture(t, brokenSubstores{users: true})
	broken := userInfoWithBearer(t, brokenFixture, mint(brokenFixture))

	if absent.status != http.StatusUnauthorized {
		t.Fatalf("absent-record /userinfo status=%d want 401; body=%s", absent.status, absent.body)
	}
	assertSameAsAbsent(t, absent, broken)
}

// TestNilRecordStore_AuthorizeEndpoint drives the browser-facing endpoint
// against a store that cannot produce the requesting client, and against
// one that cannot produce the pushed authorization request the caller
// references.
func TestNilRecordStore_AuthorizeEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("client_lookup", func(t *testing.T) {
		t.Parallel()
		const clientID = "rp-nil-authorize"
		query := url.Values{
			"client_id":     {clientID},
			"redirect_uri":  {"https://rp.testkit.invalid/callback"},
			"response_type": {"code"},
			"scope":         {"openid"},
			"state":         {"state-nil-record"},
		}

		absentFixture := newNilRecordFixture(t, brokenSubstores{})
		absent := absentFixture.get(t, "/oidc/auth", query)

		brokenFixture := newNilRecordFixture(t, brokenSubstores{clients: true})
		brokenFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		broken := brokenFixture.get(t, "/oidc/auth", query)

		if absent.status != http.StatusBadRequest {
			t.Fatalf("absent-client /authorize status=%d want 400; body=%s", absent.status, absent.body)
		}
		assertSameAsAbsent(t, absent, broken)
	})

	t.Run("pushed_request_lookup", func(t *testing.T) {
		t.Parallel()
		const clientID = "rp-nil-par"
		const requestURI = "urn:ietf:params:oauth:request_uri:nil-record"
		query := url.Values{"client_id": {clientID}, "request_uri": {requestURI}}

		absentFixture := newNilRecordFixture(t, brokenSubstores{}, op.WithFeature(feature.PAR))
		absentFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		absent := absentFixture.get(t, "/oidc/auth", query)

		brokenFixture := newNilRecordFixture(t, brokenSubstores{pars: true}, op.WithFeature(feature.PAR))
		brokenFixture.seedClient(t, clientID,
			[]string{"authorization_code", "refresh_token"}, []string{"openid"})
		brokenFixture.seedPushedRequest(t, requestURI, clientID)
		broken := brokenFixture.get(t, "/oidc/auth", query)

		if absent.status != http.StatusBadRequest {
			t.Fatalf("absent-record /authorize status=%d want 400; body=%s", absent.status, absent.body)
		}
		assertSameAsAbsent(t, absent, broken)
	})
}
