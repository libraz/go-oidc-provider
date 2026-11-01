//nolint:testpackage // tests reference the unexported table catalog, default-configuration table list and naming map.
package oidcsql

import (
	"bytes"
	"context"
	"crypto/sha256"
	databasesql "database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	scopedClientID     = "scoped-rp"
	scopedClientSecret = "scoped-rp-secret-0123456789abcdefghijklmnop"
	scopedRedirectURI  = "https://rp.example.com/callback"
	scopedSubject      = "scoped-user"
	scopedUsername     = "scoped@example.com"
	scopedPassword     = "scoped-password-correct-horse"
	scopedCSRFCookie   = "__Host-oidc_csrf"
	scopedVerifier     = "scoped-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
)

// scopedUsers is the embedder's own user directory: one user, held in
// memory, so the adapter's users table is never needed for logins or
// claims.
type scopedUsers struct {
	hash []byte
}

func (u *scopedUsers) user() *store.User {
	return &store.User{Subject: scopedSubject, Claims: map[string]any{"name": "Scoped User"}}
}

func (u *scopedUsers) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	if sub != scopedSubject {
		return nil, store.ErrNotFound
	}
	return u.user(), nil
}

func (u *scopedUsers) FindByUsername(_ context.Context, username string) (*store.User, error) {
	if username != scopedUsername {
		return nil, store.ErrNotFound
	}
	return u.user(), nil
}

func (u *scopedUsers) ReadPasswordHash(_ context.Context, subject string) ([]byte, error) {
	if subject != scopedSubject || len(u.hash) == 0 {
		return nil, store.ErrNotFound
	}
	return u.hash, nil
}

var _ store.UserPasswordStore = (*scopedUsers)(nil)

// scopedEmailSender discards every code; construction never sends one.
type scopedEmailSender struct{}

func (scopedEmailSender) Send(context.Context, string, string) error { return nil }

// freshDB returns a store over a new SQLite database holding only the
// tables whose WithNaming keys are in keep. No subject-mode marker is
// written, so op.New runs its first-boot path.
func freshDB(t *testing.T, keep ...string) *Store {
	t.Helper()
	db, err := databasesql.Open("sqlite", "file:"+t.TempDir()+"/oidc.db?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db, SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, key := range knownNamingKeys {
		if slices.Contains(keep, key) {
			continue
		}
		if _, err := db.ExecContext(t.Context(), "DROP TABLE "+s.names.byKey(key)); err != nil {
			t.Fatalf("drop %s: %v", key, err)
		}
	}
	return s
}

// without returns defaultConfigTables minus drop.
func without(drop ...string) []string {
	return slices.DeleteFunc(slices.Clone(defaultConfigTables), func(k string) bool {
		return slices.Contains(drop, k)
	})
}

// scopedOptions is the construction-only option set: the testkit's
// required defaults, the store, and opts on top (last wins).
func scopedOptions(t *testing.T, s store.Store, opts ...op.Option) []op.Option {
	t.Helper()
	return testkit.MinimalOptions(t, append([]op.Option{op.WithStore(s)}, opts...)...)
}

// passwordFlow is the default configuration's login flow.
func passwordFlow(users store.UserPasswordStore, rules ...op.Rule) op.Option {
	return op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: users}, Rules: rules})
}

// newScoped runs op.New and registers Shutdown so background workers
// (SSF delivery) stop with the test.
func newScoped(t *testing.T, opts []op.Option) error {
	t.Helper()
	p, err := op.New(opts...)
	if err != nil {
		return err
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return nil
}

// assertSchemaError checks err is the configuration error naming every
// physical table of keys.
func assertSchemaError(t *testing.T, s *Store, err error, keys ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("op.New succeeded with %v missing", keys)
	}
	var opErr *op.Error
	if !errors.As(err, &opErr) || opErr.Code != "configuration_error" {
		t.Fatalf("op.New error is not a configuration_error: %v", err)
	}
	if !strings.Contains(err.Error(), "store schema does not match this configuration") {
		t.Fatalf("op.New failed for a reason other than the schema: %v", err)
	}
	for _, key := range keys {
		if table := s.names.byKey(key); !strings.Contains(err.Error(), table) {
			t.Errorf("op.New error does not name %s: %v", table, err)
		}
	}
}

func TestScopedSchema_DefaultFlowRunsOnRequiredTables(t *testing.T) {
	t.Parallel()

	hash, err := op.HashPassword(scopedPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cases := []struct {
		name   string
		extra  []op.Option
		opaque bool
	}{
		{name: "jwt access token"},
		{
			name:   "opaque access token",
			extra:  []op.Option{op.WithAccessTokenFormat(op.AccessTokenFormatOpaque)},
			opaque: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := freshDB(t, defaultConfigTables...)
			users := &scopedUsers{hash: hash}
			opts := append([]op.Option{
				op.WithStore(s),
				passwordFlow(users),
				op.WithFeature(feature.Revoke),
				op.WithFeature(feature.Introspect),
				op.WithStaticClients(op.ConfidentialClient{
					ID:           scopedClientID,
					Secret:       scopedClientSecret,
					AuthMethod:   op.AuthClientSecretBasic,
					RedirectURIs: []string{scopedRedirectURI},
					Scopes:       []string{"openid", "profile"},
					GrantTypes:   []string{"authorization_code", "refresh_token"},
				}),
			}, tc.extra...)
			p := testkit.NewProvider(t, testkit.WithOptions(opts...))

			code := scopedCodeFlow(t, p)
			tokens := scopedToken(t, p, http.StatusOK, url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {scopedRedirectURI},
				"code_verifier": {scopedVerifier},
			})
			access := scopedString(t, tokens, "access_token")
			refresh := scopedString(t, tokens, "refresh_token")
			scopedString(t, tokens, "id_token")
			if isJWT := strings.Count(access, ".") == 2; isJWT == tc.opaque {
				t.Fatalf("access token %q: JWT=%v, want JWT=%v", access, isJWT, !tc.opaque)
			}
			scopedUserInfo(t, p, access, http.StatusOK)

			rotated := scopedToken(t, p, http.StatusOK, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
			})
			access = scopedString(t, rotated, "access_token")
			refresh = scopedString(t, rotated, "refresh_token")
			scopedUserInfo(t, p, access, http.StatusOK)
			scopedIntrospect(t, p, access, true)

			scopedRevoke(t, p, access, "access_token")
			scopedIntrospect(t, p, access, false)
			scopedUserInfo(t, p, access, http.StatusUnauthorized)

			scopedRevoke(t, p, refresh, "refresh_token")
			scopedToken(t, p, http.StatusBadRequest, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
			})
		})
	}
}

func TestScopedSchema_EachRequiredTableIsChecked(t *testing.T) {
	t.Parallel()

	for _, key := range defaultConfigTables {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			s := freshDB(t, without(key)...)
			err := newScoped(t, scopedOptions(t, s, passwordFlow(&scopedUsers{})))
			assertSchemaError(t, s, err, key)
		})
	}
}

// scopedConfig builds the options of one configuration over s.
type scopedConfig func(t *testing.T, s *Store, users *scopedUsers) []op.Option

// scopedDefault is the default configuration: password login against
// the embedder's user store, every other option at its default.
func scopedDefault(_ *testing.T, _ *Store, users *scopedUsers) []op.Option {
	return []op.Option{passwordFlow(users)}
}

// scopedCase pairs a configuration that requires tables with one that
// does not. The database holds the default configuration's tables minus
// tables.
type scopedCase struct {
	name   string
	tags   []string // checked tags the case exercises
	tables []string // WithNaming keys missing from the database
	on     scopedConfig
	off    scopedConfig
	// onStore and offStore wrap the SQL store; nil uses it as is.
	onStore, offStore func(t *testing.T, s *Store) store.Store
}

// scopedEncryptionKey is a fixed 32-byte TOTP encryption key; no secret
// is ever sealed with it.
var scopedEncryptionKey = bytes.Repeat([]byte{0x5a}, 32)

func scopedRule(step op.Step) scopedConfig {
	return func(_ *testing.T, _ *Store, users *scopedUsers) []op.Option {
		return []op.Option{passwordFlow(users, op.RuleAlways(step))}
	}
}

func scopedCases() []scopedCase {
	withDefault := func(extra ...op.Option) scopedConfig {
		return func(t *testing.T, s *Store, users *scopedUsers) []op.Option {
			return append(scopedDefault(t, s, users), extra...)
		}
	}
	return []scopedCase{
		{
			name: "par", tags: []string{"feature:par"}, tables: []string{"par_records"},
			on: withDefault(op.WithFeature(feature.PAR)), off: scopedDefault,
		},
		{
			name: "dcr", tags: []string{"dcr"}, tables: []string{"initial_access_tokens", "registration_access_tokens"},
			on: withDefault(op.WithDynamicRegistration(op.RegistrationOption{})), off: scopedDefault,
		},
		{
			name: "device_code", tags: []string{"grant:device_code"}, tables: []string{"device_codes"},
			on: withDefault(op.WithDeviceCodeGrant()), off: scopedDefault,
		},
		{
			name: "ciba", tags: []string{"grant:ciba"}, tables: []string{"ciba_requests"},
			on: withDefault(op.WithCIBA(op.WithCIBAHintResolver(op.HintResolverFunc(
				func(context.Context, op.HintKind, string) (string, error) { return scopedSubject, nil },
			)))),
			off: scopedDefault,
		},
		{
			name: "ssf", tags: []string{"ssf"}, tables: []string{"ssf_streams", "ssf_events"},
			on: withDefault(op.WithSharedSignals()), off: scopedDefault,
		},
		{
			name: "totp", tags: []string{"factor:totp"}, tables: []string{"totp_secrets"},
			on: func(t *testing.T, s *Store, users *scopedUsers) []op.Option {
				return scopedRule(op.StepTOTP{Store: s.TOTPs(), EncryptionKey: scopedEncryptionKey})(t, s, users)
			},
			off: scopedDefault,
		},
		{
			name: "passkey", tags: []string{"factor:passkey"}, tables: []string{"passkeys"},
			on: func(_ *testing.T, s *Store, users *scopedUsers) []op.Option {
				return []op.Option{
					op.WithUserStore(users),
					op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPasskey{
						Store:                   s.Passkeys(),
						RPID:                    "op.testkit.invalid",
						RPDisplayName:           "Scoped Schema",
						RPOrigins:               []string{testkit.DefaultIssuer},
						RequireUserVerification: true,
					}}),
				}
			},
			off: scopedDefault,
		},
		{
			name: "recovery", tags: []string{"factor:recovery"}, tables: []string{"recovery_codes"},
			on: func(t *testing.T, s *Store, users *scopedUsers) []op.Option {
				return scopedRule(op.StepRecoveryCode{Store: s.RecoveryCodes()})(t, s, users)
			},
			off: scopedDefault,
		},
		{
			name: "email_otp", tags: []string{"factor:email_otp"}, tables: []string{"email_otps"},
			on: func(t *testing.T, s *Store, users *scopedUsers) []op.Option {
				return scopedRule(op.StepEmailOTP{Store: s.EmailOTPs(), Sender: scopedEmailSender{}, Users: users})(t, s, users)
			},
			off: scopedDefault,
		},
		{
			name: "lockout store elsewhere", tags: []string{"lockout"}, tables: []string{"authn_lockouts"},
			on: scopedDefault,
			off: func(t *testing.T, s *Store, users *scopedUsers) []op.Option {
				return append(scopedDefault(t, s, users), op.WithAuthnLockoutStore(inmem.New().AuthnLockouts()))
			},
		},
		{
			name: "userstore fallback", tags: []string{"userstore-fallback"}, tables: []string{"users"},
			on: func(_ *testing.T, s *Store, _ *scopedUsers) []op.Option {
				return []op.Option{op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: s.UserPasswords()}})}
			},
			off: scopedDefault,
		},
		{
			name: "client_credentials only",
			tags: []string{"grant:authorization_code", "grant:refresh_token", "authorize", "lockout"},
			tables: []string{
				"authorization_codes", "refresh_tokens", "sessions", "interactions", "authn_lockouts",
			},
			on: scopedDefault,
			// Without a login flow the claims user store falls back to the
			// adapter's users table, so the embedder names its own.
			off: func(_ *testing.T, _ *Store, users *scopedUsers) []op.Option {
				return []op.Option{op.WithGrants(grant.ClientCredentials), op.WithUserStore(users)}
			},
		},
		{
			name:   "composite routes sessions, interactions and users elsewhere",
			tags:   []string{"authorize", "lockout"},
			tables: []string{"sessions", "interactions", "authn_lockouts"},
			on:     scopedDefault,
			off:    scopedDefault,
			offStore: func(t *testing.T, s *Store) store.Store {
				t.Helper()
				mem := inmem.New()
				c, err := composite.New(
					composite.WithDefault(s),
					composite.With(composite.Sessions, mem),
					composite.With(composite.Interactions, mem),
					composite.With(composite.Users, mem),
				)
				if err != nil {
					t.Fatalf("composite.New: %v", err)
				}
				return c
			},
		},
	}
}

// scopedBuild assembles a configuration's options over a fresh DB.
func scopedBuild(t *testing.T, tc scopedCase, cfg scopedConfig, wrap func(*testing.T, *Store) store.Store) (*Store, error) {
	t.Helper()
	s := freshDB(t, without(tc.tables...)...)
	var backing store.Store = s
	if wrap != nil {
		backing = wrap(t, s)
	}
	return s, newScoped(t, scopedOptions(t, backing, cfg(t, s, &scopedUsers{})...))
}

func TestScopedSchema_FeatureTables(t *testing.T) {
	t.Parallel()

	for _, tc := range scopedCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			t.Run("required", func(t *testing.T) {
				t.Parallel()
				s, err := scopedBuild(t, tc, tc.on, tc.onStore)
				assertSchemaError(t, s, err, tc.tables...)
			})
			t.Run("not required", func(t *testing.T) {
				t.Parallel()
				if _, err := scopedBuild(t, tc, tc.off, tc.offStore); err != nil {
					t.Fatalf("op.New with %v missing: %v", tc.tables, err)
				}
			})
		})
	}
}

func TestScopedSchema_EveryCheckTagHasAConfiguration(t *testing.T) {
	t.Parallel()

	tagOf := map[string]string{}
	for _, info := range tableCatalog {
		tagOf[info.key] = info.checked
	}
	// Every default-configuration table is dropped one at a time by
	// TestScopedSchema_EachRequiredTableIsChecked, which covers its tag.
	covered := map[string]bool{}
	for _, key := range defaultConfigTables {
		covered[tagOf[key]] = true
	}
	for _, tc := range scopedCases() {
		for _, key := range tc.tables {
			if !slices.Contains(tc.tags, tagOf[key]) {
				t.Errorf("case %q drops %s (tag %q) but does not list the tag", tc.name, key, tagOf[key])
			}
		}
		for _, tag := range tc.tags {
			if _, ok := checkedWhen[tag]; !ok {
				t.Errorf("case %q lists unknown tag %q", tc.name, tag)
			}
			covered[tag] = true
		}
	}
	var uncovered []string
	for _, info := range tableCatalog {
		if !covered[info.checked] && !slices.Contains(uncovered, info.checked) {
			uncovered = append(uncovered, info.checked)
		}
	}
	if len(uncovered) > 0 {
		t.Fatalf("checked tags without a configuration in TestScopedSchema_FeatureTables: %v", uncovered)
	}
}

// scopedCodeFlow walks /authorize → password login → consent → callback
// and returns the authorization code.
func scopedCodeFlow(t *testing.T, p *testkit.Provider) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	httpClient := p.HTTPClient(jar)

	sum := sha256.Sum256([]byte(scopedVerifier))
	params := url.Values{
		"client_id":             {scopedClientID},
		"redirect_uri":          {scopedRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"scoped-state"},
		"nonce":                 {"scoped-nonce"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	resp := scopedDo(t, httpClient, http.MethodGet, p.Server.URL+"/oidc/auth?"+params.Encode(), nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/authorize status=%d body=%s", resp.StatusCode, body)
	}
	location, err := resp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize Location=%s, want an interaction URL", location)
	}
	interactionURL := p.Server.URL + location.Path

	prompt := scopedDo(t, httpClient, http.MethodGet, interactionURL, nil, nil)
	defer func() { _ = prompt.Body.Close() }()
	if prompt.StatusCode != http.StatusOK {
		t.Fatalf("GET interaction status=%d", prompt.StatusCode)
	}
	envelope := scopedJSON(t, prompt)
	stateRef, _ := envelope["state_ref"].(string)
	if stateRef == "" {
		t.Fatalf("interaction prompt carries no state_ref: %v", envelope)
	}
	csrf := scopedCookie(prompt.Cookies())
	if csrf == nil {
		t.Fatalf("interaction prompt set no %s cookie", scopedCSRFCookie)
	}

	login := scopedInteraction(t, httpClient, interactionURL, p.Issuer, csrf, stateRef,
		map[string]string{"username": scopedUsername, "password": scopedPassword})
	final := scopedConsent(t, httpClient, interactionURL, p.Issuer, csrf, login)
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(final.Body)
		t.Fatalf("final interaction status=%d body=%s", final.StatusCode, body)
	}
	callback, err := final.Location()
	if err != nil {
		t.Fatalf("final Location: %v", err)
	}
	if got := callback.Query().Get("error"); got != "" {
		t.Fatalf("callback carries error=%s (%s)", got, callback.Query().Get("error_description"))
	}
	if got := callback.Query().Get("state"); got != "scoped-state" {
		t.Fatalf("callback state=%q, want scoped-state", got)
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatal("callback carries no code")
	}
	return code
}

// scopedConsent approves every scope the consent prompt presents, when
// one is prompted.
func scopedConsent(
	t *testing.T,
	httpClient *http.Client,
	interactionURL, origin string,
	csrf *http.Cookie,
	prior *http.Response,
) *http.Response {
	t.Helper()
	consent, envelope, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	stateRef, _ := envelope["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("consent prompt carries no state_ref")
	}
	// Each step boundary re-issues the CSRF cookie.
	if rotated := scopedCookie(prior.Cookies()); rotated != nil {
		csrf = rotated
	}
	approved := testkit.ApprovedScopesFrom(t, envelope)
	_ = prior.Body.Close()
	return scopedInteraction(t, httpClient, interactionURL, origin, csrf, stateRef,
		map[string]string{"approved_scopes": approved})
}

func scopedInteraction(
	t *testing.T,
	httpClient *http.Client,
	interactionURL, origin string,
	csrf *http.Cookie,
	stateRef string,
	values map[string]string,
) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		t.Fatalf("marshal interaction submission: %v", err)
	}
	return scopedDo(t, httpClient, http.MethodPost, interactionURL, bytes.NewReader(body), func(req *http.Request) {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", csrf.Value)
		req.AddCookie(csrf)
	})
}

// scopedPostForm POSTs form to an OP endpoint as the confidential client.
func scopedPostForm(t *testing.T, p *testkit.Provider, path string, form url.Values) *http.Response {
	t.Helper()
	return scopedDo(t, p.Server.Client(), http.MethodPost, p.Server.URL+path, strings.NewReader(form.Encode()),
		func(req *http.Request) {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(scopedClientID, scopedClientSecret)
		})
}

func scopedToken(t *testing.T, p *testkit.Provider, want int, form url.Values) map[string]any {
	t.Helper()
	resp := scopedPostForm(t, p, "/oidc/token", form)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token grant_type=%s status=%d want %d body=%s", form.Get("grant_type"), resp.StatusCode, want, body)
	}
	return scopedJSON(t, resp)
}

func scopedRevoke(t *testing.T, p *testkit.Provider, token, hint string) {
	t.Helper()
	resp := scopedPostForm(t, p, "/oidc/revoke", url.Values{"token": {token}, "token_type_hint": {hint}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/revoke %s status=%d body=%s", hint, resp.StatusCode, body)
	}
}

func scopedIntrospect(t *testing.T, p *testkit.Provider, token string, wantActive bool) {
	t.Helper()
	resp := scopedPostForm(t, p, "/oidc/introspect", url.Values{"token": {token}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/introspect status=%d body=%s", resp.StatusCode, body)
	}
	claims := scopedJSON(t, resp)
	if active, _ := claims["active"].(bool); active != wantActive {
		t.Fatalf("/introspect active=%v, want %v: %v", claims["active"], wantActive, claims)
	}
	if wantActive && claims["sub"] != scopedSubject {
		t.Fatalf("/introspect sub=%v, want %s", claims["sub"], scopedSubject)
	}
}

func scopedUserInfo(t *testing.T, p *testkit.Provider, accessToken string, want int) {
	t.Helper()
	resp := scopedDo(t, p.Server.Client(), http.MethodGet, p.Server.URL+"/oidc/userinfo", nil, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/userinfo status=%d want %d challenge=%q body=%s",
			resp.StatusCode, want, resp.Header.Get("WWW-Authenticate"), body)
	}
	if want != http.StatusOK {
		return
	}
	claims := scopedJSON(t, resp)
	if claims["sub"] != scopedSubject || claims["name"] != "Scoped User" {
		t.Fatalf("/userinfo claims=%v, want sub %s with its name", claims, scopedSubject)
	}
}

func scopedDo(
	t *testing.T,
	httpClient *http.Client,
	method, target string,
	body io.Reader,
	prepare func(*http.Request),
) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, target, err)
	}
	if prepare != nil {
		prepare(req)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return resp
}

func scopedJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body %s: %v", raw, err)
	}
	return out
}

func scopedString(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, _ := m[key].(string)
	if v == "" {
		t.Fatalf("response carries no %s: %v", key, m)
	}
	return v
}

func scopedCookie(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == scopedCSRFCookie {
			return c
		}
	}
	return nil
}
