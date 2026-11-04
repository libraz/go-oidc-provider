package op_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	scdCallback  = "https://rp.testkit.invalid/callback"
	scdCustomACR = "urn:example:basic"
	scdVerifier  = "static-client-defaults-pkce-verifier-0123456789abcdef"
)

// TestStaticClientDefaults_SeededAndApplied pins that the per-client
// defaults on a static seed reach the stored record and take effect on
// /authorize and the token endpoint.
func TestStaticClientDefaults_SeededAndApplied(t *testing.T) {
	t.Parallel()

	zero := int64(0)
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithACRPolicy(op.ACRLevels{scdCustomACR: op.AAL1}),
		op.WithACRValuesSupported(scdCustomACR, op.AAL1.ACRURI()),
		op.WithStaticClients(
			op.PublicClient{
				ID:               "rp-defaults",
				RedirectURIs:     []string{scdCallback},
				Scopes:           []string{"openid"},
				DefaultMaxAge:    &zero,
				RequireAuthTime:  true,
				DefaultACRValues: []string{scdCustomACR},
			},
			op.PublicClient{
				ID:           "rp-plain",
				RedirectURIs: []string{scdCallback},
				Scopes:       []string{"openid"},
			},
		),
	))

	stored, err := tk.Store.GetClient(context.Background(), "rp-defaults")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored.DefaultMaxAge == nil || *stored.DefaultMaxAge != 0 {
		t.Errorf("DefaultMaxAge = %v, want pointer to 0", stored.DefaultMaxAge)
	}
	if !stored.RequireAuthTime {
		t.Error("RequireAuthTime was not seeded")
	}
	if !slices.Equal(stored.DefaultACRValues, []string{scdCustomACR}) {
		t.Errorf("DefaultACRValues = %v, want [%s]", stored.DefaultACRValues, scdCustomACR)
	}
	plain, err := tk.Store.GetClient(context.Background(), "rp-plain")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if plain.DefaultMaxAge != nil || plain.RequireAuthTime || len(plain.DefaultACRValues) != 0 {
		t.Errorf("plain client carries defaults: %+v", plain)
	}

	t.Run("client with defaults", func(t *testing.T) {
		t.Parallel()
		f := newSCDFlow(t, tk, "rp-defaults")
		code, interacted := f.authorize(t)
		if !interacted {
			t.Fatal("first authorization must run a login")
		}
		claims := f.idTokenClaims(t, code)
		if got := claims["acr"]; got != scdCustomACR {
			t.Errorf("acr = %v, want default %q", got, scdCustomACR)
		}
		if _, ok := claims["auth_time"].(float64); !ok {
			t.Errorf("auth_time absent from id_token: %v", claims)
		}
		if _, again := f.authorize(t); !again {
			t.Error("default_max_age=0 must force re-authentication on the next request")
		}
	})

	t.Run("client without defaults", func(t *testing.T) {
		t.Parallel()
		f := newSCDFlow(t, tk, "rp-plain")
		code, interacted := f.authorize(t)
		if !interacted {
			t.Fatal("first authorization must run a login")
		}
		claims := f.idTokenClaims(t, code)
		if got := claims["acr"]; got != op.AAL1.ACRURI() {
			t.Errorf("acr = %v, want %q", got, op.AAL1.ACRURI())
		}
		if _, again := f.authorize(t); again {
			t.Error("a client without default_max_age must be served from the session")
		}
	})
}

// TestStaticClientDefaults_UnadvertisedACRRejected pins the construction
// check on DefaultACRValues.
func TestStaticClientDefaults_UnadvertisedACRRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		extra     []op.Option
		defaults  []string
		wantError string
	}{
		{
			name:     "empty defaults are unset",
			defaults: nil,
		},
		{
			name: "advertised and declared",
			extra: []op.Option{
				op.WithACRPolicy(op.ACRLevels{scdCustomACR: op.AAL1}),
				op.WithACRValuesSupported(scdCustomACR),
			},
			defaults: []string{scdCustomACR},
		},
		{
			name: "duplicates are kept",
			extra: []op.Option{
				op.WithACRPolicy(op.ACRLevels{scdCustomACR: op.AAL1}),
				op.WithACRValuesSupported(scdCustomACR),
			},
			defaults: []string{scdCustomACR, scdCustomACR},
		},
		{
			name: "declared but not advertised",
			extra: []op.Option{
				op.WithACRPolicy(op.ACRLevels{scdCustomACR: op.AAL1}),
				op.WithACRValuesSupported(op.AAL1.ACRURI()),
			},
			defaults:  []string{scdCustomACR},
			wantError: scdCustomACR,
		},
		{
			name:      "unknown to the built-in policy",
			defaults:  []string{"urn:unknown"},
			wantError: "urn:unknown",
		},
		{
			name: "custom policy still needs the advertisement",
			extra: []op.Option{
				op.WithACRPolicy(stubACRPolicy{}),
				op.WithACRValuesSupported(op.AAL1.ACRURI()),
			},
			defaults:  []string{"urn:custom"},
			wantError: "urn:custom",
		},
		{
			name:     "custom policy without an advertisement is not inspected",
			extra:    []op.Option{op.WithACRPolicy(stubACRPolicy{})},
			defaults: []string{"urn:custom"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := testkit.MinimalOptions(t, append(tc.extra, op.WithStaticClients(op.PublicClient{
				ID:               "rp-acr",
				RedirectURIs:     []string{scdCallback},
				Scopes:           []string{"openid"},
				DefaultACRValues: tc.defaults,
			}))...)
			_, err := op.New(opts...)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted the configuration, want a configuration error")
			}
			desc := configurationDescription(t, err)
			for _, want := range []string{"rp-acr", tc.wantError} {
				if !strings.Contains(desc, want) {
					t.Errorf("description %q must mention %q", desc, want)
				}
			}
		})
	}
}

// TestStaticClientDefaults_NegativeMaxAgeRejected pins that every builder
// refuses a negative DefaultMaxAge while accepting zero.
func TestStaticClientDefaults_NegativeMaxAgeRejected(t *testing.T) {
	t.Parallel()

	neg, zero := int64(-1), int64(0)
	seeds := map[string]func(maxAge *int64) op.ClientSeed{
		"public": func(m *int64) op.ClientSeed {
			return op.PublicClient{ID: "rp-age", DefaultMaxAge: m}
		},
		"confidential": func(m *int64) op.ClientSeed {
			return op.ConfidentialClient{ID: "rp-age", Secret: "rp-age-secret-0123456789-abcdefghijklmnopqrstu", DefaultMaxAge: m}
		},
		"private_key_jwt": func(m *int64) op.ClientSeed {
			return op.PrivateKeyJWTClient{ID: "rp-age", JWKS: []byte(`{"keys":[]}`), DefaultMaxAge: m}
		},
	}
	for name, mk := range seeds {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(testkit.MinimalOptions(t, op.WithStaticClients(mk(&neg)))...)
			if err == nil {
				t.Fatal("op.New accepted a negative DefaultMaxAge")
			}
			desc := configurationDescription(t, err)
			for _, want := range []string{"rp-age", "DefaultMaxAge"} {
				if !strings.Contains(desc, want) {
					t.Errorf("description %q must mention %q", desc, want)
				}
			}
			// Zero means "always re-authenticate" and must stay valid; the
			// seed error, if any, surfaces before later validation.
			if _, err := op.New(testkit.MinimalOptions(t, op.WithStaticClients(mk(&zero)))...); err != nil &&
				strings.Contains(err.Error(), "DefaultMaxAge") {
				t.Errorf("zero DefaultMaxAge rejected: %v", err)
			}
		})
	}
}

// scdFlow drives authorization-code round trips for one public client on
// its own cookie jar.
type scdFlow struct {
	tk       *testkit.Provider
	client   *http.Client
	clientID string
}

func newSCDFlow(t *testing.T, tk *testkit.Provider, clientID string) *scdFlow {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &scdFlow{tk: tk, client: tk.HTTPClient(jar), clientID: clientID}
}

func scdChallenge() string {
	sum := sha256.Sum256([]byte(scdVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *scdFlow) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

func (f *scdFlow) get(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		t.Fatalf("build GET: %v", err)
	}
	return f.do(t, req)
}

// authorize runs one /authorize request and returns the code, and whether
// a login interaction ran rather than the session serving the request.
func (f *scdFlow) authorize(t *testing.T) (code string, interacted bool) {
	t.Helper()
	q := url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {scdCallback},
		"scope":                 {"openid"},
		"state":                 {"state-scd"},
		"nonce":                 {"nonce-scd"},
		"code_challenge":        {scdChallenge()},
		"code_challenge_method": {"S256"},
	}
	resp := f.get(t, f.tk.Server.URL+"/oidc/auth?"+q.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/authorize status=%d want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if loc.Host == "rp.testkit.invalid" {
		return scdCodeFrom(t, loc), false
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize Location=%s want callback or interaction", loc)
	}
	return f.completeInteraction(t, f.tk.Server.URL+loc.Path), true
}

func scdCodeFrom(t *testing.T, loc *url.URL) string {
	t.Helper()
	if e := loc.Query().Get("error"); e != "" {
		t.Fatalf("authorize error on callback: %s (%s)", e, loc.Query().Get("error_description"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in callback %s", loc)
	}
	return code
}

func scdCSRFCookie(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == "__Host-oidc_csrf" {
			return c
		}
	}
	return nil
}

func (f *scdFlow) completeInteraction(t *testing.T, interactionURL string) string {
	t.Helper()
	prompt := f.get(t, interactionURL)
	var step map[string]any
	err := json.NewDecoder(prompt.Body).Decode(&step)
	_ = prompt.Body.Close()
	if err != nil {
		t.Fatalf("decode interaction prompt: %v", err)
	}
	stateRef, _ := step["state_ref"].(string)
	csrf := scdCSRFCookie(prompt.Cookies())
	if stateRef == "" || csrf == nil {
		t.Fatalf("interaction prompt missing state_ref/csrf: %v", step)
	}

	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{testkit.SubjectFieldName: "user-scd"},
	})
	if err != nil {
		t.Fatalf("marshal interaction body: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build interaction POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.tk.Issuer)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf.Value})
	final := f.do(t, req)

	consent, env, err := testkit.IsConsentPrompt(final)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if consent {
		consentRef, _ := env["state_ref"].(string)
		if rotated := scdCSRFCookie(final.Cookies()); rotated != nil {
			csrf = rotated
		}
		final = testkit.PostConsentApproval(t, f.client, interactionURL, f.tk.Issuer,
			csrf.Value, consentRef, "openid")
	}
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(final.Body)
		t.Fatalf("interaction final status=%d body=%s", final.StatusCode, body)
	}
	loc, err := final.Location()
	if err != nil {
		t.Fatalf("final Location: %v", err)
	}
	return scdCodeFrom(t, loc)
}

// idTokenClaims redeems code at the token endpoint and returns the
// id_token payload.
func (f *scdFlow) idTokenClaims(t *testing.T, code string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.clientID},
		"code":          {code},
		"redirect_uri":  {scdCallback},
		"code_verifier": {scdVerifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := f.do(t, req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status=%d body=%s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	idToken, _ := out["id_token"].(string)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token malformed: %q", idToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal id_token claims: %v", err)
	}
	return claims
}

// TestClientSeed_PreviousSecret_Validation pins the shape rules on the
// previous-secret fields and their interaction with
// WithHighEntropyClientSecrets.
func TestClientSeed_PreviousSecret_Validation(t *testing.T) {
	t.Parallel()

	_, heCurrent, err := op.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret: %v", err)
	}
	_, hePrevious, err := op.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret: %v", err)
	}
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	past := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	base := func() op.ConfidentialClient {
		return op.ConfidentialClient{
			ID:           "rp-rotate",
			RedirectURIs: []string{scdCallback},
			Scopes:       []string{"openid"},
		}
	}

	tests := []struct {
		name      string
		highEntro bool
		seed      func() op.ConfidentialClient
		wantError string
	}{
		{
			name: "plaintext previous with expiry",
			seed: func() op.ConfidentialClient {
				c := base()
				c.Secret, c.PreviousSecret, c.PreviousSecretExpiresAt = "new-secret-0123456789-abcdefghijklmnopqrstuv", "old-secret", future
				return c
			},
		},
		{
			name: "hash previous with expiry",
			seed: func() op.ConfidentialClient {
				c := base()
				c.Secret, c.PreviousSecretHash, c.PreviousSecretExpiresAt = "new-secret-0123456789-abcdefghijklmnopqrstuv", hePrevious, future
				return c
			},
		},
		{
			name: "past expiry is not an error",
			seed: func() op.ConfidentialClient {
				c := base()
				c.Secret, c.PreviousSecret, c.PreviousSecretExpiresAt = "new-secret-0123456789-abcdefghijklmnopqrstuv", "old-secret", past
				return c
			},
		},
		{
			name: "both previous forms are exclusive",
			seed: func() op.ConfidentialClient {
				c := base()
				c.Secret, c.PreviousSecret, c.PreviousSecretHash = "new-secret-0123456789-abcdefghijklmnopqrstuv", "old-secret", hePrevious
				c.PreviousSecretExpiresAt = future
				return c
			},
			wantError: "mutually exclusive",
		},
		{
			name: "plaintext previous needs an expiry",
			seed: func() op.ConfidentialClient {
				c := base()
				c.Secret, c.PreviousSecret = "new-secret-0123456789-abcdefghijklmnopqrstuv", "old-secret"
				return c
			},
			wantError: "PreviousSecretExpiresAt",
		},
		{
			name: "hash previous needs an expiry",
			seed: func() op.ConfidentialClient {
				c := base()
				c.Secret, c.PreviousSecretHash = "new-secret-0123456789-abcdefghijklmnopqrstuv", hePrevious
				return c
			},
			wantError: "PreviousSecretExpiresAt",
		},
		{
			name:      "high entropy rejects an argon2id previous",
			highEntro: true,
			seed: func() op.ConfidentialClient {
				c := base()
				c.SecretHash, c.PreviousSecret, c.PreviousSecretExpiresAt = heCurrent, "old-secret", future
				return c
			},
			wantError: "previous secret",
		},
		{
			name:      "high entropy accepts a high-entropy previous hash",
			highEntro: true,
			seed: func() op.ConfidentialClient {
				c := base()
				c.SecretHash, c.PreviousSecretHash, c.PreviousSecretExpiresAt = heCurrent, hePrevious, future
				return c
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			extra := []op.Option{op.WithStaticClients(tc.seed())}
			if tc.highEntro {
				extra = append(extra, op.WithHighEntropyClientSecrets())
			}
			_, err := op.New(testkit.MinimalOptions(t, extra...)...)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted the configuration, want a configuration error")
			}
			if desc := configurationDescription(t, err); !strings.Contains(desc, tc.wantError) {
				t.Errorf("description %q must mention %q", desc, tc.wantError)
			}
		})
	}
}

// TestConfidentialClient_SecretFloor pins the 32-byte floor on a
// plaintext Secret: one byte short fails op.New with a message that
// points at op.NewClientSecret; the previous secret and a pre-hashed
// SecretHash are outside the floor.
func TestConfidentialClient_SecretFloor(t *testing.T) {
	t.Parallel()

	_, hash, err := op.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret: %v", err)
	}
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		seed      op.ConfidentialClient
		wantError bool
	}{
		{
			name:      "31 bytes fails",
			seed:      op.ConfidentialClient{Secret: strings.Repeat("a", 31)},
			wantError: true,
		},
		{
			name: "32 bytes succeeds",
			seed: op.ConfidentialClient{Secret: strings.Repeat("a", 32)},
		},
		{
			name: "short previous secret with expiry succeeds",
			seed: op.ConfidentialClient{
				Secret:                  strings.Repeat("a", 32),
				PreviousSecret:          "short",
				PreviousSecretExpiresAt: future,
			},
		},
		{
			name: "SecretHash passes through",
			seed: op.ConfidentialClient{SecretHash: hash},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seed := tc.seed
			seed.ID = "rp-floor"
			seed.RedirectURIs = []string{scdCallback}
			seed.Scopes = []string{"openid"}
			_, err := op.New(testkit.MinimalOptions(t, op.WithStaticClients(seed))...)
			if !tc.wantError {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted a 31-byte Secret")
			}
			desc := configurationDescription(t, err)
			for _, want := range []string{"rp-floor", "31 bytes", "op.NewClientSecret", "SecretHash"} {
				if !strings.Contains(desc, want) {
					t.Errorf("description %q must mention %q", desc, want)
				}
			}
		})
	}
}

// TestClientSeed_PublicSurface pins the public-API shape of the
// three typed builders — every field that embedders set is exported
// and the zero value is a valid (if unsuitable) starting point for
// op.WithStaticClients. Deeper invariants (seed() output, secret
// hashing, defensive copies) live in client_seed_internal_test.go
// because they exercise the unexported seed() method.
func TestClientSeed_PublicSurface(t *testing.T) {
	t.Parallel()

	pub := op.PublicClient{
		ID:            "demo-spa",
		RedirectURIs:  []string{"https://app.example.com/cb"},
		Scopes:        []string{"openid"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}
	if pub.ID == "" {
		t.Fatal("PublicClient.ID is not assignable")
	}

	conf := op.ConfidentialClient{
		ID:           "demo-confidential",
		Secret:       "demo-secret-0123456789-abcdefghijklmnopqrstu",
		AuthMethod:   op.AuthClientSecretBasic,
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	}
	if conf.AuthMethod != op.AuthClientSecretBasic {
		t.Fatal("ConfidentialClient.AuthMethod is not assignable")
	}

	pkj := op.PrivateKeyJWTClient{
		ID:           "demo-fapi",
		JWKS:         []byte(`{"keys":[]}`),
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	}
	if len(pkj.JWKS) == 0 {
		t.Fatal("PrivateKeyJWTClient.JWKS is not assignable")
	}
}
