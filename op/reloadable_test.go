package op_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// reloadOtherIssuer is the issuer a reload that changes the issuer asks for.
const reloadOtherIssuer = "https://other-idp.example.com"

// reloadProbeMetric is a scalar counter, so Gather reports it without a sample.
const reloadProbeMetric = "oidc_refresh_replay_detected_total"

// reloadSeedClientID is the static client every reload fixture seeds; a
// build failure is provoked by seeding it again with different metadata.
const reloadSeedClientID = "reload-rp"

// reloadNow is the fixed instant every reload fixture's clock reports.
func reloadNow() time.Time { return time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC) }

// reloadFixture is the state a Reloadable and every option list built for
// it share: one store, one cookie key, the signing keys created so far and,
// when set, one registry.
type reloadFixture struct {
	st        *inmem.Store
	reg       *prometheus.Registry
	cookieKey []byte
	keys      []op.SigningKey
}

func newReloadFixture(t *testing.T, withPrometheus bool) *reloadFixture {
	t.Helper()
	f := &reloadFixture{st: inmem.New(), cookieKey: newRandomCookieKey(t)}
	if withPrometheus {
		f.reg = prometheus.NewRegistry()
	}
	return f
}

// opts returns a complete option list signing with the key named kid,
// created on first use. Every other key the fixture created stays listed
// as a retiring key, so a reload never drops the running active key.
func (f *reloadFixture) opts(t *testing.T, issuer, kid string, extra ...op.Option) []op.Option {
	t.Helper()
	opts := []op.Option{
		op.WithIssuer(issuer),
		op.WithStore(f.st),
		op.WithKeyset(f.keyset(t, kid)),
		op.WithCookieKeys(f.cookieKey),
		op.WithClock(fakeClock{now: reloadNow()}),
		fixtureAuthenticator(),
	}
	if f.reg != nil {
		opts = append(opts, op.WithPrometheus(f.reg))
	}
	return append(opts, extra...)
}

// keyset returns the fixture's keys with the one named kid first.
func (f *reloadFixture) keyset(t *testing.T, kid string) op.Keyset {
	t.Helper()
	i := slices.IndexFunc(f.keys, func(k op.SigningKey) bool { return k.KeyID == kid })
	if i < 0 {
		f.keys = append(f.keys, newTestKey(t, kid))
		i = len(f.keys) - 1
	}
	ks := op.Keyset{f.keys[i]}
	for j, k := range f.keys {
		if j != i {
			ks = append(ks, k)
		}
	}
	return ks
}

// reloadSeed seeds the fixture's static client with redirectURI.
func reloadSeed(redirectURI string) op.Option {
	return op.WithStaticClients(op.PublicClient{
		ID:           reloadSeedClientID,
		RedirectURIs: []string{redirectURI},
		Scopes:       []string{"openid"},
	})
}

const (
	reloadSeedRedirect        = "https://rp.example.com/cb"
	reloadConflictingRedirect = "https://rp.example.com/other-cb"
)

// Matrix outcomes.
const (
	reloadWantIncompatible = "incompatible"
	reloadWantBuildError   = "build_error"
	reloadWantSwapped      = "swapped"
)

// fetch GETs path through h and returns the 200 body.
func fetch(h http.Handler, path string) ([]byte, error) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody))
	if rec.Code != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", path, rec.Code)
	}
	return rec.Body.Bytes(), nil
}

// servedKids follows discovery to the JWKS and returns the kids it lists.
func servedKids(h http.Handler) ([]string, error) {
	body, err := fetch(h, "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode discovery: %w", err)
	}
	u, err := url.Parse(doc.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("parse jwks_uri %q: %w", doc.JWKSURI, err)
	}
	body, err = fetch(h, u.Path)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	kids := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	return kids, nil
}

// assertActiveKid checks that the JWKS h serves lists want first, as the
// active signing key.
func assertActiveKid(t *testing.T, h http.Handler, want string) {
	t.Helper()
	kids, err := servedKids(h)
	if err != nil {
		t.Fatalf("servedKids: %v", err)
	}
	if len(kids) == 0 || kids[0] != want {
		t.Fatalf("JWKS kids = %v, want %s first", kids, want)
	}
}

// metricsRegistered reports whether reg holds the collector for issuer.
func metricsRegistered(t *testing.T, reg *prometheus.Registry, issuer string) bool {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, fam := range families {
		if fam.GetName() != reloadProbeMetric {
			continue
		}
		for _, m := range fam.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "issuer" && lp.GetValue() == issuer {
					return true
				}
			}
		}
	}
	return false
}

// TestReloadable_Matrix covers issuer x routes x build x prometheus. A
// failing build is only meaningful with the issuer and routes unchanged.
func TestReloadable_Matrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		issuerChanged bool
		routesChanged bool
		buildFails    bool
		prometheus    bool
		want          string
	}{
		{"issuer changed", true, false, false, false, reloadWantIncompatible},
		{"routes changed", false, true, false, false, reloadWantIncompatible},
		{"issuer and routes changed", true, true, false, false, reloadWantIncompatible},
		{"issuer and routes changed same registry", true, true, false, true, reloadWantIncompatible},
		{"routes changed same registry", false, true, false, true, reloadWantIncompatible},
		{"build fails same registry", false, false, true, true, reloadWantBuildError},
		{"build fails", false, false, true, false, reloadWantBuildError},
		{"compatible", false, false, false, false, reloadWantSwapped},
		{"compatible same registry", false, false, false, true, reloadWantSwapped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newReloadFixture(t, tc.prometheus)
			r, err := op.NewReloadable(f.opts(t, validIssuer, "kid-old", reloadSeed(reloadSeedRedirect))...)
			if err != nil {
				t.Fatalf("NewReloadable: %v", err)
			}
			old := r.Provider()

			issuer := validIssuer
			if tc.issuerChanged {
				issuer = reloadOtherIssuer
			}
			seed := reloadSeed(reloadSeedRedirect)
			if tc.buildFails {
				seed = reloadSeed(reloadConflictingRedirect)
			}
			extra := []op.Option{seed}
			if tc.routesChanged {
				extra = append(extra, op.WithFeature(feature.Introspect))
			}

			err = r.Reload(context.Background(), f.opts(t, issuer, "kid-new", extra...)...)

			switch tc.want {
			case reloadWantIncompatible:
				if !errors.Is(err, op.ErrReloadIncompatible) {
					t.Fatalf("Reload = %v, want ErrReloadIncompatible", err)
				}
			case reloadWantBuildError:
				if err == nil || errors.Is(err, op.ErrReloadIncompatible) {
					t.Fatalf("Reload = %v, want the build error", err)
				}
				if !errors.Is(err, store.ErrConflict) {
					t.Fatalf("Reload = %v, want the static-client conflict that failed the build", err)
				}
			case reloadWantSwapped:
				if err != nil {
					t.Fatalf("Reload: %v", err)
				}
			}

			if tc.want == reloadWantSwapped {
				if r.Provider() == old {
					t.Fatal("Reload succeeded but the old Provider is still current")
				}
				assertActiveKid(t, r, "kid-new")
			} else {
				if r.Provider() != old {
					t.Fatal("a rejected Reload replaced the current Provider")
				}
				assertActiveKid(t, r, "kid-old")
			}
			if f.reg != nil {
				if !metricsRegistered(t, f.reg, validIssuer) {
					t.Fatal("the current Provider's metrics are not registered after Reload")
				}
				if metricsRegistered(t, f.reg, reloadOtherIssuer) {
					t.Fatal("a rejected issuer left metrics on the registry")
				}
			}
		})
	}
}

// TestReloadable_FailThenSucceedSameRegistry pins that a failed reload
// leaves the collector re-registrable, so later reloads keep working.
func TestReloadable_FailThenSucceedSameRegistry(t *testing.T) {
	t.Parallel()

	f := newReloadFixture(t, true)
	r, err := op.NewReloadable(f.opts(t, validIssuer, "kid-1", reloadSeed(reloadSeedRedirect))...)
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}

	if err := r.Reload(context.Background(),
		f.opts(t, validIssuer, "kid-fail", reloadSeed(reloadConflictingRedirect))...); err == nil {
		t.Fatal("Reload with a conflicting static client succeeded")
	}
	assertActiveKid(t, r, "kid-1")
	if !metricsRegistered(t, f.reg, validIssuer) {
		t.Fatal("metrics missing after the failed Reload")
	}

	for _, kid := range []string{"kid-2", "kid-3"} {
		if err := r.Reload(context.Background(), f.opts(t, validIssuer, kid, reloadSeed(reloadSeedRedirect))...); err != nil {
			t.Fatalf("Reload to %s: %v", kid, err)
		}
		assertActiveKid(t, r, kid)
		if !metricsRegistered(t, f.reg, validIssuer) {
			t.Fatalf("metrics missing after the Reload to %s", kid)
		}
	}
}

// TestReloadable_ConcurrentServeAndReload drives discovery and JWKS
// through the Reloadable while it reloads; it is meant to run under -race.
func TestReloadable_ConcurrentServeAndReload(t *testing.T) {
	t.Parallel()

	f := newReloadFixture(t, true)
	r, err := op.NewReloadable(f.opts(t, validIssuer, "kid-0")...)
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				kids, err := servedKids(r)
				if err != nil {
					t.Errorf("serving during reload: %v", err)
					return
				}
				if len(kids) == 0 {
					t.Error("JWKS served no keys")
					return
				}
				_ = r.Routes()
			}
		}()
	}

	for i := 1; i <= 5; i++ {
		kid := fmt.Sprintf("kid-%d", i)
		if err := r.Reload(context.Background(), f.opts(t, validIssuer, kid)...); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Reload to %s: %v", kid, err)
		}
	}
	close(stop)
	wg.Wait()
	assertActiveKid(t, r, "kid-5")
}

// TestReloadable_DrainsOldProvider pins that Reload does not return while
// the outgoing Provider still has a back-channel logout delivery in flight.
func TestReloadable_DrainsOldProvider(t *testing.T) {
	t.Parallel()

	const (
		subject  = "reload-user"
		clientID = "reload-bcl-rp"
		bound    = 10 * time.Second
	)

	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-req.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Cleanups run last-in first-out: the handler is released before Close waits on it.
	t.Cleanup(rp.Close)
	t.Cleanup(releaseOnce)

	f := newReloadFixture(t, false)
	extra := []op.Option{
		op.WithAllowInsecureBackchannelLogoutForDev(),
		op.WithBackchannelLogoutTimeout(30 * time.Second),
		op.WithBackchannelFanOutBudget(30 * time.Second),
		op.WithStaticClients(op.PublicClient{
			ID:                   clientID,
			RedirectURIs:         []string{reloadSeedRedirect},
			Scopes:               []string{"openid"},
			BackchannelLogoutURI: rp.URL + "/backchannel-logout",
		}),
	}
	r, err := op.NewReloadable(f.opts(t, devIssuer, "kid-old", extra...)...)
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	old := r.Provider()

	if err := f.st.Grants().Save(context.Background(), &store.Grant{
		ID:        "reload-grant",
		Subject:   subject,
		ClientID:  clientID,
		Scope:     []string{"openid"},
		CreatedAt: reloadNow(),
		UpdatedAt: reloadNow(),
	}); err != nil {
		t.Fatalf("save grant: %v", err)
	}
	if !op.NotifyBackchannelLogoutForTest(old, subject) {
		t.Fatal("the Provider has no back-channel coordinator")
	}
	select {
	case <-arrived:
	case <-time.After(bound):
		t.Fatal("the back-channel delivery never reached the relying party")
	}

	next := f.opts(t, devIssuer, "kid-new", extra...)
	done := make(chan error, 1)
	go func() {
		done <- r.Reload(context.Background(), next...)
	}()

	// The swap precedes the drain, so Reload is now blocked on the delivery.
	timeout := time.After(bound)
	for r.Provider() == old {
		select {
		case err := <-done:
			t.Fatalf("Reload returned (%v) before swapping in the new Provider", err)
		case <-timeout:
			t.Fatal("Reload never swapped in the new Provider")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-done:
		t.Fatalf("Reload returned (%v) while the old Provider's delivery was in flight", err)
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Reload: %v", err)
		}
	case <-time.After(bound):
		t.Fatal("Reload did not return after the delivery finished")
	}
	if r.Provider() == old {
		t.Fatal("the old Provider is current after Reload")
	}
	assertActiveKid(t, r, "kid-new")
}

// TestReloadable_IssuerChangeHasNoSideEffect pins that an issuer change is
// refused before the registry or the store is touched.
func TestReloadable_IssuerChangeHasNoSideEffect(t *testing.T) {
	t.Parallel()

	const newClientID = "reload-new-rp"

	f := newReloadFixture(t, true)
	r, err := op.NewReloadable(f.opts(t, validIssuer, "kid-old")...)
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}

	err = r.Reload(context.Background(), f.opts(t, reloadOtherIssuer, "kid-new",
		op.WithStaticClients(op.PublicClient{
			ID:           newClientID,
			RedirectURIs: []string{reloadSeedRedirect},
			Scopes:       []string{"openid"},
		}),
	)...)
	if !errors.Is(err, op.ErrReloadIncompatible) {
		t.Fatalf("Reload = %v, want ErrReloadIncompatible", err)
	}

	if !metricsRegistered(t, f.reg, validIssuer) {
		t.Fatal("the current Provider's metrics were unregistered by a refused Reload")
	}
	if metricsRegistered(t, f.reg, reloadOtherIssuer) {
		t.Fatal("the refused issuer was registered")
	}
	if _, err := f.st.Clients().GetClient(context.Background(), newClientID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetClient(%s) = %v, want ErrNotFound: a refused Reload wrote a static client", newClientID, err)
	}
	assertActiveKid(t, r, "kid-old")
}

const (
	algSwitchClientID = "alg-switch-rp"
	algSwitchSecret   = "alg-switch-secret" //nolint:gosec // opaque test fixture secret, not a credential.
	algSwitchRedirect = "https://rp.testkit.invalid/callback"
	algSwitchSubject  = "alg-switch-user"
)

// TestReload_SigningAlgorithmSwitch pins that an OP moves from ES256 to
// RS256 without invalidating what it already issued, as long as the old
// key stays behind the new active one with a NotAfter; a switch that drops
// the old key is refused.
func TestReload_SigningAlgorithmSwitch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := inmem.New()
	st.PutUser(ctx, &store.User{Subject: algSwitchSubject})
	hash, err := op.HashClientSecret(algSwitchSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	if err := st.RegisterClient(ctx, &store.Client{
		ID:                      algSwitchClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{algSwitchRedirect},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	cookieKey := newRandomCookieKey(t)
	ecKey := newTestKey(t, "ec-old")
	rsaKey := newRSATestKey(t, "rsa-new", 2048)
	opts := func(extra ...op.Option) []op.Option {
		return testkit.MinimalOptions(t, append([]op.Option{
			op.WithStore(st),
			op.WithCookieKeys(cookieKey),
			op.WithAccessTokenFormat(store.AccessTokenFormatJWT),
		}, extra...)...)
	}

	r, err := op.NewReloadable(opts(op.WithKeyset(op.Keyset{ecKey}))...)
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	srv := httptest.NewTLSServer(r)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	browser := algSwitchClient(srv, jar)
	oldAT, oldIDT := algSwitchFlow(t, srv.URL, browser)
	for name, tok := range map[string]string{"access token": oldAT, "ID token": oldIDT} {
		if alg, kid := jwsHeader(t, tok); alg != "ES256" || kid != "ec-old" {
			t.Fatalf("%s before the switch: alg=%s kid=%s, want ES256 ec-old", name, alg, kid)
		}
	}

	// Dropping the ES256 key would strand every token it signed.
	before := r.Provider()
	err = r.Reload(ctx, opts(op.WithKeyset(op.Keyset{rsaKey}), op.WithSigningAlgorithm(op.AlgRS256))...)
	if !errors.Is(err, op.ErrReloadIncompatible) {
		t.Fatalf("Reload without the old key = %v, want ErrReloadIncompatible", err)
	}
	if r.Provider() != before {
		t.Fatal("a refused Reload replaced the current Provider")
	}

	if err := r.Reload(ctx, opts(
		op.WithKeyset(op.Keyset{rsaKey, retiring(ecKey)}),
		op.WithSigningAlgorithm(op.AlgRS256),
	)...); err != nil {
		t.Fatalf("Reload to RS256: %v", err)
	}

	if status := bearerGet(t, browser, srv.URL+"/oidc/userinfo", oldAT); status != http.StatusOK {
		t.Fatalf("/userinfo with the ES256 access token after the switch: status %d, want 200", status)
	}
	resp := ssfBrowserGet(t, browser, srv.URL+"/oidc/end_session?"+url.Values{"id_token_hint": {oldIDT}}.Encode())
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("/end_session with the ES256 id_token_hint after the switch: status %d", resp.StatusCode)
	}

	freshJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	newAT, newIDT := algSwitchFlow(t, srv.URL, algSwitchClient(srv, freshJar))
	for name, tok := range map[string]string{"access token": newAT, "ID token": newIDT} {
		if alg, kid := jwsHeader(t, tok); alg != "RS256" || kid != "rsa-new" {
			t.Fatalf("%s after the switch: alg=%s kid=%s, want RS256 rsa-new", name, alg, kid)
		}
	}
}

// algSwitchClient returns a client that trusts srv and does not follow
// redirects, so each hop of the code flow can be inspected.
func algSwitchClient(srv *httptest.Server, jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport:     srv.Client().Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// algSwitchFlow runs an authorization code flow for algSwitchSubject and
// returns the access token and ID token it yields.
func algSwitchFlow(t *testing.T, base string, browser *http.Client) (accessToken, idToken string) {
	t.Helper()
	verifier := "alg-switch-pkce-verifier-0123456789-abcdefghijklmn"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {algSwitchClientID},
		"redirect_uri":          {algSwitchRedirect},
		"scope":                 {"openid profile"},
		"state":                 {"alg-switch-state"},
		"nonce":                 {"alg-switch-nonce"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	resp := ssfBrowserGet(t, browser, base+"/oidc/auth?"+q.Encode())
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize status=%d location=%v", resp.StatusCode, loc)
	}
	interactionURL := base + loc.Path

	prompt := ssfBrowserGet(t, browser, interactionURL)
	var step map[string]any
	if err := json.NewDecoder(prompt.Body).Decode(&step); err != nil {
		t.Fatalf("decode interaction prompt: %v", err)
	}
	_ = prompt.Body.Close()
	csrf := ssfCookie(prompt.Cookies(), "__Host-oidc_csrf")
	stateRef, _ := step["state_ref"].(string)
	if csrf == nil || stateRef == "" {
		t.Fatalf("interaction prompt lacks state_ref or CSRF cookie: %v", step)
	}
	raw, _ := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{testkit.SubjectFieldName: algSwitchSubject},
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testkit.DefaultIssuer)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(csrf)
	final, err := browser.Do(req)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	if rotated := ssfCookie(final.Cookies(), "__Host-oidc_csrf"); rotated != nil {
		csrf = rotated
	}
	if consent, env, err := testkit.IsConsentPrompt(final); err != nil {
		t.Fatalf("inspect consent: %v", err)
	} else if consent {
		ref, _ := env["state_ref"].(string)
		final = testkit.PostConsentApproval(t, browser, interactionURL, testkit.DefaultIssuer, csrf.Value, ref,
			testkit.ApprovedScopesFrom(t, env))
	}
	_ = final.Body.Close()
	cb, err := final.Location()
	if final.StatusCode != http.StatusFound || err != nil || cb.Query().Get("code") == "" {
		t.Fatalf("interaction did not redirect with a code: status=%d location=%v", final.StatusCode, cb)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.Query().Get("code")},
		"redirect_uri":  {algSwitchRedirect},
		"code_verifier": {verifier},
	}
	tokReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/oidc/token",
		strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(algSwitchClientID, algSwitchSecret)
	tokResp, err := browser.Do(tokReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = tokResp.Body.Close() }()
	var body struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /token: %v", err)
	}
	if tokResp.StatusCode != http.StatusOK || body.AccessToken == "" || body.IDToken == "" {
		t.Fatalf("code exchange: status=%d body=%+v", tokResp.StatusCode, body)
	}
	return body.AccessToken, body.IDToken
}

// bearerGet sends a GET carrying token as a bearer credential and returns
// the status.
func bearerGet(t *testing.T, client *http.Client, target, token string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// jwsHeader returns the alg and kid of a compact JWS.
func jwsHeader(t *testing.T, token string) (alg, kid string) {
	t.Helper()
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("not a compact JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		t.Fatalf("decode JWS header: %v", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("parse JWS header: %v", err)
	}
	return h.Alg, h.Kid
}
