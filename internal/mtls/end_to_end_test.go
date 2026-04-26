package mtls_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fixedClock is the small Clock the e2e test injects so the OP and
// the test share a wall-clock reading.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// runAuthorizeForMTLS drives /authorize → /interaction (auto-consent)
// over the testkit's plain-HTTP server and returns the issued
// authorization code. The function mirrors the DPoP end-to-end helper
// but is duplicated here because the _test packages do not share.
func runAuthorizeForMTLS(t testing.TB, tk *testkit.Provider, clientID, redirectURI, challenge, state, nonce string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	q := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+q.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("Do /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("/authorize status=%d body=%s", authResp.StatusCode, dump)
	}
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s want interaction redirect", loc.String())
	}

	// Fetch the CSRF token from the interaction step.
	getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+loc.Path, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /interaction: %v", err)
	}
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Do /interaction GET: %v", err)
	}
	defer getResp.Body.Close()
	step := decodeBodyMTLS(t, getResp)
	csrfToken, _ := step["csrf"].(string)
	if csrfToken == "" {
		t.Fatal("csrf token missing")
	}

	body, err := json.Marshal(map[string]any{
		"subject_hint":   "user-mtls",
		"granted_scopes": []string{"openid", "email"},
		"auth_time":      time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"amr":            []string{"pwd"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+loc.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest /interaction POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfToken)
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("Do /interaction POST: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(postResp.Body)
		t.Fatalf("/interaction POST status=%d body=%s", postResp.StatusCode, dump)
	}
	rpRedirect, err := postResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}
	return code
}

// decodeBodyMTLS parses an HTTP response body as a JSON object.
func decodeBodyMTLS(t testing.TB, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal(%s): %v", raw, err)
	}
	return out
}

// servePostWithCert is the package-local helper that dispatches a
// POST request through the [op.Provider] handler with a fabricated
// TLS handshake state. The testkit's [httptest.Server] is plain
// HTTP, so end-to-end tests reach into [op.Provider.ServeHTTP]
// directly when they need to thread a client cert through.
func servePostWithCert(
	t testing.TB,
	prov *testkit.Provider,
	method, urlStr string,
	form url.Values,
	cert *x509.Certificate,
	mutate func(*http.Request),
) *http.Response {
	t.Helper()
	var body io.Reader = http.NoBody
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, urlStr, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	prov.OP.ServeHTTP(rec, req)
	return rec.Result()
}

// TestE2E_MTLS_FullFlow drives /authorize → /token (with cert) →
// /userinfo (with cert) and the refresh path. It is the ground-truth
// regression suite for certificate-bound tokens against the public
// op/ surface.
func TestE2E_MTLS_FullFlow(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.MTLS)),
	)
	const secret = "rp-mtls-secret" //nolint:gosec // not a credential — opaque test fixture secret.
	hasher := authn.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-mtls",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: "user-mtls",
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})

	verifier, challenge := pkceForMTLS()
	code := runAuthorizeForMTLS(t, tk, rp.ID, rp.RedirectURIs[0], challenge, "state-1", "nonce-1")

	clientCert := generateLeaf(t)
	otherCert := generateLeaf(t)
	tokenURL := "https://op.testkit.invalid/oidc/token" //nolint:gosec // not a credential — endpoint URL.
	userinfoURL := "https://op.testkit.invalid/oidc/userinfo"

	// Exchange code for tokens with a client cert.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {verifier},
	}
	tokResp := servePostWithCert(t, tk, http.MethodPost, tokenURL, form, clientCert, func(r *http.Request) {
		r.SetBasicAuth(rp.ID, secret)
	})
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("/token status=%d body=%s", tokResp.StatusCode, dump)
	}
	body := decodeBodyMTLS(t, tokResp)
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("missing tokens: at=%q rt=%q", at, rt)
	}

	// Hit /userinfo with the matching cert: success.
	uinfoResp := servePostWithCert(t, tk, http.MethodGet, userinfoURL, nil, clientCert, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+at)
	})
	defer uinfoResp.Body.Close()
	if uinfoResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(uinfoResp.Body)
		t.Fatalf("/userinfo status=%d body=%s", uinfoResp.StatusCode, dump)
	}

	// Hit /userinfo without any cert: must fail.
	noCertResp := servePostWithCert(t, tk, http.MethodGet, userinfoURL, nil, nil, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+at)
	})
	defer noCertResp.Body.Close()
	if noCertResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/userinfo no-cert status=%d want 401", noCertResp.StatusCode)
	}

	// Hit /userinfo with a different cert: must fail.
	otherResp := servePostWithCert(t, tk, http.MethodGet, userinfoURL, nil, otherCert, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+at)
	})
	defer otherResp.Body.Close()
	if otherResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/userinfo other-cert status=%d want 401", otherResp.StatusCode)
	}

	// Refresh with the same cert: success, new tokens bound to the
	// same thumbprint.
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
	}
	refResp := servePostWithCert(t, tk, http.MethodPost, tokenURL, refForm, clientCert, func(r *http.Request) {
		r.SetBasicAuth(rp.ID, secret)
	})
	defer refResp.Body.Close()
	if refResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(refResp.Body)
		t.Fatalf("refresh status=%d body=%s", refResp.StatusCode, dump)
	}
	refBody := decodeBodyMTLS(t, refResp)
	rotated, _ := refBody["refresh_token"].(string)
	if rotated == "" || rotated == rt {
		t.Fatalf("refresh did not rotate; got %q (was %q)", rotated, rt)
	}
	rec, err := tk.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("rotated Find: %v", err)
	}
	if rec.MTLSCertThumbprint != mtls.Thumbprint(clientCert) {
		t.Errorf("rotated MTLSCertThumbprint mismatch")
	}

	// Refresh with a different cert: must fail.
	misForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotated},
	}
	misResp := servePostWithCert(t, tk, http.MethodPost, tokenURL, misForm, otherCert, func(r *http.Request) {
		r.SetBasicAuth(rp.ID, secret)
	})
	defer misResp.Body.Close()
	if misResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatch refresh status=%d want 400", misResp.StatusCode)
	}
}

// pkceForMTLS returns a deterministic PKCE pair the e2e flow can
// thread through /authorize and /token. The pair shadows the helper
// in [internal/dpop] so this _test package does not need to import
// the internal pkce machinery.
func pkceForMTLS() (verifier, challenge string) {
	verifier = "test-verifier-test-verifier-test-verifier-test-verifier-1234567"
	// SHA-256("test-verifier-test-verifier-test-verifier-test-verifier-1234567")
	// base64url-no-pad of the digest. Hard-coded here because the
	// helper is private to internal/pkce and reproducing it
	// inline would just restate the trivial transformation.
	return verifier, pkceChallenge(verifier)
}

// pkceChallenge is the SHA-256 base64url-no-pad transformation RFC
// 7636 §4.1 prescribes. Inlined to keep this test file independent
// of [internal/pkce].
func pkceChallenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
