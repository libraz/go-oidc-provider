package dpop_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// dpopProofKey pairs a fresh ECDSA P-256 signer with its public-key
// thumbprint. The structure shadows the proof_test.go signKey type so
// the E2E test does not need to reach the internal helper but still
// shares the same wire shape.
type dpopProofKey struct {
	priv crypto.Signer
	jkt  string
}

func newProofKey(t testing.TB) dpopProofKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jkt, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return dpopProofKey{priv: priv, jkt: jkt}
}

func makeProof(t testing.TB, key dpopProofKey, method, htu string, now time.Time, jti, ath string) string {
	t.Helper()
	pub := key.priv.Public()
	jwk := josev4.JSONWebKey{Key: pub}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: key.priv},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := map[string]any{
		"jti": jti,
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
	}
	if ath != "" {
		claims["ath"] = ath
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

// decodeJSONResp reads and JSON-decodes the body of resp.
func decodeJSONResp(t testing.TB, resp *http.Response) map[string]any {
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

// pkcePair returns a deterministic PKCE verifier / S256 challenge pair
// the E2E flow can thread through /authorize and /token. The challenge
// is computed inline (rather than via [internal/pkce]) so this _test
// package does not need to grow another internal-namespace import.
func pkcePair(_ testing.TB) (verifier, challenge string) {
	verifier = "test-verifier-test-verifier-test-verifier-test-verifier-1234567"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// runAuthorize drives /authorize → /interaction (auto-consent) and
// returns the issued authorization code.
func runAuthorize(t testing.TB, tk *testkit.Provider, clientID, redirectURI, challenge, state, nonce string, clock fixedClock) string {
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

	// GET /interaction/{uid} to retrieve CSRF token.
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
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("/interaction GET status=%d", getResp.StatusCode)
	}
	step := decodeJSONResp(t, getResp)
	csrfToken, _ := step["csrf"].(string)
	if csrfToken == "" {
		t.Fatal("csrf token missing")
	}

	body, err := json.Marshal(map[string]any{
		"subject_hint":   "user-dpop",
		"granted_scopes": []string{"openid", "email"},
		"auth_time":      clock.now.UTC().Format(time.RFC3339),
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

// TestE2E_DPoP_FullFlow drives /authorize → /token (with DPoP) →
// /userinfo (with DPoP) and the refresh path. It is the ground-truth
// regression suite for sender-constrained tokens against the
// public op/ surface.
func TestE2E_DPoP_FullFlow(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.DPoP)),
	)
	const secret = "rp-dpop-secret" //nolint:gosec // not a credential — opaque test fixture secret.
	hasher := authn.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-dpop",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: "user-dpop",
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})

	verifier, challenge := pkcePair(t)
	code := runAuthorize(t, tk, rp.ID, rp.RedirectURIs[0], challenge, "state-1", "nonce-1", clock)

	// Exchange code for tokens with a DPoP proof.
	key := newProofKey(t)
	tokenURL := tk.Server.URL + "/oidc/token"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {verifier},
	}
	tokReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(rp.ID, secret)
	tokReq.Header.Set("DPoP", makeProof(t, key, "POST", tokenURL, clock.now, "jti-token-1", ""))
	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		t.Fatalf("Do /token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("/token status=%d body=%s", tokResp.StatusCode, dump)
	}
	body := decodeJSONResp(t, tokResp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("missing tokens: at=%q rt=%q", at, rt)
	}

	// Hit /userinfo with a matching proof.
	userinfoURL := tk.Server.URL + "/oidc/userinfo"
	uinfoReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, userinfoURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /userinfo: %v", err)
	}
	uinfoReq.Header.Set("Authorization", "Bearer "+at)
	uinfoReq.Header.Set("DPoP", makeProof(t, key, "GET", userinfoURL, clock.now, "jti-uinfo-1", dpop.AccessTokenHash(at)))
	uinfoResp, err := http.DefaultClient.Do(uinfoReq)
	if err != nil {
		t.Fatalf("Do /userinfo: %v", err)
	}
	defer uinfoResp.Body.Close()
	if uinfoResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(uinfoResp.Body)
		t.Fatalf("/userinfo status=%d body=%s", uinfoResp.StatusCode, dump)
	}

	// Hit /userinfo without DPoP — must fail.
	plainReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, userinfoURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /userinfo plain: %v", err)
	}
	plainReq.Header.Set("Authorization", "Bearer "+at)
	plainResp, err := http.DefaultClient.Do(plainReq)
	if err != nil {
		t.Fatalf("Do /userinfo plain: %v", err)
	}
	defer plainResp.Body.Close()
	if plainResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/userinfo plain status=%d want 401", plainResp.StatusCode)
	}

	// Hit /userinfo with a proof signed by a different key — must fail.
	other := newProofKey(t)
	otherReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, userinfoURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /userinfo other: %v", err)
	}
	otherReq.Header.Set("Authorization", "Bearer "+at)
	otherReq.Header.Set("DPoP", makeProof(t, other, "GET", userinfoURL, clock.now, "jti-uinfo-other", dpop.AccessTokenHash(at)))
	otherResp, err := http.DefaultClient.Do(otherReq)
	if err != nil {
		t.Fatalf("Do /userinfo other: %v", err)
	}
	defer otherResp.Body.Close()
	if otherResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/userinfo other-key status=%d want 401", otherResp.StatusCode)
	}

	// Refresh with a matching proof — success, new chain bound to the
	// same jkt.
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
	}
	refReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tokenURL, strings.NewReader(refreshForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest refresh: %v", err)
	}
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refReq.SetBasicAuth(rp.ID, secret)
	refReq.Header.Set("DPoP", makeProof(t, key, "POST", tokenURL, clock.now, "jti-refresh-1", ""))
	refResp, err := http.DefaultClient.Do(refReq)
	if err != nil {
		t.Fatalf("Do refresh: %v", err)
	}
	defer refResp.Body.Close()
	if refResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(refResp.Body)
		t.Fatalf("refresh status=%d body=%s", refResp.StatusCode, dump)
	}
	refBody := decodeJSONResp(t, refResp)
	if got := refBody["token_type"]; got != "DPoP" {
		t.Errorf("refresh token_type=%v want DPoP", got)
	}

	// Refresh with a mismatching proof — must fail. We need a fresh
	// rotated refresh token because the previous request consumed it,
	// but we'll use the freshly issued one paired with a different
	// signing key.
	rotated, _ := refBody["refresh_token"].(string)
	if rotated == "" {
		t.Fatal("refresh did not return a rotated token")
	}
	misForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotated},
	}
	misReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tokenURL, strings.NewReader(misForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest mismatch refresh: %v", err)
	}
	misReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	misReq.SetBasicAuth(rp.ID, secret)
	misReq.Header.Set("DPoP", makeProof(t, other, "POST", tokenURL, clock.now, "jti-refresh-other", ""))
	misResp, err := http.DefaultClient.Do(misReq)
	if err != nil {
		t.Fatalf("Do mismatch refresh: %v", err)
	}
	defer misResp.Body.Close()
	if misResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatch refresh status=%d want 400", misResp.StatusCode)
	}
}
