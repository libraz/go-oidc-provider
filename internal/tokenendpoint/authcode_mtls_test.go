package tokenendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// mtlsFixture builds a token-endpoint fixture with the MTLS feature
// enabled. The shape mirrors [dpopFixture]: testkit infrastructure
// plus the request-scoped helpers tests use to drive the handler.
func mtlsFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.MTLS)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// generateMTLSLeaf produces a self-signed leaf certificate suitable for
// driving the mTLS handler tests. The cert is deterministic in
// validity bounds (no time.Now()) but uses fresh key material per call
// so distinct tests cannot accidentally bind to the same thumbprint.
func generateMTLSLeaf(tb testing.TB) *x509.Certificate {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.testkit.invalid"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// postWithMTLS issues a token-endpoint POST whose request carries a
// fabricated TLS handshake state. The provider mux serves the request
// directly through ServeHTTP, bypassing the testkit's plain-HTTP
// httptest.Server: that lets the test exercise the full handler with
// TLS metadata that an httptest.Server cannot supply.
func postWithMTLS(
	tb testing.TB,
	prov *testkit.Provider,
	form url.Values,
	basicID, basicSecret string,
	cert *x509.Certificate,
) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://op.testkit.invalid/oidc/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(basicID, basicSecret)
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	rec := httptest.NewRecorder()
	prov.OP.ServeHTTP(rec, req)
	return rec.Result()
}

// decodeMTLSResp drains and JSON-decodes resp.
func decodeMTLSResp(tb testing.TB, resp *http.Response) map[string]any {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("ReadAll: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("Unmarshal(%s): %v", raw, err)
	}
	return out
}

// TestAuthCode_MTLS_BindsX5T drives an authorization_code exchange
// with a client cert and verifies the issued access token carries
// cnf.x5t#S256 and the persisted refresh token records the same
// thumbprint.
func TestAuthCode_MTLS_BindsX5T(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-mtls"
	const grantID = "grant-mtls"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email", "offline_access"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-mtls",
	})

	cert := generateMTLSLeaf(t)
	resp := postWithMTLS(t, f.prov, authCodeForm(codeID, redirect, verifier), client.ID, secret, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeMTLSResp(t, resp))
	}
	body := decodeMTLSResp(t, resp)
	if got := body["token_type"]; got != "Bearer" {
		// RFC 8705 keeps the bearer token_type; the binding is on cnf.
		t.Errorf("token_type=%v want Bearer (mTLS keeps the bearer wire type)", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing")
	}

	// The access token MUST carry cnf.x5t#S256.
	keySet := mustKeySet(t, f.prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: f.prov.Issuer, Clock: f.clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	want := mtls.Thumbprint(cert)
	if got := parsed.Confirmation["x5t#S256"]; got != want {
		t.Errorf("cnf.x5t#S256=%q want %q", got, want)
	}
	if _, hasJKT := parsed.Confirmation["jkt"]; hasJKT {
		t.Errorf("cnf.jkt must not be present on an mTLS-bound token")
	}

	// The persisted refresh-token record MUST carry the same thumbprint.
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rt)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.MTLSCertThumbprint != want {
		t.Errorf("refresh MTLSCertThumbprint=%q want %q", rec.MTLSCertThumbprint, want)
	}
	if rec.DPoPJKT != "" {
		t.Errorf("refresh DPoPJKT must be empty on mTLS-bound chain, got %q", rec.DPoPJKT)
	}
}

// TestAuthCode_MTLS_NoCertBearer mints a bearer token when the
// request omits any client cert, even with the feature enabled.
// RFC 8705 §3 binds opportunistically: an absent cert is the bearer
// path, not an error.
func TestAuthCode_MTLS_NoCertBearer(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-bearer-with-mtls-feature"
	const grantID = "grant-bearer-mtls"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-bearer-mtls",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}
	at, _ := body["access_token"].(string)
	keySet := mustKeySet(t, f.prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: f.prov.Issuer, Clock: f.clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if len(parsed.Confirmation) != 0 {
		t.Errorf("cnf must be absent on bearer token: %v", parsed.Confirmation)
	}
}

// TestAuthCode_MTLS_DPoPWinsOverMTLS checks the documented preference:
// when both a DPoP proof AND a client cert are presented, the access
// token carries cnf.jkt (DPoP) and NOT cnf.x5t#S256.
func TestAuthCode_MTLS_DPoPWinsOverMTLS(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.DPoP), op.WithFeature(feature.MTLS)),
	)
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-dpop-wins"
	const grantID = "grant-dpop-wins"
	redirect := client.RedirectURIs[0]
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-both",
	})

	cert := generateMTLSLeaf(t)
	dpopKey := newDPoPKey(t)
	tokenURL := "https://op.testkit.invalid/oidc/token" //nolint:gosec // not a credential — endpoint URL.
	form := authCodeForm(codeID, redirect, verifier)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		tokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, secret)
	req.Header.Set("DPoP", makeDPoPProof(t, dpopKey, "POST", tokenURL, clock.now, "jti-both", ""))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	rec := httptest.NewRecorder()
	prov.OP.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeMTLSResp(t, resp))
	}
	body := decodeMTLSResp(t, resp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP (DPoP wins over mTLS)", got)
	}
	at, _ := body["access_token"].(string)
	keySet := mustKeySet(t, prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: prov.Issuer, Clock: clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := parsed.Confirmation["jkt"]; got != dpopKey.jkt {
		t.Errorf("cnf.jkt=%q want %q", got, dpopKey.jkt)
	}
	if _, ok := parsed.Confirmation["x5t#S256"]; ok {
		t.Errorf("cnf.x5t#S256 must NOT be present when DPoP wins")
	}
}
