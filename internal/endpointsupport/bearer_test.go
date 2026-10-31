package endpointsupport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestBearerFromHeader pins every recognised / rejected shape so a
// regression that introduces a third scheme or breaks case-insensitive
// matching is caught here rather than in an endpoint integration test.
func TestBearerFromHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{"empty", "", "", false},
		{"bearer simple", "Bearer abc", "abc", true},
		{"bearer trim", "Bearer   abc  ", "abc", true},
		{"bearer lowercase", "bearer abc", "abc", true},
		{"dpop simple", "DPoP abc", "abc", true},
		{"dpop mixed case", "dPoP abc", "abc", true},
		{"unknown scheme", "Basic abc", "", false},
		{"bearer no token", "Bearer ", "", false},
		{"only scheme", "Bearer", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tok, ok := endpointsupport.BearerFromHeader(tc.header)
			if tok != tc.wantToken || ok != tc.wantOK {
				t.Fatalf("BearerFromHeader(%q): (%q,%v), want (%q,%v)", tc.header, tok, ok, tc.wantToken, tc.wantOK)
			}
		})
	}
}

// TestIsFormContent / TestIsJSONContent pin the content-type matchers.
func TestIsFormContent(t *testing.T) {
	t.Parallel()
	if !endpointsupport.IsFormContent("application/x-www-form-urlencoded") {
		t.Fatalf("plain form rejected")
	}
	if !endpointsupport.IsFormContent("application/x-www-form-urlencoded; charset=UTF-8") {
		t.Fatalf("parameterised form rejected")
	}
	if endpointsupport.IsFormContent("application/json") {
		t.Fatalf("json accepted as form")
	}
	if endpointsupport.IsFormContent("") {
		t.Fatalf("empty accepted as form")
	}
}

func TestIsJSONContent(t *testing.T) {
	t.Parallel()
	if !endpointsupport.IsJSONContent("application/json") {
		t.Fatalf("plain json rejected")
	}
	if !endpointsupport.IsJSONContent("Application/JSON; charset=UTF-8") {
		t.Fatalf("case+param json rejected")
	}
	if endpointsupport.IsJSONContent("application/x-www-form-urlencoded") {
		t.Fatalf("form accepted as json")
	}
}

// bearerFixture is an OP-shaped dependency set for [endpointsupport.AcceptBearer]:
// one ES256 signing key, an in-memory store, and a pinned clock.
type bearerFixture struct {
	now    time.Time
	signer tokens.SigningKey
	st     *inmem.Store
	deps   endpointsupport.BearerDeps
}

const (
	acceptTestIssuer = "https://op.example"
	acceptTestURL    = "http://op.example/resource"
)

func newBearerFixture(t *testing.T) *bearerFixture {
	t.Helper()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	clock := timex.ClockFunc(func() time.Time { return now })
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{{KeyID: "k1", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	st := inmem.New()
	return &bearerFixture{
		now:    now,
		signer: tokens.SigningKey{KeyID: "k1", Signer: priv},
		st:     st,
		deps: endpointsupport.BearerDeps{
			Keys:               set,
			Issuer:             acceptTestIssuer,
			Clock:              clock,
			OpaqueAccessTokens: st.OpaqueAccessTokens(),
			GrantRevocations:   st.GrantRevocations(),
			RevocationStrategy: store.RevocationStrategyGrantTombstone,
		},
	}
}

func (f *bearerFixture) jwt(t *testing.T, edit func(*tokens.AccessTokenClaims)) string {
	t.Helper()
	c := tokens.AccessTokenClaims{
		Issuer:    acceptTestIssuer,
		Subject:   "user-1",
		Audience:  []string{acceptTestIssuer},
		ClientID:  "client-1",
		GrantID:   "grant-1",
		IssuedAt:  f.now.Add(-time.Minute).Unix(),
		ExpiresAt: f.now.Add(time.Hour).Unix(),
		JTI:       "at-1",
		Scope:     []string{"ssf.read"},
	}
	if edit != nil {
		edit(&c)
	}
	raw, err := tokens.SignAccessToken(f.signer, c)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	return raw
}

func (f *bearerFixture) opaque(t *testing.T, edit func(*store.OpaqueAccessToken)) string {
	t.Helper()
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-1",
		GrantID:   "grant-1",
		ClientID:  "client-1",
		Subject:   "user-1",
		Scope:     []string{"ssf.manage"},
		Audience:  acceptTestIssuer,
		IssuedAt:  f.now.Add(-time.Minute),
		ExpiresAt: f.now.Add(time.Hour),
	}
	if edit != nil {
		edit(rec)
	}
	if err := f.st.OpaqueAccessTokens().Save(context.Background(), rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return rec.ID
}

func bearerRequest(t *testing.T, authorization string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, acceptTestURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

// requireBearerRejection asserts err is a 401 [*endpointsupport.BearerError]
// and returns the WWW-Authenticate value it writes.
func requireBearerRejection(t *testing.T, err error, wantScheme, wantDesc string) string {
	t.Helper()
	var be *endpointsupport.BearerError
	if !errors.As(err, &be) {
		t.Fatalf("err = %v, want *BearerError", err)
	}
	if be.Status != http.StatusUnauthorized || be.Scheme != wantScheme || be.Description != wantDesc {
		t.Fatalf("rejection = {%d %q %q %q}, want {401 %q _ %q}", be.Status, be.Scheme, be.Code, be.Description, wantScheme, wantDesc)
	}
	rec := httptest.NewRecorder()
	be.WriteResponse(rec)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("written status = %d, want 401", rec.Code)
	}
	return rec.Header().Get("WWW-Authenticate")
}

func TestAcceptBearer_MissingOrMalformedHeader(t *testing.T) {
	t.Parallel()
	f := newBearerFixture(t)
	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "Bearer ", "Bearer", "Token abc"} {
		_, err := endpointsupport.AcceptBearer(bearerRequest(t, header), f.deps)
		if got := requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, ""); got != "Bearer" {
			t.Errorf("header %q: WWW-Authenticate = %q, want bare %q", header, got, "Bearer")
		}
	}
}

func TestAcceptBearer_JWT(t *testing.T) {
	t.Parallel()
	f := newBearerFixture(t)

	access, err := endpointsupport.AcceptBearer(bearerRequest(t, "Bearer "+f.jwt(t, nil)), f.deps)
	if err != nil {
		t.Fatalf("AcceptBearer: %v", err)
	}
	c := access.Claims
	if c.Subject != "user-1" || c.ClientID != "client-1" || c.GrantID != "grant-1" ||
		len(c.Scope) != 1 || c.Scope[0] != "ssf.read" || c.ExpiresAt != f.now.Add(time.Hour).Unix() {
		t.Fatalf("claims = %+v", c)
	}

	cases := []struct {
		name string
		raw  string
		desc string
	}{
		{"expired", f.jwt(t, func(c *tokens.AccessTokenClaims) { c.ExpiresAt = f.now.Add(-time.Hour).Unix() }), "The access token expired"},
		{"foreign audience", f.jwt(t, func(c *tokens.AccessTokenClaims) { c.Audience = []string{"https://rs.example"} }), "The access token is invalid"},
		{"wrong issuer", f.jwt(t, func(c *tokens.AccessTokenClaims) { c.Issuer = "https://other.example" }), "The access token is invalid"},
		{"not a token", "a.b.c", "The access token is invalid"},
	}
	for _, tc := range cases {
		_, err := endpointsupport.AcceptBearer(bearerRequest(t, "Bearer "+tc.raw), f.deps)
		got := requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, tc.desc)
		if want := `Bearer error="invalid_token", error_description="` + tc.desc + `"`; got != want {
			t.Errorf("%s: WWW-Authenticate = %q, want %q", tc.name, got, want)
		}
	}
}

func TestAcceptBearer_Opaque(t *testing.T) {
	t.Parallel()
	f := newBearerFixture(t)
	cert := bearerTestCert(t)
	raw := f.opaque(t, func(r *store.OpaqueAccessToken) { r.AuthorizationRecorded = true })

	access, err := endpointsupport.AcceptBearer(bearerRequest(t, "Bearer "+raw), f.deps)
	if err != nil {
		t.Fatalf("AcceptBearer: %v", err)
	}
	c := access.Claims
	if c.Subject != "user-1" || c.ClientID != "client-1" || c.GrantID != "grant-1" ||
		len(c.Audience) != 1 || c.Audience[0] != acceptTestIssuer ||
		c.ExpiresAt != f.now.Add(time.Hour).Unix() || !access.AuthorizationRecorded {
		t.Fatalf("access = %+v claims = %+v", access, c)
	}

	bound := f.opaque(t, func(r *store.OpaqueAccessToken) {
		r.ID = "opaque-bound"
		r.MTLSCertThumbprint = mtls.Thumbprint(cert)
	})
	f.deps.MTLS = newBearerMTLS(t)
	r := bearerRequest(t, "Bearer "+bound)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	access, err = endpointsupport.AcceptBearer(r, f.deps)
	if err != nil {
		t.Fatalf("AcceptBearer bound: %v", err)
	}
	if access.Claims.Confirmation[tokens.CnfX5tS256] != mtls.Thumbprint(cert) {
		t.Fatalf("cnf = %v, want the record's thumbprint", access.Claims.Confirmation)
	}

	expired := f.opaque(t, func(r *store.OpaqueAccessToken) {
		r.ID = "opaque-expired"
		r.ExpiresAt = f.now.Add(-time.Minute)
	})
	_, err = endpointsupport.AcceptBearer(bearerRequest(t, "Bearer "+expired), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, "The access token has expired")

	_, err = endpointsupport.AcceptBearer(bearerRequest(t, "Bearer opaque-unknown"), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, "The access token is invalid")
}

func TestAcceptBearer_Revoked(t *testing.T) {
	t.Parallel()
	f := newBearerFixture(t)
	ctx := context.Background()

	raw := f.jwt(t, nil)
	if err := f.st.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{GrantID: "grant-1", RevokedAt: f.now}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	_, err := endpointsupport.AcceptBearer(bearerRequest(t, "Bearer "+raw), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, "The access token has been revoked")

	opaque := f.opaque(t, nil)
	if err := f.st.OpaqueAccessTokens().RevokeByID(ctx, opaque); err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	_, err = endpointsupport.AcceptBearer(bearerRequest(t, "Bearer "+opaque), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, "The access token has been revoked")
}

func TestAcceptBearer_DPoPBound(t *testing.T) {
	t.Parallel()
	f := newBearerFixture(t)
	bound := newBearerDPoPKey(t)
	other := newBearerDPoPKey(t)
	raw := f.jwt(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{tokens.CnfJKT: bound.jkt}
	})

	present := func(scheme string, key bearerDPoPKey, jti string) *http.Request {
		r := bearerRequest(t, scheme+" "+raw)
		r.Header.Set("DPoP", key.proof(t, f.now, jti, dpop.AccessTokenHash(raw)))
		return r
	}

	_, err := endpointsupport.AcceptBearer(present("DPoP", bound, "p0"), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeDPoP, "DPoP verification is not enabled")

	verifier, err := dpop.NewVerifier(dpop.VerifierConfig{JTIs: f.st.ConsumedJTIs(), Clock: f.deps.Clock})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	f.deps.DPoP = verifier

	if _, err := endpointsupport.AcceptBearer(present("DPoP", bound, "p1"), f.deps); err != nil {
		t.Fatalf("matching proof: %v", err)
	}
	_, err = endpointsupport.AcceptBearer(present("DPoP", other, "p2"), f.deps)
	got := requireBearerRejection(t, err, endpointsupport.BearerSchemeDPoP, "DPoP proof key does not match the bound thumbprint")
	if want := `DPoP error="invalid_token", error_description="DPoP proof key does not match the bound thumbprint"`; got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
	_, err = endpointsupport.AcceptBearer(present("Bearer", bound, "p3"), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeDPoP, "DPoP-bound access token must use the DPoP authentication scheme")
	_, err = endpointsupport.AcceptBearer(bearerRequest(t, "DPoP "+raw), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeDPoP, "DPoP proof required")
}

func TestAcceptBearer_MTLSBound(t *testing.T) {
	t.Parallel()
	f := newBearerFixture(t)
	f.deps.MTLS = newBearerMTLS(t)
	cert := bearerTestCert(t)
	raw := f.jwt(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{tokens.CnfX5tS256: mtls.Thumbprint(cert)}
	})
	present := func(c *x509.Certificate) *http.Request {
		r := bearerRequest(t, "Bearer "+raw)
		if c != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
		}
		return r
	}

	if _, err := endpointsupport.AcceptBearer(present(cert), f.deps); err != nil {
		t.Fatalf("matching cert: %v", err)
	}
	const mismatch = "client certificate does not match the bound thumbprint"
	_, err := endpointsupport.AcceptBearer(present(bearerTestCert(t)), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, mismatch)
	_, err = endpointsupport.AcceptBearer(present(nil), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, mismatch)

	f.deps.MTLS = nil
	_, err = endpointsupport.AcceptBearer(present(cert), f.deps)
	requireBearerRejection(t, err, endpointsupport.BearerSchemeBearer, "mTLS verification is not enabled")
}

type countingNonces struct{ n int }

func (c *countingNonces) IssueNonce() string {
	c.n++
	return "nonce-" + strconv.Itoa(c.n)
}

// TestNewUseDPoPNonceError pins the RFC 9449 §9 challenge: a fresh
// nonce per rejection, and no DPoP-Nonce header without an issuer.
func TestNewUseDPoPNonceError(t *testing.T) {
	t.Parallel()
	nonces := &countingNonces{}
	for _, want := range []string{"nonce-1", "nonce-2"} {
		rec := httptest.NewRecorder()
		endpointsupport.NewUseDPoPNonceError(nonces).WriteResponse(rec)
		if got := rec.Header().Get("DPoP-Nonce"); got != want {
			t.Errorf("DPoP-Nonce = %q, want %q", got, want)
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, `DPoP error="use_dpop_nonce", error_description=`) {
			t.Errorf("WWW-Authenticate = %q", got)
		}
	}
	rec := httptest.NewRecorder()
	endpointsupport.NewUseDPoPNonceError(nil).WriteResponse(rec)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("DPoP-Nonce") != "" {
		t.Errorf("nil issuer: status=%d DPoP-Nonce=%q", rec.Code, rec.Header().Get("DPoP-Nonce"))
	}
}

func newBearerMTLS(t *testing.T) *mtls.Verifier {
	t.Helper()
	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("mtls.NewVerifier: %v", err)
	}
	return v
}

func bearerTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

type bearerDPoPKey struct {
	priv *ecdsa.PrivateKey
	jkt  string
}

func newBearerDPoPKey(t *testing.T) bearerDPoPKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jkt, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return bearerDPoPKey{priv: priv, jkt: jkt}
}

func (k bearerDPoPKey) proof(t *testing.T, now time.Time, jti, ath string) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: k.priv},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", josev4.JSONWebKey{Key: &k.priv.PublicKey}),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(map[string]any{
		"jti": jti, "htm": http.MethodGet, "htu": acceptTestURL, "iat": now.Unix(), "ath": ath,
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return out
}
