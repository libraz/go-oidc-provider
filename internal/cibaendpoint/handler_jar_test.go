package cibaendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	jarTestIssuer  = "https://op.example"
	jarTestKID     = "rp-ciba-jar-1"
	jarTestSecret  = "rp-ciba-jar-secret" //nolint:gosec // test fixture, not a real credential.
	jarTestRPID    = "client-ciba-jar"
	jarTestSubject = "user-ciba-jar"
)

// jarFixture bundles a JAR-enabled cibaendpoint deps with the keys
// and clients required to exercise FAPI-CIBA-ID1 §5.2.2 paths.
type jarFixture struct {
	clock fixedClock
	store *inmem.Store
	deps  cibaendpoint.Deps
	priv  *ecdsa.PrivateKey
	rp    *store.Client
}

// newJARFixture constructs a CIBA fixture wired with a JAR verifier
// pointed at an inline JWKs registered against a confidential client
// authorised for the CIBA grant.
func newJARFixture(t *testing.T) *jarFixture {
	t.Helper()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keys := josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     jarTestKID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		}},
	}
	jwks, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("Marshal jwks: %v", err)
	}
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(jarTestSecret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := &store.Client{
		ID:                      jarTestRPID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"urn:openid:params:grant-type:ciba"},
		Scopes:                  []string{"openid", "profile", "email"},
		JWKs:                    jwks,
	}
	if err := s.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	verifier, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          jarTestIssuer,
		Resolver:        jar.NewDefaultResolver(clock),
		Clock:           clock,
		JTIs:            s.ConsumedJTIs(),
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	deps := cibaendpoint.Deps{
		Issuer:       jarTestIssuer,
		Clients:      s,
		CIBARequests: s.CIBARequests(),
		Clock:        clock,
		HintResolver: fakeResolver{subject: jarTestSubject},
		JAR:          verifier,
	}
	return &jarFixture{
		clock: clock,
		store: s,
		deps:  deps,
		priv:  priv,
		rp:    rp,
	}
}

// jarSign returns a compact ES256 JWS over claims with the fixture's
// signing key.
func (f *jarFixture) jarSign(t *testing.T, claims map[string]any) string {
	t.Helper()
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       f.priv,
			KeyID:     jarTestKID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	signer, err := josev4.NewSigner(sk, (&josev4.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return out
}

// happyClaims returns the canonical claim set for a FAPI-CIBA
// signed authentication request: iss / aud / exp / iat / jti per
// FAPI-CIBA-ID1 §5.2.2 plus the CIBA-specific parameters.
func (f *jarFixture) happyClaims() map[string]any {
	return map[string]any{
		"iss":        f.rp.ID,
		"aud":        jarTestIssuer,
		"exp":        f.clock.now.Add(5 * time.Minute).Unix(),
		"iat":        f.clock.now.Unix(),
		"nbf":        f.clock.now.Unix(),
		"jti":        freshJTI(),
		"client_id":  f.rp.ID,
		"scope":      "openid profile",
		"login_hint": "alice@example",
	}
}

// freshJTI returns a 128-bit random "jti" suitable for a single
// request object so successive request objects do not collide on
// the consumed-jti gate.
func freshJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "jti-" + hex.EncodeToString(b[:])
}

// jarPostRequest builds a /bc-authorize POST carrying form values
// (which may include "request") and Basic auth.
func jarPostRequest(form url.Values) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/bc-authorize",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(jarTestRPID, jarTestSecret)
	return req
}

// TestServe_JAR_HappyPath confirms that a properly signed request
// object is verified, merged onto the form, and the merged values
// drive a successful auth_req_id issuance.
func TestServe_JAR_HappyPath(t *testing.T) {
	t.Parallel()
	f := newJARFixture(t)
	signed := f.jarSign(t, f.happyClaims())
	form := url.Values{
		"request": {signed},
	}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(f.deps).ServeHTTP(rec, jarPostRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.AuthReqID == "" {
		t.Fatalf("auth_req_id missing")
	}
	persisted, err := f.store.CIBARequests().FindByAuthReqID(context.Background(), body.AuthReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if persisted.Subject != jarTestSubject {
		t.Errorf("subject = %q, want %q", persisted.Subject, jarTestSubject)
	}
	wantScope := []string{"openid", "profile"}
	if len(persisted.Scope) != len(wantScope) || persisted.Scope[0] != wantScope[0] || persisted.Scope[1] != wantScope[1] {
		t.Errorf("scope = %v, want %v", persisted.Scope, wantScope)
	}
}

// TestServe_JAR_RequireSignedRejectsUnsigned confirms that
// RequireSignedAuthRequest=true rejects a /bc-authorize POST that
// omits the "request" parameter, surfacing invalid_request per
// FAPI-CIBA-ID1 §5.2.2 ("the authentication request MUST be a
// signed authentication request").
func TestServe_JAR_RequireSignedRejectsUnsigned(t *testing.T) {
	t.Parallel()
	f := newJARFixture(t)
	f.deps.RequireSignedAuthRequest = true

	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "alice@example")
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(f.deps).ServeHTTP(rec, jarPostRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

// TestServe_JAR_NoVerifierRejectsRequest confirms that posting
// "request" against a deps with JAR=nil surfaces invalid_request —
// the OP advertises that JAR is off, so any inbound signed request
// is a configuration mismatch. CIBA Core §13 limits BCA error codes
// to a closed set that excludes invalid_request_object.
func TestServe_JAR_NoVerifierRejectsRequest(t *testing.T) {
	t.Parallel()
	f := newJARFixture(t)
	signed := f.jarSign(t, f.happyClaims())
	f.deps.JAR = nil

	form := url.Values{
		"request": {signed},
	}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(f.deps).ServeHTTP(rec, jarPostRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

// TestServe_JAR_BadSignature confirms that a request object whose
// signature does not match the registered keyset is rejected with
// invalid_request (CIBA Core §13 closed list).
func TestServe_JAR_BadSignature(t *testing.T) {
	t.Parallel()
	f := newJARFixture(t)
	// Sign with a fresh key the OP does not know about.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       other,
			KeyID:     jarTestKID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	signer, err := josev4.NewSigner(sk, (&josev4.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signed, err := jwt.Signed(signer).Claims(f.happyClaims()).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	form := url.Values{
		"request": {signed},
	}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(f.deps).ServeHTTP(rec, jarPostRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

// TestServe_JAR_BadAudience confirms that a request object whose
// "aud" claim does not match the OP issuer is rejected.
func TestServe_JAR_BadAudience(t *testing.T) {
	t.Parallel()
	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["aud"] = "https://different-op.example.com"
	signed := f.jarSign(t, claims)
	form := url.Values{
		"request": {signed},
	}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(f.deps).ServeHTTP(rec, jarPostRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

// TestServe_JAR_Expired confirms that a request object whose "exp"
// claim has elapsed is rejected.
func TestServe_JAR_Expired(t *testing.T) {
	t.Parallel()
	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["exp"] = f.clock.now.Add(-time.Minute).Unix()
	claims["iat"] = f.clock.now.Add(-2 * time.Minute).Unix()
	signed := f.jarSign(t, claims)
	form := url.Values{
		"request": {signed},
	}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(f.deps).ServeHTTP(rec, jarPostRequest(form))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}

// TestServe_JAR_ClaimsOverrideForm confirms that when a parameter
// appears both in the wire form and the request object, the JWT
// value wins per RFC 9101 §6.1. The persisted scope reflects the
// claim, not the form.
func TestServe_JAR_ClaimsOverrideForm(t *testing.T) {
	t.Parallel()
	f := newJARFixture(t)
	claims := f.happyClaims()
	// JWT scope: "openid email"
	claims["scope"] = "openid email"
	signed := f.jarSign(t, claims)

	form := url.Values{
		"request": {signed},
		// Form scope: "openid profile" — should be overridden by the
		// JWT's "openid email".
		"scope": {"openid profile"},
	}
	rec := httptest.NewRecorder()
	cibaendpoint.Handler(f.deps).ServeHTTP(rec, jarPostRequest(form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body successBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	persisted, err := f.store.CIBARequests().FindByAuthReqID(context.Background(), body.AuthReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	wantScope := []string{"openid", "email"}
	if len(persisted.Scope) != len(wantScope) {
		t.Fatalf("scope = %v, want %v", persisted.Scope, wantScope)
	}
	for i, s := range wantScope {
		if persisted.Scope[i] != s {
			t.Errorf("scope[%d] = %q, want %q (claim must win)", i, persisted.Scope[i], s)
		}
	}
}
