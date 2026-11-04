package tokenendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/assertiongrant"
	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	jbGrantType  = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	jbOPIssuer   = "https://op.example"
	jbTokenURL   = "https://op.example/token" //nolint:gosec // Token endpoint URL, not a credential.
	jbPlainIss   = "https://idp-plain.example.com"
	jbJAGIss     = "https://idp-jag.example.com"
	jbUnknownIss = "https://idp-unknown.example.com"
	jbIssuerKID  = "jb-issuer-key"
	jbSecret     = "jb-secret"
	jbAPI        = "https://api.example.com/mcp"
	jbOther      = "https://other.example.com/mcp"

	jbClient   = "jb-client"
	jbPublic   = "jb-public"
	jbNoGrant  = "jb-no-grant"
	jbOutsider = "jb-outsider"
)

// jbNow is the fixed instant every jwt-bearer test runs at.
var jbNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// jbFixture wires [tokenendpoint.Deps] around an assertion verifier that
// trusts two issuers by static JWKS: one plain RFC 7523, one ID-JAG.
type jbFixture struct {
	deps      tokenendpoint.Deps
	store     *inmem.Store
	clock     fixedClock
	issuerKey *ecdsa.PrivateKey
	opKeys    *keys.Set
	events    *recordingEmitter
	jti       int
}

func newJBFixture(t *testing.T) *jbFixture {
	t.Helper()
	clock := fixedClock{now: jbNow}
	s := inmem.New(inmem.WithClock(clock))
	hash, err := (&clientauth.Argon2id{}).Hash(jbSecret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	clients := []*store.Client{
		{
			ID: jbClient, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes: []string{jbGrantType},
			Scopes:     []string{"openid", "read", "write"},
			Resources:  []string{jbAPI, jbOther},
		},
		{
			ID: jbPublic, TokenEndpointAuthMethod: "none", PublicClient: true,
			GrantTypes: []string{jbGrantType}, Scopes: []string{"read"},
		},
		{
			ID: jbNoGrant, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"},
		},
		{
			ID: jbOutsider, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes: []string{jbGrantType}, Scopes: []string{"read"},
		},
	}
	for _, c := range clients {
		if err := s.RegisterClient(context.Background(), c); err != nil {
			t.Fatalf("RegisterClient(%s): %v", c.ID, err)
		}
	}
	seedSubject(t, s, "user-alice")

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwks := jbJWKS(t, issuerKey)
	verifier := jbVerifier(t, s, clock, rpjwks.New(rpjwks.Config{Clock: clock}), []assertiongrant.Issuer{
		{Issuer: jbPlainIss, JWKS: jwks, Profile: assertiongrant.ProfileJWT},
		{Issuer: jbJAGIss, JWKS: jwks, Profile: assertiongrant.ProfileIDJAG},
	})

	entry, err := keys.GenerateES256("jb-op-kid")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	opKeys, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	events := &recordingEmitter{}
	allowed := map[string][]string{
		jbPlainIss: {jbClient, jbPublic, jbNoGrant},
		jbJAGIss:   {jbClient, jbPublic, jbNoGrant},
	}
	deps := tokenendpoint.Deps{
		Issuer:       jbOPIssuer,
		Clients:      s,
		UserStore:    s.Users(),
		Keys:         opKeys,
		Clock:        clock,
		AccessTokens: s.AccessTokens(),
		Audit:        events,
		JWTBearer:    verifier,
		ResolveAssertionSubject: func(_ context.Context, sub assertiongrant.Subject) (string, error) {
			switch sub.Subject {
			case "alice":
				return "user-alice", nil
			case "gone":
				return "user-gone", nil
			case "blank":
				return "", nil
			case "broken":
				return "", errors.New("directory unavailable")
			default:
				return "", assertiongrant.ErrUnknownSubject
			}
		},
		JWTBearerAllowedClients: func(issuer string) []string { return allowed[issuer] },
	}
	return &jbFixture{deps: deps, store: s, clock: clock, issuerKey: issuerKey, opKeys: opKeys, events: events}
}

func jbVerifier(t *testing.T, s *inmem.Store, clock fixedClock, fetcher *rpjwks.Fetcher, issuers []assertiongrant.Issuer) *assertiongrant.Verifier {
	t.Helper()
	v, err := assertiongrant.New(assertiongrant.Config{
		Issuers:          issuers,
		KeySource:        fetcher,
		JTIs:             s.ConsumedJTIs(),
		Clock:            clock,
		OPIssuer:         jbOPIssuer,
		TokenEndpointURL: jbTokenURL,
	})
	if err != nil {
		t.Fatalf("assertiongrant.New: %v", err)
	}
	return v
}

func jbJWKS(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{
		{Key: &key.PublicKey, KeyID: jbIssuerKID, Use: "sig", Algorithm: "ES256"},
	}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// plainClaims returns an RFC 7523 claim set for sub with a fresh jti.
func (f *jbFixture) plainClaims(sub string) map[string]any {
	f.jti++
	return map[string]any{
		"iss": jbPlainIss,
		"sub": sub,
		"aud": jbOPIssuer,
		"exp": jbNow.Add(2 * time.Minute).Unix(),
		"iat": jbNow.Unix(),
		"jti": "jb-jti-" + strconv.Itoa(f.jti),
	}
}

// idjagClaims returns an ID-JAG claim set for sub, issued to jbClient.
func (f *jbFixture) idjagClaims(sub string) map[string]any {
	c := f.plainClaims(sub)
	c["iss"] = jbJAGIss
	c["client_id"] = jbClient
	return c
}

func (f *jbFixture) sign(t *testing.T, claims map[string]any, typ string) string {
	t.Helper()
	opts := (&josev4.SignerOptions{}).WithHeader("kid", jbIssuerKID)
	if typ != "" {
		opts = opts.WithType(josev4.ContentType(typ))
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.ES256, Key: f.issuerKey}, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return out
}

func (f *jbFixture) plain(t *testing.T, sub string) string {
	t.Helper()
	return f.sign(t, f.plainClaims(sub), "")
}

func (f *jbFixture) idjag(t *testing.T, claims map[string]any) string {
	t.Helper()
	return f.sign(t, claims, "oauth-id-jag+jwt")
}

// jbRequest describes one /token call.
type jbRequest struct {
	clientID  string
	form      url.Values
	dpopProof string
	cert      *x509.Certificate
}

func jbForm(assertion string, extra ...string) url.Values {
	form := url.Values{}
	form.Set("grant_type", jbGrantType)
	if assertion != "" {
		form.Set("assertion", assertion)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Add(extra[i], extra[i+1])
	}
	return form
}

func (f *jbFixture) do(t *testing.T, in jbRequest) *httptest.ResponseRecorder {
	t.Helper()
	if in.clientID == "" {
		in.clientID = jbClient
	}
	form := in.form
	if in.clientID == jbPublic {
		form.Set("client_id", jbPublic)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, jbTokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if in.clientID != jbPublic {
		req.SetBasicAuth(in.clientID, jbSecret)
	}
	if in.dpopProof != "" {
		req.Header.Set("DPoP", in.dpopProof)
	}
	if in.cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{in.cert}}
	}
	rec := httptest.NewRecorder()
	tokenendpoint.Handler(f.deps).ServeHTTP(rec, req)
	return rec
}

func (f *jbFixture) post(t *testing.T, clientID string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, jbRequest{clientID: clientID, form: form})
}

func jbBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v: %s", err, rec.Body.String())
	}
	return body
}

func jbExpectError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, status, rec.Body.String())
	}
	if got := jbBody(t, rec)["error"]; got != code {
		t.Fatalf("error = %v, want %q", got, code)
	}
}

// expectOK asserts a success response without refresh_token or id_token and
// returns the verified access token claims.
func (f *jbFixture) expectOK(t *testing.T, rec *httptest.ResponseRecorder) (map[string]any, *tokens.AccessTokenClaims) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := jbBody(t, rec)
	for _, absent := range []string{"refresh_token", "id_token"} {
		if _, has := body[absent]; has {
			t.Errorf("%s must not be issued on the jwt-bearer grant", absent)
		}
	}
	at, _ := body["access_token"].(string)
	verifier := &tokens.AccessTokenVerifier{Keys: f.opKeys, Issuer: jbOPIssuer, Clock: f.clock}
	parsed, _, err := verifier.Verify(context.Background(), at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	return body, parsed
}

// rejectedReasons returns the reason of every jwt_bearer.rejected event.
func (f *jbFixture) rejectedReasons() []string {
	var out []string
	for _, ev := range f.events.events {
		if ev.Name == string(auditevent.AuditJWTBearerRejected) {
			reason, _ := ev.Extras["reason"].(string)
			out = append(out, reason)
		}
	}
	return out
}

func (f *jbFixture) expectRejectedReason(t *testing.T, want string) {
	t.Helper()
	got := f.rejectedReasons()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("jwt_bearer.rejected reasons = %v, want [%s]", got, want)
	}
}

func (f *jbFixture) countEvents(name auditevent.Name) int {
	n := 0
	for _, ev := range f.events.events {
		if ev.Name == string(name) {
			n++
		}
	}
	return n
}

func TestJWTBearer_PlainProfile_HappyPath(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)

	body, at := f.expectOK(t, f.post(t, jbClient, jbForm(f.plain(t, "alice"))))
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}
	if body["scope"] != "read write" {
		t.Errorf("scope = %v, want the registered set without openid", body["scope"])
	}
	if got, _ := body["expires_in"].(float64); got <= 0 {
		t.Errorf("expires_in = %v, want > 0", body["expires_in"])
	}
	if at.Subject != "user-alice" {
		t.Errorf("sub = %q, want the resolved subject", at.Subject)
	}
	if at.ClientID != jbClient {
		t.Errorf("client_id = %q, want %q", at.ClientID, jbClient)
	}
	if len(at.Audience) != 1 || at.Audience[0] != jbOPIssuer {
		t.Errorf("aud = %v, want [%s]", at.Audience, jbOPIssuer)
	}
	if at.GrantID != "" {
		t.Errorf("gid = %q, want none (unbacked token)", at.GrantID)
	}
	if len(at.Confirmation) != 0 {
		t.Errorf("cnf = %v, want none on an unbound request", at.Confirmation)
	}
	if n := f.countEvents(auditevent.AuditJWTBearerGranted); n != 1 {
		t.Errorf("jwt_bearer.granted events = %d, want 1", n)
	}
}

func TestJWTBearer_IDJAGProfile_HappyPath(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	claims := f.idjagClaims("alice")
	claims["scope"] = "read"
	claims["resource"] = jbAPI

	body, at := f.expectOK(t, f.post(t, jbClient, jbForm(f.idjag(t, claims))))
	if body["scope"] != "read" {
		t.Errorf("scope = %v, want the default narrowed to the scope claim", body["scope"])
	}
	if len(at.Audience) != 1 || at.Audience[0] != jbAPI {
		t.Errorf("aud = %v, want the claimed resource", at.Audience)
	}
	if at.Subject != "user-alice" {
		t.Errorf("sub = %q, want user-alice", at.Subject)
	}
	var granted *audit.Event
	for i := range f.events.events {
		if f.events.events[i].Name == string(auditevent.AuditJWTBearerGranted) {
			granted = &f.events.events[i]
		}
	}
	if granted == nil || granted.Extras["profile"] != "id-jag" || granted.Extras["issuer"] != jbJAGIss {
		t.Errorf("jwt_bearer.granted = %+v, want profile id-jag from %s", granted, jbJAGIss)
	}
}

func TestJWTBearer_NoneClient_UnauthorizedClient(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)

	jbExpectError(t, f.post(t, jbPublic, jbForm(f.plain(t, "alice"))), http.StatusBadRequest, "unauthorized_client")
	f.expectRejectedReason(t, "public_client")
}

func TestJWTBearer_AllowedClientsMiss_UnauthorizedClient(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	assertion := f.plain(t, "alice")

	jbExpectError(t, f.post(t, jbOutsider, jbForm(assertion)), http.StatusBadRequest, "unauthorized_client")
	f.expectRejectedReason(t, "client_not_allowed")
	// The refusal ran before verification, so the jti is still unspent.
	f.expectOK(t, f.post(t, jbClient, jbForm(assertion)))
}

func TestJWTBearer_GrantTypesMiss_UnauthorizedClient(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)

	jbExpectError(t, f.post(t, jbNoGrant, jbForm(f.plain(t, "alice"))), http.StatusBadRequest, "unauthorized_client")
}

func TestJWTBearer_UnknownIssuer_InvalidGrant(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	claims := f.plainClaims("alice")
	claims["iss"] = jbUnknownIss

	jbExpectError(t, f.post(t, jbClient, jbForm(f.sign(t, claims, ""))), http.StatusBadRequest, "invalid_grant")
	f.expectRejectedReason(t, string(assertiongrant.ReasonIssuer))
}

func TestJWTBearer_ReplayedAssertion_InvalidGrant(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	assertion := f.plain(t, "alice")

	f.expectOK(t, f.post(t, jbClient, jbForm(assertion)))
	jbExpectError(t, f.post(t, jbClient, jbForm(assertion)), http.StatusBadRequest, "invalid_grant")
	f.expectRejectedReason(t, string(assertiongrant.ReasonReplay))
}

func TestJWTBearer_UnknownSubject_AccessDenied(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)

	jbExpectError(t, f.post(t, jbClient, jbForm(f.plain(t, "stranger"))), http.StatusBadRequest, "access_denied")
	f.expectRejectedReason(t, "unknown_subject")
}

func TestJWTBearer_SubjectNotLive_AccessDenied(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)

	jbExpectError(t, f.post(t, jbClient, jbForm(f.plain(t, "gone"))), http.StatusBadRequest, "access_denied")
	f.expectRejectedReason(t, "subject_not_live")
}

func TestJWTBearer_ResolverFaults_ServerError(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{"blank", "broken"} {
		t.Run(sub, func(t *testing.T) {
			t.Parallel()
			f := newJBFixture(t)
			jbExpectError(t, f.post(t, jbClient, jbForm(f.plain(t, sub))), http.StatusInternalServerError, "server_error")
			f.expectRejectedReason(t, "resolver_fault")
		})
	}
}

func TestJWTBearer_ScopeNarrowing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, scope, want string
	}{
		{"registered subset kept", "write", "write"},
		{"absent falls back to registration", "", "read write"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBFixture(t)
			form := jbForm(f.plain(t, "alice"))
			if tc.scope != "" {
				form.Set("scope", tc.scope)
			}
			body, at := f.expectOK(t, f.post(t, jbClient, form))
			if body["scope"] != tc.want {
				t.Errorf("scope = %v, want %q", body["scope"], tc.want)
			}
			if got := strings.Join(at.Scope, " "); got != tc.want {
				t.Errorf("access token scope = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJWTBearer_ScopeOutsideRegistration_InvalidScope(t *testing.T) {
	t.Parallel()
	for _, scope := range []string{"admin", "read admin", "openid write"} {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()
			f := newJBFixture(t)
			assertion := f.plain(t, "alice")

			jbExpectError(t, f.post(t, jbClient, jbForm(assertion, "scope", scope)), http.StatusBadRequest, "invalid_scope")
			f.expectRejectedReason(t, "scope")
			// A request the client can fix does not consume the assertion.
			f.expectOK(t, f.post(t, jbClient, jbForm(assertion)))
		})
	}
}

func TestJWTBearer_IDJAGScopeBeyondClaim_InvalidGrant(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	claims := f.idjagClaims("alice")
	claims["scope"] = "read"

	jbExpectError(t, f.post(t, jbClient, jbForm(f.idjag(t, claims), "scope", "write")), http.StatusBadRequest, "invalid_grant")
	f.expectRejectedReason(t, string(assertiongrant.ReasonIDJAG))
}

func TestJWTBearer_ResourceRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		claim     any // nil: no resource claim
		requested string
		wantAud   string
		wantError string
	}{
		{name: "request within claim", claim: jbAPI, requested: jbAPI, wantAud: jbAPI},
		{name: "request outside claim", claim: jbAPI, requested: jbOther, wantError: "invalid_target"},
		{name: "claim becomes audience", claim: jbAPI, wantAud: jbAPI},
		{name: "several claimed, request selects", claim: []string{jbAPI, jbOther}, requested: jbOther, wantAud: jbOther},
		{name: "several claimed, none selected", claim: []string{jbAPI, jbOther}, wantError: "invalid_target"},
		{name: "no claim, request registered", requested: jbOther, wantAud: jbOther},
		{name: "no claim, request unregistered", requested: "https://unregistered.example.com", wantError: "invalid_target"},
		{name: "neither", wantAud: jbOPIssuer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBFixture(t)
			claims := f.idjagClaims("alice")
			if tc.claim != nil {
				claims["resource"] = tc.claim
			}
			form := jbForm(f.idjag(t, claims))
			if tc.requested != "" {
				form.Set("resource", tc.requested)
			}
			rec := f.post(t, jbClient, form)
			if tc.wantError != "" {
				jbExpectError(t, rec, http.StatusBadRequest, tc.wantError)
				f.expectRejectedReason(t, "resource")
				return
			}
			_, at := f.expectOK(t, rec)
			if len(at.Audience) != 1 || at.Audience[0] != tc.wantAud {
				t.Errorf("aud = %v, want [%s]", at.Audience, tc.wantAud)
			}
		})
	}
}

func TestJWTBearer_DPoP_StampsCnfJKT(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	verifier, err := dpop.NewVerifier(dpop.VerifierConfig{JTIs: f.store.ConsumedJTIs(), Clock: f.clock})
	if err != nil {
		t.Fatalf("dpop.NewVerifier: %v", err)
	}
	f.deps.DPoP = verifier
	key := newDPoPKey(t)
	// The ID-JAG is bound to the same key, so the verifier's cnf check runs too.
	claims := f.idjagClaims("alice")
	claims["cnf"] = map[string]any{"jkt": key.jkt}

	body, at := f.expectOK(t, f.do(t, jbRequest{
		form:      jbForm(f.idjag(t, claims)),
		dpopProof: makeDPoPProof(t, key, http.MethodPost, jbTokenURL, jbNow, "jb-dpop-1", ""),
	}))
	if body["token_type"] != "DPoP" {
		t.Errorf("token_type = %v, want DPoP", body["token_type"])
	}
	if got := at.Confirmation[tokens.CnfJKT]; got != key.jkt {
		t.Errorf("cnf.jkt = %q, want %q", got, key.jkt)
	}
}

func TestJWTBearer_MTLS_StampsCnfX5T(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	verifier, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		t.Fatalf("mtls.NewVerifier: %v", err)
	}
	f.deps.MTLS = verifier
	cert := generateMTLSLeaf(t)

	body, at := f.expectOK(t, f.do(t, jbRequest{form: jbForm(f.plain(t, "alice")), cert: cert}))
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer (RFC 8705 keeps the bearer type)", body["token_type"])
	}
	if got, want := at.Confirmation[tokens.CnfX5tS256], mtls.Thumbprint(cert); got != want {
		t.Errorf("cnf.x5t#S256 = %q, want %q", got, want)
	}
}

// jbFailingTransport answers every round-trip with a transient fetch failure.
type jbFailingTransport struct{}

func (jbFailingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &rpjwks.TransientError{Cause: errors.New("upstream unavailable")}
}

func TestJWTBearer_IssuerKeySourceOutage_ServiceUnavailable(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	fetcher := rpjwks.New(rpjwks.Config{Clock: f.clock, AllowPrivateNetwork: true, BaseTransport: jbFailingTransport{}})
	f.deps.JWTBearer = jbVerifier(t, f.store, f.clock, fetcher, []assertiongrant.Issuer{
		{Issuer: jbPlainIss, JWKSURI: srv.URL, Profile: assertiongrant.ProfileJWT},
	})

	jbExpectError(t, f.post(t, jbClient, jbForm(f.plain(t, "alice"))), http.StatusServiceUnavailable, "server_error")
	f.expectRejectedReason(t, "key_source_unavailable")
}

func TestJWTBearer_MissingAssertion_InvalidRequest(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)

	jbExpectError(t, f.post(t, jbClient, jbForm("")), http.StatusBadRequest, "invalid_request")
	f.expectRejectedReason(t, "missing_assertion")
}

func TestJWTBearer_DuplicateAssertion_InvalidRequest(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	assertion := f.plain(t, "alice")

	jbExpectError(t, f.post(t, jbClient, jbForm(assertion, "assertion", assertion)), http.StatusBadRequest, "invalid_request")
}

func TestJWTBearer_NotConfigured_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	f.deps.JWTBearer = nil

	jbExpectError(t, f.post(t, jbClient, jbForm(f.plain(t, "alice"))), http.StatusBadRequest, "unsupported_grant_type")
}

// A request the client can correct by changing its parameters leaves the
// assertion redeemable: the resource selection is settled before the jti
// is spent.
func TestJWTBearer_CorrectableResourceKeepsAssertion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		claim   any
		refused string
	}{
		{name: "request outside claim", claim: jbAPI, refused: jbOther},
		{name: "several claimed, none selected", claim: []string{jbAPI, jbOther}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBFixture(t)
			claims := f.idjagClaims("alice")
			claims["resource"] = tc.claim
			assertion := f.idjag(t, claims)

			form := jbForm(assertion)
			if tc.refused != "" {
				form.Set("resource", tc.refused)
			}
			jbExpectError(t, f.post(t, jbClient, form), http.StatusBadRequest, "invalid_target")
			_, at := f.expectOK(t, f.post(t, jbClient, jbForm(assertion, "resource", jbAPI)))
			if len(at.Audience) != 1 || at.Audience[0] != jbAPI {
				t.Errorf("aud = %v, want [%s]", at.Audience, jbAPI)
			}
		})
	}
}

// An ID-JAG scope claim sharing nothing with the client's registration
// narrows to nothing, which is invalid_scope rather than an empty token.
func TestJWTBearer_IDJAGScopeDisjointFromRegistration_InvalidScope(t *testing.T) {
	t.Parallel()
	f := newJBFixture(t)
	claims := f.idjagClaims("alice")
	claims["scope"] = "admin"

	rec := f.post(t, jbClient, jbForm(f.idjag(t, claims)))
	jbExpectError(t, rec, http.StatusBadRequest, "invalid_scope")
	if _, has := jbBody(t, rec)["access_token"]; has {
		t.Error("an empty scope set must not be issued")
	}
	f.expectRejectedReason(t, "scope")
}

// A resource claim spelled differently from the registration (host case,
// trailing slash) names the same RFC 8707 resource, and the audience the
// token carries is the canonical form whichever path selected it.
func TestJWTBearer_IDJAGResourceClaimComparedCanonically(t *testing.T) {
	t.Parallel()
	const spelled = "https://API.example.com/mcp/"
	for name, extra := range map[string][]string{
		"claim becomes audience":     nil,
		"parameter selects claim":    {"resource", jbAPI},
		"parameter spelled as claim": {"resource", spelled},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newJBFixture(t)
			claims := f.idjagClaims("alice")
			claims["resource"] = spelled
			_, at := f.expectOK(t, f.post(t, jbClient, jbForm(f.idjag(t, claims), extra...)))
			if len(at.Audience) != 1 || at.Audience[0] != jbAPI {
				t.Errorf("aud = %v, want [%s]", at.Audience, jbAPI)
			}
		})
	}
}
