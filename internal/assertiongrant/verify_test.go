package assertiongrant_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/assertiongrant"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opIssuer  = "https://op.example.com"
	tokenURL  = "https://op.example.com/token" //nolint:gosec // Token endpoint URL, not a credential.
	plainIss  = "https://idp-plain.example.com"
	jagIss    = "https://idp-jag.example.com"
	clientID  = "client-1"
	apiRes    = "https://api.example.com"
	dpopJKT   = "dpop-thumbprint"
	mtlsX5T   = "cert-thumbprint"
	issuerKID = "issuer-key-1"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

var testNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func jwksFor(t *testing.T, kid string, keys ...*ecdsa.PrivateKey) []byte {
	t.Helper()
	set := josev4.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, josev4.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Use: "sig", Algorithm: "ES256"})
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// assertion is the material a test row mutates before signing.
type assertion struct {
	claims map[string]any
	typ    string
	kid    string
	key    any
	alg    josev4.SignatureAlgorithm
	raw    string // when set, replaces the signed output
}

func sign(t *testing.T, a *assertion) string {
	t.Helper()
	if a.raw != "" {
		return a.raw
	}
	opts := &josev4.SignerOptions{}
	if a.kid != "" {
		opts = opts.WithHeader("kid", a.kid)
	}
	if a.typ != "" {
		opts = opts.WithType(josev4.ContentType(a.typ))
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: a.alg, Key: a.key}, opts)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	payload, err := json.Marshal(a.claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return out
}

func baseAssertion(profile assertiongrant.Profile, key *ecdsa.PrivateKey) *assertion {
	a := &assertion{key: key, kid: issuerKID, alg: josev4.ES256}
	if profile == assertiongrant.ProfileIDJAG {
		a.typ = "oauth-id-jag+jwt"
		a.claims = map[string]any{
			"iss":       jagIss,
			"sub":       "user-1",
			"aud":       opIssuer,
			"client_id": clientID,
			"exp":       testNow.Add(2 * time.Minute).Unix(),
			"iat":       testNow.Unix(),
			"jti":       "jti-jag-1",
			"scope":     "read write",
			"resource":  apiRes,
		}
		return a
	}
	a.claims = map[string]any{
		"iss": plainIss,
		"sub": "user-1",
		"aud": opIssuer,
		"exp": testNow.Add(2 * time.Minute).Unix(),
		"iat": testNow.Unix(),
		"jti": "jti-plain-1",
	}
	return a
}

func baseClient() assertiongrant.ClientContext {
	return assertiongrant.ClientContext{
		ID:              clientID,
		RequestedScopes: []string{"read"},
		Resources:       []string{apiRes},
	}
}

type fixture struct {
	verifier *assertiongrant.Verifier
	jtis     store.ConsumedJTIStore
	key      *ecdsa.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := newKey(t)
	jwks := jwksFor(t, issuerKID, key)
	return newFixtureWith(t, key, rpjwks.New(rpjwks.Config{Clock: fixedClock{testNow}}), []assertiongrant.Issuer{
		{Issuer: plainIss, JWKS: jwks, Profile: assertiongrant.ProfileJWT},
		{Issuer: jagIss, JWKS: jwks, Profile: assertiongrant.ProfileIDJAG},
	})
}

func newFixtureWith(t *testing.T, key *ecdsa.PrivateKey, fetcher *rpjwks.Fetcher, issuers []assertiongrant.Issuer) *fixture {
	t.Helper()
	clock := fixedClock{testNow}
	jtis := inmem.New(inmem.WithClock(clock)).ConsumedJTIs()
	v, err := assertiongrant.New(assertiongrant.Config{
		Issuers:          issuers,
		KeySource:        fetcher,
		JTIs:             jtis,
		Clock:            clock,
		OPIssuer:         opIssuer,
		TokenEndpointURL: tokenURL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{verifier: v, jtis: jtis, key: key}
}

func reasonOf(err error) assertiongrant.Reason {
	var e *assertiongrant.Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func TestVerify_AcceptsPlainJWT(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := baseAssertion(assertiongrant.ProfileJWT, f.key)
	a.claims["email"] = "user@example.com"

	res, err := f.verifier.Verify(context.Background(), sign(t, a), baseClient())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Profile != assertiongrant.ProfileJWT {
		t.Errorf("Profile = %v, want jwt", res.Profile)
	}
	want := assertiongrant.Subject{Issuer: plainIss, Subject: "user-1", ClientID: clientID}
	if res.Subject.Issuer != want.Issuer || res.Subject.Subject != want.Subject || res.Subject.ClientID != want.ClientID {
		t.Errorf("Subject = %+v, want %+v", res.Subject, want)
	}
	if got := res.Subject.Claims["email"]; got != "user@example.com" {
		t.Errorf("Claims[email] = %v, want the verified claim", got)
	}
	if res.Scopes != nil || res.Resources != nil {
		t.Errorf("plain profile carried scopes %v / resources %v", res.Scopes, res.Resources)
	}
	if !res.ExpiresAt.Equal(time.Unix(testNow.Add(2*time.Minute).Unix(), 0)) {
		t.Errorf("ExpiresAt = %v", res.ExpiresAt)
	}
}

func TestVerify_AcceptsIDJAG(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := baseAssertion(assertiongrant.ProfileIDJAG, f.key)
	a.claims["cnf"] = map[string]any{"jkt": dpopJKT}
	client := baseClient()
	client.Binding.DPoPJKT = dpopJKT

	res, err := f.verifier.Verify(context.Background(), sign(t, a), client)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Profile != assertiongrant.ProfileIDJAG {
		t.Errorf("Profile = %v, want id-jag", res.Profile)
	}
	if strings.Join(res.Scopes, " ") != "read write" {
		t.Errorf("Scopes = %v, want [read write]", res.Scopes)
	}
	if len(res.Resources) != 1 || res.Resources[0] != apiRes {
		t.Errorf("Resources = %v, want [%s]", res.Resources, apiRes)
	}
	if res.Subject.Issuer != jagIss || res.Subject.ClientID != clientID {
		t.Errorf("Subject = %+v", res.Subject)
	}
}

// TestVerify_EdgeTable walks the verifier's rows of the input edge-value
// table: each mutation is either accepted or rejected at the named stage.
func TestVerify_EdgeTable(t *testing.T) {
	t.Parallel()

	b64 := base64.RawURLEncoding.EncodeToString
	otherKey := newKey(t)
	limit := testNow.Add(5*time.Minute + 60*time.Second).Unix()

	type row struct {
		name    string
		profile assertiongrant.Profile
		mutate  func(a *assertion)
		client  func(c *assertiongrant.ClientContext)
		want    assertiongrant.Reason // "" = accepted
	}
	rows := []row{
		// parse
		{name: "not three parts", mutate: func(a *assertion) { a.raw = "abc.def" }, want: assertiongrant.ReasonParse},
		{name: "JWE five parts", mutate: func(a *assertion) {
			a.raw = b64([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM"}`)) + ".a.b.c.d"
		}, want: assertiongrant.ReasonParse},
		{name: "alg none", mutate: func(a *assertion) {
			a.raw = b64([]byte(`{"alg":"none"}`)) + "." + b64([]byte(`{"iss":"`+plainIss+`"}`)) + "."
		}, want: assertiongrant.ReasonParse},
		{name: "alg HS256", mutate: func(a *assertion) {
			a.alg, a.key = josev4.HS256, []byte(strings.Repeat("s", 32))
		}, want: assertiongrant.ReasonParse},
		{name: "payload not JSON", mutate: func(a *assertion) {
			a.raw = b64([]byte(`{"alg":"ES256"}`)) + "." + b64([]byte(`nope`)) + "." + b64([]byte("sig"))
		}, want: assertiongrant.ReasonParse},

		// issuer
		{name: "iss missing", mutate: func(a *assertion) { delete(a.claims, "iss") }, want: assertiongrant.ReasonIssuer},
		{name: "iss not a string", mutate: func(a *assertion) { a.claims["iss"] = 42 }, want: assertiongrant.ReasonIssuer},
		{name: "iss case differs", mutate: func(a *assertion) { a.claims["iss"] = strings.ToUpper(plainIss) }, want: assertiongrant.ReasonIssuer},
		{name: "iss untrusted", mutate: func(a *assertion) { a.claims["iss"] = "https://evil.example.com" }, want: assertiongrant.ReasonIssuer},

		// typ
		{name: "plain typ JWT", mutate: func(a *assertion) { a.typ = "JWT" }},
		{name: "plain typ id-jag", mutate: func(a *assertion) { a.typ = "oauth-id-jag+jwt" }, want: assertiongrant.ReasonTyp},
		{name: "plain typ at+jwt", mutate: func(a *assertion) { a.typ = "at+jwt" }, want: assertiongrant.ReasonTyp},
		{name: "idjag typ absent", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.typ = "" }, want: assertiongrant.ReasonTyp},
		{name: "idjag typ JWT", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.typ = "JWT" }, want: assertiongrant.ReasonTyp},
		{name: "idjag typ with application prefix", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.typ = "application/oauth-id-jag+jwt" }},

		// signature
		{name: "wrong key same kid", mutate: func(a *assertion) { a.key = otherKey }, want: assertiongrant.ReasonSignature},
		{name: "unknown kid inline keys", mutate: func(a *assertion) { a.kid = "unknown" }, want: assertiongrant.ReasonSignature},

		// claims: aud
		{name: "plain aud token endpoint", mutate: func(a *assertion) { a.claims["aud"] = tokenURL }},
		{name: "plain aud array containing issuer", mutate: func(a *assertion) { a.claims["aud"] = []string{"https://other", opIssuer} }},
		{name: "plain aud other", mutate: func(a *assertion) { a.claims["aud"] = "https://other" }, want: assertiongrant.ReasonClaims},
		{name: "aud missing", mutate: func(a *assertion) { delete(a.claims, "aud") }, want: assertiongrant.ReasonClaims},
		{name: "idjag aud one-element array", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.claims["aud"] = []string{opIssuer} }},
		{name: "idjag aud two values", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.claims["aud"] = []string{opIssuer, tokenURL} }, want: assertiongrant.ReasonClaims},
		{name: "idjag aud token endpoint", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.claims["aud"] = tokenURL }, want: assertiongrant.ReasonClaims},

		// claims: exp
		{name: "exp missing", mutate: func(a *assertion) { delete(a.claims, "exp") }, want: assertiongrant.ReasonClaims},
		{name: "exp zero", mutate: func(a *assertion) { a.claims["exp"] = 0 }, want: assertiongrant.ReasonClaims},
		{name: "exp negative", mutate: func(a *assertion) { a.claims["exp"] = -1 }, want: assertiongrant.ReasonClaims},
		{name: "exp string", mutate: func(a *assertion) { a.claims["exp"] = "1893456000" }, want: assertiongrant.ReasonClaims},
		{name: "exp at now+5m+60s", mutate: func(a *assertion) { a.claims["exp"] = limit }},
		{name: "exp at now+5m+61s", mutate: func(a *assertion) { a.claims["exp"] = limit + 1 }, want: assertiongrant.ReasonClaims},
		{name: "exp past within leeway", mutate: func(a *assertion) { a.claims["exp"] = testNow.Add(-30 * time.Second).Unix() }},
		{name: "exp past beyond leeway", mutate: func(a *assertion) { a.claims["exp"] = testNow.Add(-61 * time.Second).Unix() }, want: assertiongrant.ReasonClaims},

		// claims: nbf / iat
		{name: "nbf within leeway", mutate: func(a *assertion) { a.claims["nbf"] = testNow.Add(60 * time.Second).Unix() }},
		{name: "nbf future", mutate: func(a *assertion) { a.claims["nbf"] = testNow.Add(61 * time.Second).Unix() }, want: assertiongrant.ReasonClaims},
		{name: "iat future", mutate: func(a *assertion) { a.claims["iat"] = testNow.Add(61 * time.Second).Unix() }, want: assertiongrant.ReasonClaims},
		{name: "plain iat absent", mutate: func(a *assertion) { delete(a.claims, "iat") }},
		{name: "idjag iat absent", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { delete(a.claims, "iat") }, want: assertiongrant.ReasonClaims},

		// claims: sub
		{name: "sub empty", mutate: func(a *assertion) { a.claims["sub"] = "" }, want: assertiongrant.ReasonClaims},
		{name: "sub missing", mutate: func(a *assertion) { delete(a.claims, "sub") }, want: assertiongrant.ReasonClaims},

		// idjag
		{name: "idjag client_id mismatch", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.claims["client_id"] = "client-2" }, want: assertiongrant.ReasonIDJAG},
		{name: "idjag client_id missing", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { delete(a.claims, "client_id") }, want: assertiongrant.ReasonIDJAG},
		{name: "idjag tenant present", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { a.claims["tenant"] = "t1" }, want: assertiongrant.ReasonIDJAG},
		{name: "idjag requested scope outside claim", profile: assertiongrant.ProfileIDJAG, client: func(c *assertiongrant.ClientContext) {
			c.RequestedScopes = []string{"read", "admin"}
		}, want: assertiongrant.ReasonIDJAG},
		{name: "idjag no scope claim", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { delete(a.claims, "scope") }},
		{name: "idjag resource outside client resources", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) {
			a.claims["resource"] = []string{apiRes, "https://other-api.example.com"}
		}, want: assertiongrant.ReasonIDJAG},
		{name: "idjag cnf jwk", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) {
			a.claims["cnf"] = map[string]any{"jwk": map[string]any{"kty": "EC"}}
		}, want: assertiongrant.ReasonIDJAG},
		{name: "idjag cnf both methods", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) {
			a.claims["cnf"] = map[string]any{"jkt": dpopJKT, "x5t#S256": mtlsX5T}
		}, client: func(c *assertiongrant.ClientContext) {
			c.Binding = assertiongrant.Binding{DPoPJKT: dpopJKT, X5TS256: mtlsX5T}
		}, want: assertiongrant.ReasonIDJAG},
		{name: "idjag cnf jkt mismatch", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) {
			a.claims["cnf"] = map[string]any{"jkt": "other"}
		}, client: func(c *assertiongrant.ClientContext) { c.Binding.DPoPJKT = dpopJKT }, want: assertiongrant.ReasonIDJAG},
		{name: "idjag cnf jkt without binding", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) {
			a.claims["cnf"] = map[string]any{"jkt": dpopJKT}
		}, want: assertiongrant.ReasonIDJAG},
		{name: "idjag cnf x5t#S256 match", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) {
			a.claims["cnf"] = map[string]any{"x5t#S256": mtlsX5T}
		}, client: func(c *assertiongrant.ClientContext) { c.Binding.X5TS256 = mtlsX5T }},

		// replay: jti shape
		{name: "jti missing", mutate: func(a *assertion) { delete(a.claims, "jti") }, want: assertiongrant.ReasonReplay},
		{name: "jti empty", mutate: func(a *assertion) { a.claims["jti"] = "" }, want: assertiongrant.ReasonReplay},
		{name: "jti 257 chars", mutate: func(a *assertion) { a.claims["jti"] = strings.Repeat("j", 257) }, want: assertiongrant.ReasonReplay},
		{name: "jti 256 chars", mutate: func(a *assertion) { a.claims["jti"] = strings.Repeat("j", 256) }},
		{name: "idjag jti missing", profile: assertiongrant.ProfileIDJAG, mutate: func(a *assertion) { delete(a.claims, "jti") }, want: assertiongrant.ReasonReplay},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			a := baseAssertion(r.profile, f.key)
			if r.mutate != nil {
				r.mutate(a)
			}
			client := baseClient()
			if r.client != nil {
				r.client(&client)
			}
			_, err := f.verifier.Verify(context.Background(), sign(t, a), client)
			if r.want == "" {
				if err != nil {
					t.Fatalf("Verify rejected an acceptable assertion: %v", err)
				}
				return
			}
			if got := reasonOf(err); got != r.want {
				t.Fatalf("reason = %q (err %v), want %q", got, err, r.want)
			}
		})
	}
}

// TestVerify_NonASCIISubjectPassesVerbatim pins that the verifier hands sub
// to the resolver unchanged.
func TestVerify_NonASCIISubjectPassesVerbatim(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := baseAssertion(assertiongrant.ProfileJWT, f.key)
	a.claims["sub"] = "ユーザー-1"
	res, err := f.verifier.Verify(context.Background(), sign(t, a), baseClient())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Subject.Subject != "ユーザー-1" {
		t.Errorf("Subject = %q, want the claim verbatim", res.Subject.Subject)
	}
}

func TestVerify_RejectsReusedJTI(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	raw := sign(t, baseAssertion(assertiongrant.ProfileJWT, f.key))
	if _, err := f.verifier.Verify(context.Background(), raw, baseClient()); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	_, err := f.verifier.Verify(context.Background(), raw, baseClient())
	if got := reasonOf(err); got != assertiongrant.ReasonReplay {
		t.Fatalf("second Verify reason = %q (err %v), want replay", got, err)
	}
}

// TestVerify_ReplayKeyIsIssuerScopedAndSeparateFromClientAssertions pins the
// jti namespace: the same jti from two issuers is two markers, neither of
// which can collide with the client-assertion namespace.
func TestVerify_ReplayKeyIsIssuerScopedAndSeparateFromClientAssertions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	plain := baseAssertion(assertiongrant.ProfileJWT, f.key)
	plain.claims["jti"] = "shared"
	jag := baseAssertion(assertiongrant.ProfileIDJAG, f.key)
	jag.claims["jti"] = "shared"
	for _, a := range []*assertion{plain, jag} {
		if _, err := f.verifier.Verify(ctx, sign(t, a), baseClient()); err != nil {
			t.Fatalf("Verify %s: %v", a.claims["iss"], err)
		}
	}
	for _, key := range []string{
		"jwtbearer:https%3A//idp-plain.example.com:shared",
		"jwtbearer:https%3A//idp-jag.example.com:shared",
	} {
		ok, err := f.jtis.Has(ctx, key)
		if err != nil || !ok {
			t.Errorf("Has(%q) = %v, %v; want a marker", key, ok, err)
		}
	}
}

// TestVerify_RejectedAssertionDoesNotConsumeJTI pins that replay runs last.
func TestVerify_RejectedAssertionDoesNotConsumeJTI(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := baseAssertion(assertiongrant.ProfileIDJAG, f.key)
	client := baseClient()
	client.ID = "client-2"
	if _, err := f.verifier.Verify(context.Background(), sign(t, a), client); reasonOf(err) != assertiongrant.ReasonIDJAG {
		t.Fatalf("mismatched client: err = %v, want idjag", err)
	}
	if _, err := f.verifier.Verify(context.Background(), sign(t, a), baseClient()); err != nil {
		t.Fatalf("Verify after a rejected attempt: %v", err)
	}
}

func rotatingJWKS(t *testing.T, first, second []byte, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := second
		if hits.Add(1) == 1 {
			body = first
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestVerify_RefetchesIssuerKeysOnKIDMiss pins rotation recovery: an
// assertion naming a kid the cached issuer keyset lacks triggers one fresh
// fetch, and a kid still absent afterwards is a signature rejection.
func TestVerify_RefetchesIssuerKeysOnKIDMiss(t *testing.T) {
	t.Parallel()
	oldKey, newKeyPair := newKey(t), newKey(t)
	hits := &atomic.Int32{}
	srv := rotatingJWKS(t, jwksFor(t, "old", oldKey), jwksFor(t, "new", newKeyPair), hits)
	fetcher := rpjwks.New(rpjwks.Config{Clock: fixedClock{testNow}, AllowPrivateNetwork: true})
	f := newFixtureWith(t, oldKey, fetcher, []assertiongrant.Issuer{
		{Issuer: plainIss, JWKSURI: srv.URL, Profile: assertiongrant.ProfileJWT},
	})
	ctx := context.Background()

	first := baseAssertion(assertiongrant.ProfileJWT, oldKey)
	first.kid = "old"
	if _, err := f.verifier.Verify(ctx, sign(t, first), baseClient()); err != nil {
		t.Fatalf("Verify under the cached key: %v", err)
	}

	rotated := baseAssertion(assertiongrant.ProfileJWT, newKeyPair)
	rotated.kid, rotated.claims["jti"] = "new", "jti-rotated"
	if _, err := f.verifier.Verify(ctx, sign(t, rotated), baseClient()); err != nil {
		t.Fatalf("Verify under the rotated key: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("hits = %d, want 2 (one refetch on the kid miss)", got)
	}

	// Inside the throttle window an unknown kid costs no round-trip.
	unknown := baseAssertion(assertiongrant.ProfileJWT, newKeyPair)
	unknown.kid, unknown.claims["jti"] = "missing", "jti-missing"
	_, err := f.verifier.Verify(ctx, sign(t, unknown), baseClient())
	if got := reasonOf(err); got != assertiongrant.ReasonSignature {
		t.Fatalf("unknown kid reason = %q (err %v), want signature", got, err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits = %d after a throttled kid miss, want still 2", got)
	}
}

// failingTransport answers every round-trip with a transient fetch failure.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &rpjwks.TransientError{Cause: errors.New("upstream unavailable")}
}

// TestVerify_TransientKeySourceOutageIsNotAnAssertionDefect pins the 503
// mapping: a transient JWKS failure surfaces ErrKeySourceUnavailable, not an
// invalid_grant *Error, and consumes no jti.
func TestVerify_TransientKeySourceOutageIsNotAnAssertionDefect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	fetcher := rpjwks.New(rpjwks.Config{
		Clock:               fixedClock{testNow},
		AllowPrivateNetwork: true,
		BaseTransport:       failingTransport{},
	})
	key := newKey(t)
	f := newFixtureWith(t, key, fetcher, []assertiongrant.Issuer{
		{Issuer: plainIss, JWKSURI: srv.URL, Profile: assertiongrant.ProfileJWT},
	})

	_, err := f.verifier.Verify(context.Background(), sign(t, baseAssertion(assertiongrant.ProfileJWT, key)), baseClient())
	if !errors.Is(err, assertiongrant.ErrKeySourceUnavailable) {
		t.Fatalf("err = %v, want ErrKeySourceUnavailable", err)
	}
	var e *assertiongrant.Error
	if errors.As(err, &e) {
		t.Fatalf("transient outage surfaced as an assertion defect (%q)", e.Reason)
	}
	if ok, _ := f.jtis.Has(context.Background(), "jwtbearer:https%3A//idp-plain.example.com:jti-plain-1"); ok {
		t.Error("a transient outage consumed the jti")
	}
}

func TestPeekIssuer(t *testing.T) {
	t.Parallel()
	key := newKey(t)
	got, err := assertiongrant.PeekIssuer(sign(t, baseAssertion(assertiongrant.ProfileIDJAG, key)))
	if err != nil || got != jagIss {
		t.Fatalf("PeekIssuer = %q, %v; want %q", got, err, jagIss)
	}
	if _, err := assertiongrant.PeekIssuer("abc.def"); reasonOf(err) != assertiongrant.ReasonParse {
		t.Errorf("PeekIssuer(garbage) err = %v, want parse", err)
	}
}

func TestNew_RejectsIncompleteConfig(t *testing.T) {
	t.Parallel()
	fetcher := rpjwks.New(rpjwks.Config{})
	jtis := inmem.New().ConsumedJTIs()
	iss := assertiongrant.Issuer{Issuer: plainIss, JWKS: []byte(`{"keys":[]}`)}
	for name, cfg := range map[string]assertiongrant.Config{
		"no issuers":    {KeySource: fetcher, JTIs: jtis, OPIssuer: opIssuer},
		"empty issuer":  {Issuers: []assertiongrant.Issuer{{}}, KeySource: fetcher, JTIs: jtis, OPIssuer: opIssuer},
		"duplicate":     {Issuers: []assertiongrant.Issuer{iss, iss}, KeySource: fetcher, JTIs: jtis, OPIssuer: opIssuer},
		"no key source": {Issuers: []assertiongrant.Issuer{iss}, JTIs: jtis, OPIssuer: opIssuer},
		"no jti store":  {Issuers: []assertiongrant.Issuer{iss}, KeySource: fetcher, OPIssuer: opIssuer},
		"no OP issuer":  {Issuers: []assertiongrant.Issuer{iss}, KeySource: fetcher, JTIs: jtis},
	} {
		if _, err := assertiongrant.New(cfg); err == nil {
			t.Errorf("%s: New accepted the config", name)
		}
	}
}
