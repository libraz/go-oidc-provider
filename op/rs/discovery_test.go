package rs_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/op/rs"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// issuerServer is an issuer whose discovery document and introspection
// answer the test controls, with a fetch counter per path.
type issuerServer struct {
	srv           *httptest.Server
	keys          *keyServer
	discovery     func(issuer string) (int, string)
	introspection func() string
	// introspectionStatus overrides the introspection answer's HTTP
	// status; zero means 200.
	introspectionStatus int
	discoveryHits       atomic.Int32
	jwksHits            atomic.Int32
}

func newIssuerServer(t *testing.T, keys *keyServer) *issuerServer {
	t.Helper()
	s := &issuerServer{keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		s.discoveryHits.Add(1)
		status, body := s.discovery(s.srv.URL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		s.jwksHits.Add(1)
		keys.srv.Config.Handler.ServeHTTP(w, r)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if s.introspectionStatus != 0 {
			w.WriteHeader(s.introspectionStatus)
		}
		_, _ = w.Write([]byte(s.introspection()))
	})
	s.srv = httptest.NewTLSServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// verifier builds a verifier that discovers everything from s.
func (s *issuerServer) verifier(t *testing.T, clock *testClock, mutate ...func(*rs.Config)) *rs.Verifier {
	t.Helper()
	cfg := rs.Config{
		Issuer:              s.srv.URL,
		Audience:            testAudience,
		HTTPClient:          s.srv.Client(),
		AllowPrivateNetwork: true,
		Clock:               clock,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := rs.New(cfg)
	if err != nil {
		t.Fatalf("rs.New: %v", err)
	}
	return v
}

// token mints an at+jwt naming s as its issuer.
func (s *issuerServer) token(t *testing.T, f *fixture) string {
	t.Helper()
	claims := baseClaims()
	claims["iss"] = s.srv.URL
	return signJWS(t, josev4.ES256, f.key, primaryKID, "at+jwt", claims)
}

func discoveryDoc(issuer, jwksURI string) string {
	return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, jwksURI)
}

// TestVerifier_DiscoveryHappyPath pins the baseline the failure cases
// below depart from: a document naming this issuer is used.
func TestVerifier_DiscoveryHappyPath(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	s := newIssuerServer(t, f.ks)
	s.discovery = func(issuer string) (int, string) {
		return http.StatusOK, discoveryDoc(issuer, issuer+"/jwks")
	}
	mustVerify(t, s.verifier(t, f.clock), newRequest(t, "Bearer", s.token(t, f)))
}

// TestVerifier_DiscoveryIssuerMismatchIsServerFault: a discovery document
// naming another issuer is refused, and its jwks_uri is never fetched.
func TestVerifier_DiscoveryIssuerMismatchIsServerFault(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	s := newIssuerServer(t, f.ks)
	s.discovery = func(issuer string) (int, string) {
		return http.StatusOK, discoveryDoc("https://attacker.example.com", issuer+"/jwks")
	}
	_, err := s.verifier(t, f.clock).Verify(newRequest(t, "Bearer", s.token(t, f)))
	wantError(t, err, http.StatusServiceUnavailable, "")
	if got := s.jwksHits.Load(); got != 0 {
		t.Fatalf("jwks_uri of a mismatched discovery document fetched %d times, want 0", got)
	}
}

// TestVerifier_DiscoveredEndpointMustPassURLRule: a discovered jwks_uri is
// held to the same scheme rule as a configured one.
func TestVerifier_DiscoveredEndpointMustPassURLRule(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	s := newIssuerServer(t, f.ks)
	s.discovery = func(issuer string) (int, string) {
		return http.StatusOK, discoveryDoc(issuer, "http://issuer.example.com/jwks")
	}
	_, err := s.verifier(t, f.clock).Verify(newRequest(t, "Bearer", s.token(t, f)))
	wantError(t, err, http.StatusServiceUnavailable, "")
}

// TestVerifier_DiscoveryFailureIsRememberedForNegativeTTL: a failed
// discovery is not retried per request until the negative TTL elapses.
func TestVerifier_DiscoveryFailureIsRememberedForNegativeTTL(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	s := newIssuerServer(t, f.ks)
	var healthy atomic.Bool
	s.discovery = func(issuer string) (int, string) {
		if !healthy.Load() {
			return http.StatusInternalServerError, `{}`
		}
		return http.StatusOK, discoveryDoc(issuer, issuer+"/jwks")
	}
	v := s.verifier(t, f.clock)
	raw := s.token(t, f)

	for range 3 {
		_, err := v.Verify(newRequest(t, "Bearer", raw))
		wantError(t, err, http.StatusServiceUnavailable, "")
	}
	if got := s.discoveryHits.Load(); got != 1 {
		t.Fatalf("discovery fetched %d times inside the negative TTL, want 1", got)
	}

	healthy.Store(true)
	f.clock.Set(testNow.Add(rpjwks.DefaultNegativeTTL))
	claims := baseClaims()
	claims["iss"] = s.srv.URL
	claims["exp"] = testNow.Add(time.Hour).Unix()
	mustVerify(t, v, newRequest(t, "Bearer", signJWS(t, josev4.ES256, f.key, primaryKID, "at+jwt", claims)))
	if got := s.discoveryHits.Load(); got != 2 {
		t.Fatalf("discovery fetched %d times after the negative TTL, want 2", got)
	}
}

func withServerIntrospection(s *issuerServer) func(*rs.Config) {
	return func(c *rs.Config) {
		c.Introspection = &rs.IntrospectionConfig{Endpoint: s.srv.URL + "/introspect", ClientID: "rs", ClientSecret: "rs-secret"}
	}
}

// TestVerifier_IntrospectionProtocolFailureIsServerFault: an introspection
// answer the verifier cannot read is the server's fault (503), never an
// accepted token.
func TestVerifier_IntrospectionProtocolFailureIsServerFault(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"not json":          `<html>maintenance</html>`,
		"malformed claims":  `{"active":true,"exp":"soon"}`,
		"active not a bool": `{"active":"true"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			s := newIssuerServer(t, f.ks)
			s.introspection = func() string { return body }
			_, err := s.verifier(t, f.clock, withServerIntrospection(s)).Verify(newRequest(t, "Bearer", "opaque-token"))
			wantError(t, err, http.StatusServiceUnavailable, "")
		})
	}
}

// TestVerifier_IntrospectedTokenObeysClaimRules: an active introspection
// answer still passes the iss, aud and exp rules a JWT does.
func TestVerifier_IntrospectedTokenObeysClaimRules(t *testing.T) {
	t.Parallel()

	active := func(iss, aud string, exp int64) string {
		return fmt.Sprintf(`{"active":true,"iss":%q,"aud":%q,"sub":"user-1","client_id":"client-1","exp":%d,"iat":%d}`,
			iss, aud, exp, testNow.Add(-time.Minute).Unix())
	}
	cases := []struct {
		name string
		body func(issuer string) string
		ok   bool
	}{
		{"valid", func(iss string) string { return active(iss, testAudience, testNow.Add(time.Hour).Unix()) }, true},
		{"other issuer", func(string) string {
			return active("https://other.example.com", testAudience, testNow.Add(time.Hour).Unix())
		}, false},
		{"other audience", func(iss string) string {
			return active(iss, "https://other.example.com/api", testNow.Add(time.Hour).Unix())
		}, false},
		{"expired", func(iss string) string { return active(iss, testAudience, testNow.Unix()) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			s := newIssuerServer(t, f.ks)
			s.introspection = func() string { return tc.body(s.srv.URL) }
			_, err := s.verifier(t, f.clock, withServerIntrospection(s)).Verify(newRequest(t, "Bearer", "opaque-token"))
			if tc.ok {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			wantError(t, err, http.StatusUnauthorized, "invalid_token")
		})
	}
}

// countingJTIs records how many times Mark is called.
type countingJTIs struct {
	store.ConsumedJTIStore
	marks atomic.Int32
	fail  error
}

func (c *countingJTIs) Mark(ctx context.Context, jti string, expiresAt time.Time) error {
	c.marks.Add(1)
	if c.fail != nil {
		return c.fail
	}
	return c.ConsumedJTIStore.Mark(ctx, jti, expiresAt)
}

// TestVerifier_DPoPSharedReplayStoreSpansInstances: two verifiers sharing
// Config.DPoPReplay detect a proof replayed against the other instance.
func TestVerifier_DPoPSharedReplayStoreSpansInstances(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
	shared := inmem.New(inmem.WithClock(f.clock)).ConsumedJTIs()
	withShared := func(c *rs.Config) { c.DPoPReplay = shared }
	a, b := f.verifier(t, withShared), f.verifier(t, withShared)

	proof := key.proof(t, http.MethodGet, resourceURL, testNow, raw)
	first := newRequest(t, "DPoP", raw)
	first.Header.Set("DPoP", proof)
	mustVerify(t, a, first)

	replay := newRequest(t, "DPoP", raw)
	replay.Header.Set("DPoP", proof)
	_, err := b.Verify(replay)
	wantError(t, err, http.StatusUnauthorized, "invalid_dpop_proof")
}

// TestVerifier_DPoPWrongKeyProofConsumesNothing: a proof by a key the
// token is not bound to is refused before its jti is recorded.
func TestVerifier_DPoPWrongKeyProofConsumesNothing(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
	jtis := &countingJTIs{ConsumedJTIStore: inmem.New(inmem.WithClock(f.clock)).ConsumedJTIs()}
	v := f.verifier(t, func(c *rs.Config) { c.DPoPReplay = jtis })

	req := newRequest(t, "DPoP", raw)
	req.Header.Set("DPoP", newProofKey(t, josev4.ES256).proof(t, http.MethodGet, resourceURL, testNow, raw))
	_, err := v.Verify(req)
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
	if got := jtis.marks.Load(); got != 0 {
		t.Fatalf("replay store written %d times for a wrong-key proof, want 0", got)
	}
}

// TestVerifier_DPoPReplayStoreFaultIsServerFault: a replay store that
// cannot record the proof fails closed with 503.
func TestVerifier_DPoPReplayStoreFaultIsServerFault(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
	jtis := &countingJTIs{
		ConsumedJTIStore: inmem.New(inmem.WithClock(f.clock)).ConsumedJTIs(),
		fail:             errors.New("replay store unreachable"),
	}
	v := f.verifier(t, func(c *rs.Config) { c.DPoPReplay = jtis })

	req := newRequest(t, "DPoP", raw)
	req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, testNow, raw))
	_, err := v.Verify(req)
	wantError(t, err, http.StatusServiceUnavailable, "")
}

// TestVerifier_FailureExitsMapToStatus enumerates the verifier's discovery,
// jwks_uri and introspection failure exits: a server fault is 503, an
// inactive token is 401 invalid_token, and none is ever accepted.
func TestVerifier_FailureExitsMapToStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		discovery     func(issuer string) (int, string)
		introspection string
		introStatus   int
		viaDiscovery  bool // introspection endpoint comes from discovery
		jwt           bool
		wantStatus    int
		wantCode      string
	}{
		{name: "introspection 500", introspection: `{}`, introStatus: http.StatusInternalServerError, wantStatus: http.StatusServiceUnavailable},
		{name: "introspection 401", introspection: `{}`, introStatus: http.StatusUnauthorized, wantStatus: http.StatusServiceUnavailable},
		{name: "introspection inactive", introspection: `{"active":false}`, wantStatus: http.StatusUnauthorized, wantCode: "invalid_token"},
		{
			name: "discovery not json", jwt: true,
			discovery:  func(string) (int, string) { return http.StatusOK, `not json` },
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "discovery without jwks_uri", jwt: true,
			discovery:  func(issuer string) (int, string) { return http.StatusOK, discoveryDoc(issuer, "") },
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "discovery without introspection_endpoint", viaDiscovery: true,
			discovery:  func(issuer string) (int, string) { return http.StatusOK, discoveryDoc(issuer, issuer+"/jwks") },
			wantStatus: http.StatusServiceUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			s := newIssuerServer(t, f.ks)
			s.discovery = tc.discovery
			s.introspection = func() string { return tc.introspection }
			s.introspectionStatus = tc.introStatus
			var mutate []func(*rs.Config)
			if tc.viaDiscovery {
				mutate = append(mutate, func(c *rs.Config) {
					c.Introspection = &rs.IntrospectionConfig{ClientID: "rs", ClientSecret: "rs-secret"}
				})
			} else if !tc.jwt {
				mutate = append(mutate, withServerIntrospection(s))
			}
			raw := "opaque-token"
			if tc.jwt {
				raw = s.token(t, f)
			}
			_, err := s.verifier(t, f.clock, mutate...).Verify(newRequest(t, "Bearer", raw))
			wantError(t, err, tc.wantStatus, tc.wantCode)
		})
	}
}
