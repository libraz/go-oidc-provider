package scenarios_test

// Catalog: test/scenarios/catalog/ssf.yaml (SSF-NNN)
// Spec:
//   - OpenID Shared Signals Framework 1.0
//   - OpenID CAEP 1.0, CAEP Interoperability Profile 1.0
//   - RFC 8417 (SET), RFC 8935 (push), RFC 8936 (poll)
//   - RFC 8414 (path-form well-known), RFC 6750 §3.1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	ssfRxA = "ssf-rx-a"
	ssfRxB = "ssf-rx-b"
	//nolint:gosec // opaque test fixture secret, not a credential.
	ssfSecret      = "ssf-scenario-receiver-secret"
	ssfRedirectURI = "https://rp.testkit.invalid/callback"

	ssfEvSessionRevoked   = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	ssfEvCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec // event type URI.
	ssfEvStreamUpdated    = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
	ssfEvVerification     = "https://schemas.openid.net/secevent/ssf/event-type/verification"

	ssfPushMethod = "urn:ietf:rfc:8935"

	// ssfPushWait bounds one push wait. The delivery worker ticks every
	// five seconds, so this spans several ticks.
	ssfPushWait = 20 * time.Second
)

// newSSFProvider builds an OP with the transmitter on and two receiver
// clients (both may use ssf.read and ssf.manage).
func newSSFProvider(t *testing.T, extra ...op.Option) *testkit.Provider {
	t.Helper()
	opts := append([]op.Option{scenariokit.WithClientCredentials(), op.WithSharedSignals()}, extra...)
	return newSSFProviderOpts(t, true, opts...)
}

func newSSFProviderOpts(t *testing.T, shutdown bool, opts ...op.Option) *testkit.Provider {
	t.Helper()
	return newSSFProviderWith(t, shutdown, []testkit.Option{testkit.WithOptions(opts...)})
}

// newSSFProviderWith is [newSSFProviderOpts] taking testkit options, for a
// row that also controls the clock.
func newSSFProviderWith(t *testing.T, shutdown bool, tkOpts []testkit.Option) *testkit.Provider {
	t.Helper()
	tk := testkit.NewProvider(t, tkOpts...)
	if shutdown {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := tk.OP.Shutdown(ctx); err != nil {
				t.Errorf("Shutdown: %v", err)
			}
		})
	}
	hash, err := op.HashClientSecret(ssfSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	for _, id := range []string{ssfRxA, ssfRxB} {
		tk.RegisterClient(t, testkit.ClientFixture{
			ID:                      id,
			SecretHash:              hash,
			RedirectURIs:            []string{ssfRedirectURI},
			Scopes:                  []string{"openid", "profile", "ssf.read", "ssf.manage"},
			GrantTypes:              []string{"authorization_code", "client_credentials"},
			TokenEndpointAuthMethod: "client_secret_basic",
		})
	}
	return tk
}

// ssfReq sends one request to the testkit server. A nil bearer sends no
// Authorization header. A body is JSON-encoded unless it is a []byte,
// which is sent verbatim.
func ssfReq(t *testing.T, tk *testkit.Provider, method, path string, bearer *string, body any) (int, map[string]any, []byte) {
	t.Helper()
	var rd io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, tk.Server.URL+path, rd)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != nil {
		req.Header.Set("Authorization", "Bearer "+*bearer)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(raw) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode %s %s body %q: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode, out, raw
}

func ssfDoJSON(t *testing.T, tk *testkit.Provider, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	status, out, _ := ssfReq(t, tk, method, path, &bearer, body)
	return status, out
}

// ssfTokenFor obtains a client_credentials access token with scope.
func ssfTokenFor(t *testing.T, tk *testkit.Provider, clientID, scope string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, ssfSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /token: %v", err)
	}
	tok, _ := out["access_token"].(string)
	if resp.StatusCode != http.StatusOK || tok == "" {
		t.Fatalf("client_credentials %q for %s: status=%d body=%v", scope, clientID, resp.StatusCode, out)
	}
	return tok
}

func ssfManageToken(t *testing.T, tk *testkit.Provider, clientID string) string {
	t.Helper()
	return ssfTokenFor(t, tk, clientID, "ssf.manage ssf.read")
}

func ssfCreateStream(t *testing.T, tk *testkit.Provider, token string, body map[string]any) string {
	t.Helper()
	status, resp := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/streams", token, body)
	id, _ := resp["stream_id"].(string)
	if status != http.StatusCreated || id == "" {
		t.Fatalf("create stream: status=%d body=%v", status, resp)
	}
	return id
}

func ssfSeedGrant(t *testing.T, tk *testkit.Provider, subject, clientID string) {
	t.Helper()
	if err := tk.Store.Grants().Save(context.Background(), &store.Grant{
		ID:       "grant-" + subject + "-" + clientID,
		Subject:  subject,
		ClientID: clientID,
		Scope:    []string{"openid"},
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// ssfVerifySET verifies set against the OP's published JWKS and returns
// its claims, failing on the structural SET rules shared by every event.
func ssfVerifySET(t *testing.T, tk *testkit.Provider, set string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSignedCompact(set, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse SET: %v", err)
	}
	if typ, _ := jws.Signatures[0].Protected.ExtraHeaders["typ"].(string); typ != "secevent+jwt" {
		t.Fatalf("SET typ = %q, want secevent+jwt", typ)
	}
	jwksReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tk.Server.URL+"/oidc/jwks", nil)
	if err != nil {
		t.Fatalf("build jwks request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(jwksReq)
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	keys := jwks.Key(jws.Signatures[0].Protected.KeyID)
	if len(keys) == 0 {
		t.Fatalf("SET kid %q not in the OP JWKS", jws.Signatures[0].Protected.KeyID)
	}
	payload, err := jws.Verify(keys[0])
	if err != nil {
		t.Fatalf("SET does not verify with the OP JWKS: %v", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode SET claims: %v", err)
	}
	if _, ok := claims["sub"]; ok {
		t.Errorf("SET carries sub: %v", claims)
	}
	if _, ok := claims["exp"]; ok {
		t.Errorf("SET carries exp: %v", claims)
	}
	if claims["iss"] != tk.Issuer {
		t.Errorf("SET iss = %v, want %s", claims["iss"], tk.Issuer)
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Errorf("SET has no jti: %v", claims)
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("SET has no numeric iat: %v", claims)
	}
	if events, _ := claims["events"].(map[string]any); len(events) != 1 {
		t.Errorf("SET carries %d events, want exactly 1: %v", len(events), claims["events"])
	}
	return claims
}

// ssfEventOf returns the single event type and payload of a SET.
func ssfEventOf(claims map[string]any) (string, map[string]any) {
	events, _ := claims["events"].(map[string]any)
	for typ, payload := range events {
		p, _ := payload.(map[string]any)
		return typ, p
	}
	return "", nil
}

func ssfWantIssSub(t *testing.T, tk *testkit.Provider, claims map[string]any, sub string) {
	t.Helper()
	subID, _ := claims["sub_id"].(map[string]any)
	if subID["format"] != "iss_sub" || subID["iss"] != tk.Issuer || subID["sub"] != sub {
		t.Errorf("sub_id = %v, want iss_sub{iss=%s, sub=%s}", subID, tk.Issuer, sub)
	}
}

// ssfPoll polls the stream once and returns the verified SETs by event
// type (the last one wins when a type repeats, so count with the jtis or
// [ssfPollExact]) plus the raw response.
// ack is sent verbatim; the jtis seen are returned for the caller to ack.
func ssfPoll(t *testing.T, tk *testkit.Provider, token, streamID string, body map[string]any) (map[string]map[string]any, []string, map[string]any) {
	t.Helper()
	status, resp := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/poll/"+streamID, token, body)
	if status != http.StatusOK {
		t.Fatalf("poll status=%d body=%v", status, resp)
	}
	sets, _ := resp["sets"].(map[string]any)
	byType := map[string]map[string]any{}
	jtis := make([]string, 0, len(sets))
	for jti, raw := range sets {
		jtis = append(jtis, jti)
		claims := ssfVerifySET(t, tk, raw.(string))
		if claims["jti"] != jti {
			t.Errorf("poll key %q != SET jti %v", jti, claims["jti"])
		}
		typ, _ := ssfEventOf(claims)
		byType[typ] = claims
	}
	return byType, jtis, resp
}

// ssfPollExact polls once with returnImmediately and fails unless exactly
// want SETs come back, counted by jti so a duplicate of one event type is
// seen. The by-type map is for reading a SET's content, never for counting.
func ssfPollExact(t *testing.T, tk *testkit.Provider, token, streamID string, want int) (map[string]map[string]any, []string) {
	t.Helper()
	byType, jtis, _ := ssfPoll(t, tk, token, streamID, map[string]any{"returnImmediately": true})
	if len(jtis) != want {
		t.Fatalf("poll of %s returned %d SETs %v, want %d", streamID, len(jtis), byType, want)
	}
	return byType, jtis
}

// ssfDrain polls with returnImmediately and acks everything, leaving the
// stream's queue empty (the creation-time verification, typically).
func ssfDrain(t *testing.T, tk *testkit.Provider, token, streamID string) {
	t.Helper()
	_, jtis, _ := ssfPoll(t, tk, token, streamID, map[string]any{"returnImmediately": true})
	_, _, _ = ssfPoll(t, tk, token, streamID, map[string]any{"returnImmediately": true, "maxEvents": 0, "ack": jtis})
}

func ssfEmitCredentialChange(t *testing.T, tk *testkit.Provider, subject string) {
	t.Helper()
	if err := tk.OP.EmitSecurityEvent(context.Background(), op.CredentialChange{
		Subject:        subject,
		CredentialType: op.CredentialTypePassword,
		ChangeType:     op.CredentialChangeUpdate,
	}); err != nil {
		t.Fatalf("EmitSecurityEvent: %v", err)
	}
}

// ssfPushReceiver is an RFC 8935 receiver recording every SET and the
// Authorization header it arrived with, answering 202.
type ssfPushReceiver struct {
	server *httptest.Server
	sets   chan string

	mu   sync.Mutex
	auth []string
}

func newSSFPushReceiver(t *testing.T) *ssfPushReceiver {
	t.Helper()
	rx := &ssfPushReceiver{sets: make(chan string, 32)}
	rx.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/secevent+jwt" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rx.mu.Lock()
		rx.auth = append(rx.auth, r.Header.Get("Authorization"))
		rx.mu.Unlock()
		rx.sets <- string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(rx.server.Close)
	return rx
}

// await returns the first pushed SET carrying eventType, skipping others.
func (rx *ssfPushReceiver) await(t *testing.T, tk *testkit.Provider, eventType string) map[string]any {
	t.Helper()
	deadline := time.NewTimer(ssfPushWait)
	defer deadline.Stop()
	for {
		select {
		case set := <-rx.sets:
			claims := ssfVerifySET(t, tk, set)
			if typ, _ := ssfEventOf(claims); typ == eventType {
				return claims
			}
		case <-deadline.C:
			t.Fatalf("no %s SET pushed within %s", eventType, ssfPushWait)
			return nil
		}
	}
}

func (rx *ssfPushReceiver) authHeaders() []string {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	return append([]string(nil), rx.auth...)
}

// TestScenario_SSF_001_MetadataDocument pins the transmitter metadata at
// the issuer-rooted well-known path, outside the mount prefix.
func TestScenario_SSF_001_MetadataDocument(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	status, doc, _ := ssfReq(t, tk, http.MethodGet, "/.well-known/ssf-configuration", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("metadata status=%d", status)
	}
	for k, want := range map[string]string{
		"spec_version":           "1_0",
		"issuer":                 tk.Issuer,
		"jwks_uri":               tk.Issuer + "/oidc/jwks",
		"configuration_endpoint": tk.Issuer + "/oidc/ssf/streams",
		"status_endpoint":        tk.Issuer + "/oidc/ssf/status",
		"verification_endpoint":  tk.Issuer + "/oidc/ssf/verify",
		"default_subjects":       "ALL",
	} {
		if doc[k] != want {
			t.Errorf("metadata %s = %v, want %s", k, doc[k], want)
		}
	}
	for _, key := range []string{"delivery_methods_supported", "authorization_schemes"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("metadata has no %s: %v", key, doc)
		}
	}
	methods := ssfStrings(doc["delivery_methods_supported"])
	if !slices.Contains(methods, ssfPushMethod) || !slices.Contains(methods, "urn:ietf:rfc:8936") {
		t.Errorf("delivery_methods_supported = %v, want push and poll", methods)
	}
	schemes, _ := doc["authorization_schemes"].([]any)
	if len(schemes) != 1 || schemes[0].(map[string]any)["spec_urn"] != "urn:ietf:rfc:6749" {
		t.Errorf("authorization_schemes = %v, want one urn:ietf:rfc:6749 scheme", schemes)
	}

	// The metadata is not an OIDC discovery member.
	status, disc, _ := ssfReq(t, tk, http.MethodGet, "/oidc/.well-known/openid-configuration", nil, nil)
	if status == http.StatusOK {
		for k := range disc {
			if strings.Contains(k, "ssf") {
				t.Errorf("OIDC discovery advertises %q", k)
			}
		}
	}
}

func ssfStrings(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestScenario_SSF_002_MetadataPathIssuer pins the RFC 8414 form: the
// issuer path is appended after the well-known segment and the bare form
// is not served.
func TestScenario_SSF_002_MetadataPathIssuer(t *testing.T) {
	t.Parallel()
	const issuer = "https://op.testkit.invalid/tenant-a"
	tk := testkit.NewProvider(t, testkit.WithIssuer(issuer), testkit.WithOptions(op.WithSharedSignals()))
	t.Cleanup(func() { _ = tk.OP.Shutdown(context.Background()) })

	status, doc, _ := ssfReq(t, tk, http.MethodGet, "/.well-known/ssf-configuration/tenant-a", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("path-form metadata status=%d, want 200", status)
	}
	if doc["issuer"] != issuer || doc["spec_version"] != "1_0" {
		t.Errorf("metadata issuer=%v spec_version=%v, want %s / 1_0", doc["issuer"], doc["spec_version"], issuer)
	}
	if status, _, _ := ssfReq(t, tk, http.MethodGet, "/.well-known/ssf-configuration", nil, nil); status != http.StatusNotFound {
		t.Errorf("bare well-known status=%d, want 404 for a path issuer", status)
	}
}

// TestScenario_SSF_003_DisabledByDefault pins that without
// op.WithSharedSignals no transmitter route exists.
func TestScenario_SSF_003_DisabledByDefault(t *testing.T) {
	t.Parallel()
	tk := testkit.NewProvider(t)
	for _, path := range []string{"/.well-known/ssf-configuration", "/oidc/ssf/streams", "/oidc/ssf/status", "/oidc/ssf/verify", "/oidc/ssf/poll/x"} {
		if status, _, _ := ssfReq(t, tk, http.MethodGet, path, nil, nil); status != http.StatusNotFound {
			t.Errorf("GET %s status=%d, want 404", path, status)
		}
	}
}

// TestScenario_SSF_010_CreateStream pins creation: 201 with a generated
// stream_id, aud equal to the receiver client_id, a second stream refused
// with 409, and the authorization header never echoed.
func TestScenario_SSF_010_CreateStream(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t, op.WithAllowInsecureOutboundForDev(op.OutboundSharedSignals))
	token := ssfManageToken(t, tk, ssfRxA)

	status, created, raw := ssfReq(t, tk, http.MethodPost, "/oidc/ssf/streams", &token, map[string]any{
		"delivery": map[string]any{
			"method":               ssfPushMethod,
			"endpoint_url":         "http://127.0.0.1:9/push",
			"authorization_header": "Bearer receiver-secret-value",
		},
		"events_requested": []string{ssfEvSessionRevoked, "https://example.invalid/unknown-event"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", status, raw)
	}
	if id, _ := created["stream_id"].(string); id == "" {
		t.Errorf("no stream_id: %v", created)
	}
	if created["aud"] != ssfRxA || created["iss"] != tk.Issuer {
		t.Errorf("aud=%v iss=%v, want %s / %s", created["aud"], created["iss"], ssfRxA, tk.Issuer)
	}
	if delivered := ssfStrings(created["events_delivered"]); len(delivered) != 1 || delivered[0] != ssfEvSessionRevoked {
		t.Errorf("events_delivered = %v, want only the supported requested event", delivered)
	}
	if strings.Contains(string(raw), "receiver-secret-value") {
		t.Errorf("create response echoes the authorization header: %s", raw)
	}

	status, again := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/streams", token, map[string]any{})
	if status != http.StatusConflict {
		t.Errorf("second create status=%d body=%v, want 409", status, again)
	}

	_, _, got := ssfReq(t, tk, http.MethodGet, "/oidc/ssf/streams", &token, nil)
	if strings.Contains(string(got), "receiver-secret-value") || !strings.HasPrefix(string(got), "[") {
		t.Errorf("GET without stream_id = %s, want an array without the authorization header", got)
	}
}

// TestScenario_SSF_011_StreamIsolation pins that a receiver cannot see,
// poll, change or delete another receiver's stream, and cannot tell it
// exists.
func TestScenario_SSF_011_StreamIsolation(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	tokenA := ssfManageToken(t, tk, ssfRxA)
	tokenB := ssfManageToken(t, tk, ssfRxB)
	id := ssfCreateStream(t, tk, tokenA, map[string]any{})

	q := "?stream_id=" + url.QueryEscape(id)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/oidc/ssf/streams" + q, nil},
		{http.MethodPatch, "/oidc/ssf/streams", map[string]any{"stream_id": id, "description": "x"}},
		{http.MethodPut, "/oidc/ssf/streams", map[string]any{"stream_id": id}},
		{http.MethodDelete, "/oidc/ssf/streams" + q, nil},
		{http.MethodGet, "/oidc/ssf/status" + q, nil},
		{http.MethodPost, "/oidc/ssf/status", map[string]any{"stream_id": id, "status": "disabled"}},
		{http.MethodPost, "/oidc/ssf/verify", map[string]any{"stream_id": id, "state": "s"}},
		{http.MethodPost, "/oidc/ssf/poll/" + id, map[string]any{"returnImmediately": true}},
	} {
		if status, body := ssfDoJSON(t, tk, c.method, c.path, tokenB, c.body); status != http.StatusNotFound {
			t.Errorf("%s %s by the other receiver: status=%d body=%v, want 404", c.method, c.path, status, body)
		}
	}

	// A stream_id that never existed is indistinguishable from the foreign one.
	status, _ := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/streams?stream_id=no-such-stream", tokenB, nil)
	if status != http.StatusNotFound {
		t.Errorf("unknown stream_id status=%d, want 404", status)
	}
	// Receiver B owns no stream, so listing yields an empty array, and A's stream is intact.
	if _, _, raw := ssfReq(t, tk, http.MethodGet, "/oidc/ssf/streams", &tokenB, nil); strings.TrimSpace(string(raw)) != "[]" {
		t.Errorf("other receiver's list = %s, want []", raw)
	}
	if status, got := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/streams"+q, tokenA, nil); status != http.StatusOK || got["stream_id"] != id {
		t.Errorf("owner read after foreign attempts: status=%d body=%v", status, got)
	}
}

// TestScenario_SSF_012_ScopeAndBearer pins the authorization table: no
// token is 401 with a Bearer challenge, ssf.read can read but not change,
// and a token without any ssf scope is refused.
func TestScenario_SSF_012_ScopeAndBearer(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	manage := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, manage, map[string]any{})
	read := ssfTokenFor(t, tk, ssfRxA, "ssf.read")
	hash, err := op.HashClientSecret(ssfSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID: "ssf-rx-noscope", SecretHash: hash, RedirectURIs: []string{ssfRedirectURI},
		Scopes: []string{"openid"}, GrantTypes: []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	none := ssfTokenFor(t, tk, "ssf-rx-noscope", "")

	status, _, _ := ssfReq(t, tk, http.MethodGet, "/oidc/ssf/streams", nil, nil)
	if status != http.StatusUnauthorized {
		t.Errorf("no token status=%d, want 401", status)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+"/oidc/ssf/streams", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if ch := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(ch, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", ch)
	}

	if status, body := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/streams?stream_id="+id, read, nil); status != http.StatusOK || body["stream_id"] != id {
		t.Errorf("ssf.read GET: status=%d body=%v, want 200 for the owned stream", status, body)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/oidc/ssf/streams", map[string]any{}},
		{http.MethodPatch, "/oidc/ssf/streams", map[string]any{"stream_id": id, "description": "x"}},
		{http.MethodPut, "/oidc/ssf/streams", map[string]any{"stream_id": id}},
		{http.MethodDelete, "/oidc/ssf/streams?stream_id=" + id, nil},
		{http.MethodPost, "/oidc/ssf/status", map[string]any{"stream_id": id, "status": "paused"}},
		{http.MethodPost, "/oidc/ssf/verify", map[string]any{"stream_id": id, "state": "s"}},
	} {
		if status, body := ssfDoJSON(t, tk, c.method, c.path, read, c.body); status != http.StatusForbidden {
			t.Errorf("ssf.read %s %s: status=%d body=%v, want 403", c.method, c.path, status, body)
		}
	}
	if status, _ := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/streams", none, nil); status != http.StatusForbidden && status != http.StatusUnauthorized {
		t.Errorf("token without ssf scope status=%d, want 401 or 403", status)
	}
	// The stream survived every refused write.
	if status, body := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/status?stream_id="+id, manage, nil); status != http.StatusOK || body["status"] != "enabled" {
		t.Errorf("status after refused writes: %d %v, want enabled", status, body)
	}
}

// TestScenario_SSF_013_PatchAndPut pins PATCH (only the named members
// change) against PUT (omitted members are dropped) and the recomputation
// of events_delivered.
func TestScenario_SSF_013_PatchAndPut(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{
		"description":      "first",
		"events_requested": []string{ssfEvSessionRevoked},
	})

	status, patched := ssfDoJSON(t, tk, http.MethodPatch, "/oidc/ssf/streams", token, map[string]any{"stream_id": id, "description": "second"})
	if status != http.StatusOK || patched["description"] != "second" {
		t.Fatalf("PATCH description: status=%d body=%v", status, patched)
	}
	if got := ssfStrings(patched["events_requested"]); len(got) != 1 || got[0] != ssfEvSessionRevoked {
		t.Errorf("PATCH changed events_requested to %v", got)
	}

	status, patched = ssfDoJSON(t, tk, http.MethodPatch, "/oidc/ssf/streams", token, map[string]any{
		"stream_id": id, "events_requested": []string{ssfEvCredentialChange},
	})
	if status != http.StatusOK {
		t.Fatalf("PATCH events_requested: status=%d body=%v", status, patched)
	}
	if got := ssfStrings(patched["events_delivered"]); len(got) != 1 || got[0] != ssfEvCredentialChange {
		t.Errorf("events_delivered after PATCH = %v, want [%s]", got, ssfEvCredentialChange)
	}
	if patched["description"] != "second" {
		t.Errorf("PATCH of events_requested dropped description: %v", patched["description"])
	}

	status, put := ssfDoJSON(t, tk, http.MethodPut, "/oidc/ssf/streams", token, map[string]any{
		"stream_id": id, "events_requested": []string{ssfEvSessionRevoked, ssfEvCredentialChange},
	})
	if status != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%v", status, put)
	}
	if d, _ := put["description"].(string); d != "" {
		t.Errorf("PUT kept the omitted description %q", d)
	}
	if got := ssfStrings(put["events_delivered"]); len(got) != 2 {
		t.Errorf("events_delivered after PUT = %v, want both events", got)
	}

	// Unknown URIs alone are accepted and deliver nothing.
	status, none := ssfDoJSON(t, tk, http.MethodPatch, "/oidc/ssf/streams", token, map[string]any{
		"stream_id": id, "events_requested": []string{"https://example.invalid/unknown"},
	})
	if status != http.StatusOK || len(ssfStrings(none["events_delivered"])) != 0 {
		t.Errorf("unknown-only events_requested: status=%d events_delivered=%v, want 200 and empty", status, none["events_delivered"])
	}
}

// TestScenario_SSF_014_ImmutableMembers pins that members the receiver
// may not set are refused with 400 and leave the stream unchanged.
func TestScenario_SSF_014_ImmutableMembers(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{"events_requested": []string{ssfEvSessionRevoked}})

	for name, body := range map[string]map[string]any{
		"events_delivered differs": {"stream_id": id, "events_delivered": []string{ssfEvCredentialChange}},
		"aud change":               {"stream_id": id, "aud": "someone-else"},
		"iss change":               {"stream_id": id, "iss": "https://elsewhere.invalid"},
	} {
		for _, method := range []string{http.MethodPatch, http.MethodPut} {
			if status, resp := ssfDoJSON(t, tk, method, "/oidc/ssf/streams", token, body); status != http.StatusBadRequest {
				t.Errorf("%s %s: status=%d body=%v, want 400", method, name, status, resp)
			}
		}
	}
	status, got := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/streams?stream_id="+id, token, nil)
	if status != http.StatusOK || got["aud"] != ssfRxA || got["iss"] != tk.Issuer {
		t.Errorf("stream after refused updates: status=%d body=%v", status, got)
	}
}

// TestScenario_SSF_015_InputBoundaries pins the request-shape edges of
// stream creation.
func TestScenario_SSF_015_InputBoundaries(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t) // no dev option: http push targets are refused
	token := ssfManageToken(t, tk, ssfRxA)

	for name, body := range map[string][]byte{
		"malformed JSON":       []byte(`{"description":`),
		"trailing garbage":     []byte(`{} trailing`),
		"unknown method":       []byte(`{"delivery":{"method":"urn:example:carrier-pigeon"}}`),
		"push without url":     []byte(`{"delivery":{"method":"` + ssfPushMethod + `"}}`),
		"http push no dev opt": []byte(`{"delivery":{"method":"` + ssfPushMethod + `","endpoint_url":"http://receiver.example.com/push"}}`),
		"url with userinfo":    []byte(`{"delivery":{"method":"` + ssfPushMethod + `","endpoint_url":"https://u:p@receiver.example.com/push"}}`),
		"url with fragment":    []byte(`{"delivery":{"method":"` + ssfPushMethod + `","endpoint_url":"https://receiver.example.com/push#f"}}`),
		"private IP literal":   []byte(`{"delivery":{"method":"` + ssfPushMethod + `","endpoint_url":"https://10.0.0.5/push"}}`),
		"authorization 4KiB+":  []byte(`{"delivery":{"method":"` + ssfPushMethod + `","endpoint_url":"https://receiver.example.com/push","authorization_header":"` + strings.Repeat("a", 4097) + `"}}`),
	} {
		if status, _, raw := ssfReq(t, tk, http.MethodPost, "/oidc/ssf/streams", &token, body); status != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s, want 400", name, status, raw)
		}
	}
	if status, _, _ := ssfReq(t, tk, http.MethodPost, "/oidc/ssf/streams", &token, []byte(`{"description":"`+strings.Repeat("a", 70*1024)+`"}`)); status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body status=%d, want 413", status)
	}

	// None of the refusals created a stream, so the receiver's empty-body
	// create still succeeds and yields a poll stream.
	status, created, raw := ssfReq(t, tk, http.MethodPost, "/oidc/ssf/streams", &token, []byte(``))
	if status != http.StatusCreated {
		t.Fatalf("empty-body create status=%d body=%s", status, raw)
	}
	if d, _ := created["delivery"].(map[string]any); d["method"] != "urn:ietf:rfc:8936" {
		t.Errorf("default delivery = %v, want poll", created["delivery"])
	}
	id, _ := created["stream_id"].(string)

	long := strings.Repeat("a", 300)
	status, patched := ssfDoJSON(t, tk, http.MethodPatch, "/oidc/ssf/streams", token, map[string]any{"stream_id": id, "description": long})
	if desc, _ := patched["description"].(string); status != http.StatusOK || utf8.RuneCountInString(desc) != 256 {
		t.Errorf("long description: status=%d length=%d, want 200 truncated to 256", status, utf8.RuneCountInString(desc))
	}
	status, patched = ssfDoJSON(t, tk, http.MethodPatch, "/oidc/ssf/streams", token, map[string]any{"stream_id": id, "description": "受信者 A", "unknown_member": 1})
	if status != http.StatusOK || patched["description"] != "受信者 A" {
		t.Errorf("non-ASCII description / unknown member: status=%d body=%v", status, patched)
	}
}

// TestScenario_SSF_016_DeleteStream pins that deletion removes the
// stream and its queue.
func TestScenario_SSF_016_DeleteStream(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{})

	if status, body := ssfDoJSON(t, tk, http.MethodDelete, "/oidc/ssf/streams?stream_id="+id, token, nil); status != http.StatusNoContent {
		t.Fatalf("DELETE status=%d body=%v, want 204", status, body)
	}
	if status, _ := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/streams?stream_id="+id, token, nil); status != http.StatusNotFound {
		t.Errorf("GET deleted stream status=%d, want 404", status)
	}
	if status, _ := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/poll/"+id, token, map[string]any{"returnImmediately": true}); status != http.StatusNotFound {
		t.Errorf("poll deleted stream status=%d, want 404", status)
	}
	// The receiver may create a fresh stream, which starts with its own queue.
	id2 := ssfCreateStream(t, tk, token, map[string]any{})
	if id2 == id {
		t.Errorf("recreated stream reused id %s", id)
	}
	byType, _ := ssfPollExact(t, tk, token, id2, 1)
	if byType[ssfEvVerification] == nil {
		t.Errorf("new stream queue = %v, want only its creation verification", byType)
	}
}

// TestScenario_SSF_020_LogoutPushesSessionRevoked drives RP-Initiated
// Logout and checks the pushed session-revoked SET: signed by the OP
// JWKS, addressed to the receiver, iss_sub of the user, initiating entity
// user, and the receiver's authorization header presented.
func TestScenario_SSF_020_LogoutPushesSessionRevoked(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t, op.WithAllowInsecureOutboundForDev(op.OutboundSharedSignals))
	rx := newSSFPushReceiver(t)
	token := ssfManageToken(t, tk, ssfRxA)
	ssfCreateStream(t, tk, token, map[string]any{
		"delivery": map[string]any{
			"method":               ssfPushMethod,
			"endpoint_url":         rx.server.URL + "/push",
			"authorization_header": "Bearer scenario-rx-token",
		},
		"events_requested": []string{ssfEvSessionRevoked},
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	browser := tk.HTTPClient(jar)
	params := scenariokit.AuthorizeParams{
		ClientID: ssfRxA, RedirectURI: ssfRedirectURI, Scope: "openid profile",
		PKCE: scenariokit.NewPKCEPair(""),
	}
	flow := scenariokit.RunCodeFlowWithClient(t, tk, browser, "alice", params)
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: ssfRedirectURI, Verifier: params.PKCE.Verifier,
		ClientID: ssfRxA, ClientSecret: ssfSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("code exchange: status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	wantSub, _ := scenariokit.DecodeJWSClaims(t, tok.IDToken)["sub"].(string)

	target := tk.Server.URL + "/oidc/end_session?" + url.Values{"id_token_hint": {tok.IDToken}}.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatalf("GET end_session: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("/end_session status=%d", resp.StatusCode)
	}

	claims := rx.await(t, tk, ssfEvSessionRevoked)
	ssfWantIssSub(t, tk, claims, wantSub)
	if claims["aud"] != ssfRxA {
		t.Errorf("aud = %v, want %s", claims["aud"], ssfRxA)
	}
	_, ev := ssfEventOf(claims)
	if ev["initiating_entity"] != "user" {
		t.Errorf("initiating_entity = %v, want user", ev["initiating_entity"])
	}
	if reason, _ := ev["reason_admin"].(map[string]any); len(reason) == 0 {
		t.Errorf("reason_admin empty: %v", ev)
	}
	for _, h := range rx.authHeaders() {
		if h != "Bearer scenario-rx-token" {
			t.Errorf("push Authorization = %q, want the stream's configured header", h)
		}
	}
}

// TestScenario_SSF_021_RevokeSubjectPublishesBeforeGrantRemoval pins the
// order: RevokeSubject announces session-revoked to the receivers holding
// a grant, then removes the grants; an embedder event emitted afterwards
// finds no destination.
func TestScenario_SSF_021_RevokeSubjectPublishesBeforeGrantRemoval(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{
		"events_requested": []string{ssfEvSessionRevoked, ssfEvCredentialChange},
	})
	ssfDrain(t, tk, token, id)

	ssfSeedGrant(t, tk, "bob", ssfRxA)
	if err := tk.OP.RevokeSubject(context.Background(), "bob"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	byType, jtis := ssfPollExact(t, tk, token, id, 1)
	revoked := byType[ssfEvSessionRevoked]
	if revoked == nil {
		t.Fatalf("after RevokeSubject got %v, want exactly one session-revoked", byType)
	}
	ssfWantIssSub(t, tk, revoked, "bob")
	_, ev := ssfEventOf(revoked)
	if _, ok := ev["initiating_entity"]; ok {
		t.Errorf("RevokeSubject session-revoked carries initiating_entity: %v", ev)
	}
	if reason, _ := ev["reason_admin"].(map[string]any); len(reason) == 0 {
		t.Errorf("reason_admin empty: %v", ev)
	}
	_, _, _ = ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true, "maxEvents": 0, "ack": jtis})

	ssfEmitCredentialChange(t, tk, "bob")
	ssfPollExact(t, tk, token, id, 0)
}

// TestScenario_SSF_022_EmitPollAck pins the embedder path: the event
// reaches the poll stream, an unacked SET is returned again, and an acked
// one never is. Also pins the SET claim shape.
func TestScenario_SSF_022_EmitPollAck(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{"events_requested": []string{ssfEvCredentialChange}})
	ssfDrain(t, tk, token, id)

	ssfSeedGrant(t, tk, "carol", ssfRxA)
	ssfEmitCredentialChange(t, tk, "carol")

	byType, jtis := ssfPollExact(t, tk, token, id, 1)
	claims := byType[ssfEvCredentialChange]
	if claims == nil {
		t.Fatalf("first poll = %v, want one credential-change", byType)
	}
	ssfWantIssSub(t, tk, claims, "carol")
	if claims["aud"] != ssfRxA {
		t.Errorf("aud = %v, want %s", claims["aud"], ssfRxA)
	}
	if txn, _ := claims["txn"].(string); txn == "" {
		t.Errorf("no txn: %v", claims)
	}
	_, ev := ssfEventOf(claims)
	if ev["credential_type"] != "password" || ev["change_type"] != "update" {
		t.Errorf("payload = %v, want password / update", ev)
	}
	if _, ok := ev["event_timestamp"].(float64); !ok {
		t.Errorf("no numeric event_timestamp: %v", ev)
	}
	if reason, _ := ev["reason_admin"].(map[string]any); reason["en"] == "" || reason["en"] == nil {
		t.Errorf("default reason_admin missing: %v", ev)
	}

	again, againJTIs, _ := ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true})
	if again[ssfEvCredentialChange] == nil || againJTIs[0] != jtis[0] {
		t.Errorf("unacked SET not returned again with the same jti: %v vs %v", againJTIs, jtis)
	}

	_, _, resp := ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true, "ack": jtis})
	if sets, _ := resp["sets"].(map[string]any); len(sets) != 0 {
		t.Errorf("acked SET returned again: %v", sets)
	}
}

// TestScenario_SSF_023_RecipientSelection pins who receives an event:
// only the receivers whose subject has a grant and whose stream delivers
// that event type.
func TestScenario_SSF_023_RecipientSelection(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	tokenA := ssfManageToken(t, tk, ssfRxA)
	tokenB := ssfManageToken(t, tk, ssfRxB)
	idA := ssfCreateStream(t, tk, tokenA, map[string]any{"events_requested": []string{ssfEvCredentialChange}})
	idB := ssfCreateStream(t, tk, tokenB, map[string]any{"events_requested": []string{ssfEvSessionRevoked}})
	ssfDrain(t, tk, tokenA, idA)
	ssfDrain(t, tk, tokenB, idB)

	// A holds a grant and requested credential-change; B did not request it
	// and a third subject has no grant with A.
	ssfSeedGrant(t, tk, "dave", ssfRxA)
	ssfSeedGrant(t, tk, "dave", ssfRxB)
	ssfSeedGrant(t, tk, "erin", ssfRxB)
	ssfEmitCredentialChange(t, tk, "dave")
	ssfEmitCredentialChange(t, tk, "erin")

	// Exactly one SET, dave's: erin's would be a second credential-change.
	gotA, _ := ssfPollExact(t, tk, tokenA, idA, 1)
	if gotA[ssfEvCredentialChange] == nil {
		t.Fatalf("receiver A got %v, want exactly dave's credential-change", gotA)
	}
	ssfWantIssSub(t, tk, gotA[ssfEvCredentialChange], "dave")
	ssfPollExact(t, tk, tokenB, idB, 0)
}

// TestScenario_SSF_024_PausedHoldsUntilEnabled pins that a paused stream
// holds ordinary events, still delivers the stream-updated notice, and
// releases the held events on enabling.
func TestScenario_SSF_024_PausedHoldsUntilEnabled(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{"events_requested": []string{ssfEvCredentialChange}})
	ssfDrain(t, tk, token, id)
	ssfSeedGrant(t, tk, "frank", ssfRxA)

	if status, body := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/status", token, map[string]any{"stream_id": id, "status": "paused"}); status != http.StatusOK || body["status"] != "paused" {
		t.Fatalf("pause: status=%d body=%v", status, body)
	}
	ssfEmitCredentialChange(t, tk, "frank")

	byType, jtis := ssfPollExact(t, tk, token, id, 1)
	if byType[ssfEvCredentialChange] != nil {
		t.Fatalf("paused stream delivered an ordinary event: %v", byType)
	}
	upd := byType[ssfEvStreamUpdated]
	if upd == nil {
		t.Fatalf("paused stream did not deliver stream-updated: %v", byType)
	}
	if _, p := ssfEventOf(upd); p["status"] != "paused" {
		t.Errorf("stream-updated status = %v, want paused", p["status"])
	}
	if subID, _ := upd["sub_id"].(map[string]any); subID["format"] != "opaque" || subID["id"] != id {
		t.Errorf("stream-updated sub_id = %v, want opaque of the stream id", subID)
	}
	_, _, _ = ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true, "maxEvents": 0, "ack": jtis})

	if status, body := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/status", token, map[string]any{"stream_id": id, "status": "enabled"}); status != http.StatusOK || body["status"] != "enabled" {
		t.Fatalf("enable: status=%d body=%v", status, body)
	}
	byType, _ = ssfPollExact(t, tk, token, id, 2)
	held := byType[ssfEvCredentialChange]
	if held == nil {
		t.Fatalf("enabling did not release the held event: %v", byType)
	}
	ssfWantIssSub(t, tk, held, "frank")
	if _, p := ssfEventOf(byType[ssfEvStreamUpdated]); p["status"] != "enabled" {
		t.Errorf("stream-updated after enabling = %v, want status enabled", byType[ssfEvStreamUpdated])
	}
}

// TestScenario_SSF_025_DisabledDropsButNotifies pins that disabling drops
// queued ordinary events and refuses new ones, while the stream-updated
// notice for the transition is still delivered by poll.
func TestScenario_SSF_025_DisabledDropsButNotifies(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{"events_requested": []string{ssfEvCredentialChange}})
	ssfDrain(t, tk, token, id)
	ssfSeedGrant(t, tk, "gina", ssfRxA)

	ssfEmitCredentialChange(t, tk, "gina") // queued before the transition
	status, body := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/status", token, map[string]any{"stream_id": id, "status": "disabled", "reason": "maintenance"})
	if status != http.StatusOK || body["status"] != "disabled" || body["reason"] != "maintenance" {
		t.Fatalf("disable: status=%d body=%v", status, body)
	}
	ssfEmitCredentialChange(t, tk, "gina") // after the transition

	byType, _ := ssfPollExact(t, tk, token, id, 1)
	if byType[ssfEvCredentialChange] != nil {
		t.Errorf("disabled stream kept or accepted an ordinary event: %v", byType)
	}
	upd := byType[ssfEvStreamUpdated]
	if upd == nil {
		t.Fatalf("disabling did not deliver stream-updated: %v", byType)
	}
	if _, p := ssfEventOf(upd); p["status"] != "disabled" {
		t.Errorf("stream-updated status = %v, want disabled", p["status"])
	}
	if status, got := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/status?stream_id="+id, token, nil); status != http.StatusOK || got["status"] != "disabled" {
		t.Errorf("status read = %d %v, want disabled", status, got)
	}
	if status, _ := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/status", token, map[string]any{"stream_id": id, "status": "archived"}); status != http.StatusBadRequest {
		t.Errorf("unknown status value: status=%d, want 400", status)
	}
}

// TestScenario_SSF_026_Verification pins both verification forms: the
// creation-time one carries no state, a requested one echoes it, and a
// newer request replaces a pending one.
func TestScenario_SSF_026_Verification(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{})

	byType, jtis := ssfPollExact(t, tk, token, id, 1)
	v := byType[ssfEvVerification]
	if v == nil {
		t.Fatalf("creation queue = %v, want one verification", byType)
	}
	if _, p := ssfEventOf(v); p["state"] != nil {
		t.Errorf("creation-time verification carries state %v", p["state"])
	}
	if subID, _ := v["sub_id"].(map[string]any); subID["format"] != "opaque" || subID["id"] != id {
		t.Errorf("verification sub_id = %v, want opaque of the stream id", subID)
	}
	_, _, _ = ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true, "maxEvents": 0, "ack": jtis})

	for _, state := range []string{"first-state", "second-state"} {
		if status, body := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/verify", token, map[string]any{"stream_id": id, "state": state}); status != http.StatusNoContent {
			t.Fatalf("verify %q: status=%d body=%v, want 204", state, status, body)
		}
	}
	byType, _ = ssfPollExact(t, tk, token, id, 1)
	if _, p := ssfEventOf(byType[ssfEvVerification]); p["state"] != "second-state" {
		t.Errorf("queue after two requests = %v, want one verification echoing the newer state", byType)
	}
}

// TestScenario_SSF_027_LongPoll pins RFC 8936 §2.5: with returnImmediately
// false and nothing pending, the request stays open and answers with an
// event that arrives meanwhile. The wait is bounded by the request
// context, not by a fixed sleep.
func TestScenario_SSF_027_LongPoll(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{"events_requested": []string{ssfEvCredentialChange}})
	ssfDrain(t, tk, token, id)
	ssfSeedGrant(t, tk, "hana", ssfRxA)

	// returnImmediately true on an empty queue answers at once with no SETs.
	ssfPollExact(t, tk, token, id, 0)

	type result struct {
		byType map[string]map[string]any
	}
	done := make(chan result, 1)
	go func() {
		status, resp, raw := ssfReq(t, tk, http.MethodPost, "/oidc/ssf/poll/"+id, &token, map[string]any{"returnImmediately": false})
		if status != http.StatusOK {
			t.Errorf("long poll status=%d body=%s", status, raw)
			done <- result{}
			return
		}
		sets, _ := resp["sets"].(map[string]any)
		byType := map[string]map[string]any{}
		for _, s := range sets {
			c := ssfVerifySET(t, tk, s.(string))
			typ, _ := ssfEventOf(c)
			byType[typ] = c
		}
		done <- result{byType}
	}()

	select {
	case r := <-done:
		// Answered before any event existed: only acceptable if it carried one,
		// which cannot happen yet.
		t.Fatalf("long poll answered before an event existed: %v", r.byType)
	case <-time.After(1500 * time.Millisecond):
	}
	ssfEmitCredentialChange(t, tk, "hana")

	select {
	case r := <-done:
		c := r.byType[ssfEvCredentialChange]
		if c == nil {
			t.Fatalf("long poll answered %v, want the emitted credential-change", r.byType)
		}
		ssfWantIssSub(t, tk, c, "hana")
	case <-time.After(15 * time.Second):
		t.Fatal("long poll did not return the event within its bound")
	}
}

// TestScenario_SSF_028_PollRequestShape pins maxEvents handling, the
// more-available flag, ack-only requests and the 400 on malformed members.
func TestScenario_SSF_028_PollRequestShape(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{"events_requested": []string{ssfEvCredentialChange}})
	ssfDrain(t, tk, token, id)
	ssfSeedGrant(t, tk, "ivan", ssfRxA)
	for range 3 {
		ssfEmitCredentialChange(t, tk, "ivan")
	}

	// maxEvents 0 acks only: no SETs are returned and nothing is consumed.
	_, _, resp := ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true, "maxEvents": 0})
	if sets, _ := resp["sets"].(map[string]any); len(sets) != 0 {
		t.Errorf("maxEvents 0 returned %v", sets)
	}

	// maxEvents 2 of 3 returns two and reports more.
	_, jtis, resp := ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true, "maxEvents": 2})
	if len(jtis) != 2 || resp["moreAvailable"] != true {
		t.Fatalf("maxEvents 2: %d sets moreAvailable=%v, want 2 and true", len(jtis), resp["moreAvailable"])
	}
	// Unknown jtis in ack are ignored while the real ones are consumed.
	_, rest, resp := ssfPoll(t, tk, token, id, map[string]any{"returnImmediately": true, "ack": append([]string{"no-such-jti"}, jtis...)})
	if len(rest) != 1 || resp["moreAvailable"] == true {
		t.Errorf("after acking two: %d sets moreAvailable=%v, want the remaining 1 and no more", len(rest), resp["moreAvailable"])
	}

	for name, body := range map[string]map[string]any{
		"negative maxEvents":   {"maxEvents": -1},
		"fractional maxEvents": {"maxEvents": 1.5},
		"string maxEvents":     {"maxEvents": "3"},
		"non-string ack":       {"ack": []any{1}},
		"non-object setErrs":   {"setErrs": map[string]any{"jti": "bad"}},
	} {
		body["returnImmediately"] = true
		if status, got := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/poll/"+id, token, body); status != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%v, want 400", name, status, got)
		}
	}
}
