// Test file pins ID-JAG issuance through token exchange
// (draft-ietf-oauth-identity-assertion-authz-grant §4.3): the
// construction matrix, the request gates, the policy outcome mapping,
// the minted claim set, and the response shape the wire layer writes.
//
//nolint:testpackage // exercises the handler alongside unexported fixtures
package tokenexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

const (
	idjagIssuer   = "https://idp.example"
	idjagClientID = "idp-client"
	idjagSubject  = "user-1"
	idjagAudience = "https://ras.example"
	idjagGrantID  = "grant-idjag"
	idjagRASID    = "ras-client-7"
)

// idjagGrantStore answers the two reads the ID-JAG path makes: the
// consent lookup behind the id_token and the lineage lookup by grant ID.
type idjagGrantStore struct {
	grant *store.Grant
}

func (s idjagGrantStore) Save(context.Context, *store.Grant) error {
	panic("idjagGrantStore.Save should not be reached")
}

func (s idjagGrantStore) Find(_ context.Context, id string) (*store.Grant, error) {
	if s.grant == nil || s.grant.ID != id {
		return nil, store.ErrNotFound
	}
	return s.grant, nil
}

func (s idjagGrantStore) FindBySubjectClient(_ context.Context, subject, clientID string) (*store.Grant, error) {
	if s.grant == nil || s.grant.Subject != subject || s.grant.ClientID != clientID {
		return nil, store.ErrNotFound
	}
	return s.grant, nil
}

func (s idjagGrantStore) ListBySubject(context.Context, string) ([]*store.Grant, error) {
	panic("idjagGrantStore.ListBySubject should not be reached")
}

func (s idjagGrantStore) Delete(context.Context, string) error {
	panic("idjagGrantStore.Delete should not be reached")
}

func (s idjagGrantStore) HasAny(context.Context) (bool, error) {
	panic("idjagGrantStore.HasAny should not be reached")
}

// recordingIDJAGPolicy returns decide's outcome and keeps the last
// request it was handed.
type recordingIDJAGPolicy struct {
	mu     sync.Mutex
	seen   *IDJAGRequest
	decide func(IDJAGRequest) (*IDJAGDecision, error)
}

func (p *recordingIDJAGPolicy) allow(_ context.Context, req IDJAGRequest) (*IDJAGDecision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = &req
	if p.decide != nil {
		return p.decide(req)
	}
	return &IDJAGDecision{ClientID: idjagRASID, Scope: req.Scope, Resource: req.Resource, Email: "user@example.com"}, nil
}

func (p *recordingIDJAGPolicy) last() *IDJAGRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}

type idjagFixture struct {
	h       *Handler
	signer  tokens.SigningKey
	now     time.Time
	emitter *recordingEmitter
	policy  *recordingIDJAGPolicy
}

func newIDJAGFixture(t *testing.T, accessPolicy PolicyFunc) *idjagFixture {
	t.Helper()
	entry, err := keys.GenerateES256("idjag-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	f := &idjagFixture{
		signer:  tokens.FromInternalEntry(entry),
		now:     time.Unix(1_800_000_000, 0).UTC(),
		emitter: &recordingEmitter{},
		policy:  &recordingIDJAGPolicy{},
	}
	h, err := New(Config{
		Policy:      accessPolicy,
		IDJAGPolicy: f.policy.allow,
		Issuer:      idjagIssuer,
		Keys:        keySet,
		Grants: idjagGrantStore{grant: &store.Grant{
			ID:       idjagGrantID,
			Subject:  idjagSubject,
			ClientID: idjagClientID,
			Scope:    []string{"openid"},
		}},
		Audit:        f.emitter,
		Clock:        fixedClock{now: f.now},
		MaxAccessTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.h = h
	return f
}

// idToken mints an OP id_token for the IdP client, expiring in ttl.
func (f *idjagFixture) idToken(t *testing.T, aud string, ttl time.Duration) string {
	t.Helper()
	raw, err := tokens.SignIDToken(f.signer, tokens.IDTokenClaims{
		Issuer:    idjagIssuer,
		Subject:   idjagSubject,
		Audience:  []string{aud},
		IssuedAt:  f.now.Unix(),
		ExpiresAt: f.now.Add(ttl).Unix(),
		AuthTime:  f.now.Add(-time.Minute).Unix(),
		ACR:       "urn:example:acr:mfa",
		AMR:       []string{"pwd", "otp"},
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	return raw
}

// idpClient is confidential and registers no RAS scope or resource.
func idpClient() *store.Client {
	return &store.Client{ //nolint:gosec // G101: test fixture client, not a credential.
		ID:                      idjagClientID,
		TokenEndpointAuthMethod: "private_key_jwt",
		GrantTypes:              []string{GrantType},
		Scopes:                  []string{"openid"},
	}
}

func (f *idjagFixture) request(t *testing.T) customgrant.Request {
	t.Helper()
	return customgrant.Request{
		Client: idpClient(),
		Form: map[string][]string{
			"subject_token":        {f.idToken(t, idjagClientID, 10*time.Minute)},
			"subject_token_type":   {TokenTypeIDToken},
			"requested_token_type": {TokenTypeIDJAG},
			"audience":             {idjagAudience},
		},
		RequestedScope: []string{"chat.read", "chat.history"},
	}
}

func wireCode(t *testing.T, err error) string {
	t.Helper()
	var we *wireError
	if !errors.As(err, &we) {
		t.Fatalf("err = %v, want a wireError", err)
	}
	return we.code
}

func decodeJWTPart(t *testing.T, raw string, idx int) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS expected 3 parts, got %d", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[idx])
	if err != nil {
		t.Fatalf("decode part %d: %v", idx, err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal part %d: %v", idx, err)
	}
	return out
}

func TestIDJAG_New_RequiresAtLeastOnePolicy(t *testing.T) {
	t.Parallel()
	entry, err := keys.GenerateES256("idjag-new-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	if _, err := New(Config{Issuer: idjagIssuer, Keys: keySet}); err == nil {
		t.Error("New accepted a config with neither Policy nor IDJAGPolicy")
	}
	idjagOnly := func(context.Context, IDJAGRequest) (*IDJAGDecision, error) {
		return nil, ErrIDJAGDenied
	}
	if _, err := New(Config{IDJAGPolicy: idjagOnly, Issuer: idjagIssuer, Keys: keySet}); err != nil {
		t.Errorf("New rejected an IDJAGPolicy-only config: %v", err)
	}
}

func TestIDJAG_IssuesAssertionWithDraftClaimSet(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)
	resp, err := f.h.Handle(context.Background(), f.request(t))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	header := decodeJWTPart(t, resp.AccessToken, 0)
	if header["typ"] != "oauth-id-jag+jwt" || header["alg"] != "ES256" || header["kid"] != "idjag-kid" {
		t.Errorf("header = %v", header)
	}
	parsed, err := josev4.ParseSignedCompact(resp.AccessToken, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	if _, err := parsed.Verify(f.signer.Signer.Public()); err != nil {
		t.Fatalf("ID-JAG does not verify under the active key: %v", err)
	}
	c := decodeJWTPart(t, resp.AccessToken, 1)
	want := map[string]any{
		"iss":       idjagIssuer,
		"sub":       idjagSubject,
		"aud":       idjagAudience,
		"client_id": idjagRASID,
		"scope":     "chat.read chat.history",
		"email":     "user@example.com",
		"acr":       "urn:example:acr:mfa",
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}
	if c["iat"] != float64(f.now.Unix()) || c["exp"] != float64(f.now.Add(5*time.Minute).Unix()) {
		t.Errorf("iat/exp = %v/%v, want now/now+5m", c["iat"], c["exp"])
	}
	if c["auth_time"] != float64(f.now.Add(-time.Minute).Unix()) {
		t.Errorf("auth_time = %v, want the id_token's", c["auth_time"])
	}
	if amr, _ := c["amr"].([]any); len(amr) != 2 || amr[0] != "pwd" || amr[1] != "otp" {
		t.Errorf("amr = %v, want [pwd otp]", c["amr"])
	}
	if jti, _ := c["jti"].(string); jti == "" {
		t.Error("jti missing")
	}
	for _, absent := range []string{"cnf", "resource", "act", "azp", "nonce"} {
		if _, ok := c[absent]; ok {
			t.Errorf("claim %s present on an unbound, resource-less ID-JAG: %v", absent, c[absent])
		}
	}
}

func TestIDJAG_ResponseShape(t *testing.T) {
	t.Parallel()
	for _, dpop := range []string{"", "dpop-jkt"} {
		f := newIDJAGFixture(t, nil)
		req := f.request(t)
		req.DPoPJKT = dpop
		resp, err := f.h.Handle(context.Background(), req)
		if err != nil {
			t.Fatalf("dpop=%q: Handle: %v", dpop, err)
		}
		if resp.AccessToken == "" || resp.BoundAccessToken != nil {
			t.Errorf("dpop=%q: the ID-JAG must ride verbatim on access_token: %+v", dpop, resp)
		}
		if resp.TokenType != "N_A" {
			t.Errorf("dpop=%q: TokenType = %q, want N_A", dpop, resp.TokenType)
		}
		if resp.IssuedTokenType != TokenTypeIDJAG || resp.IssuesAccessToken() {
			t.Errorf("dpop=%q: IssuedTokenType = %q, want the id-jag urn", dpop, resp.IssuedTokenType)
		}
		if resp.AccessTokenTTL != 5*time.Minute {
			t.Errorf("dpop=%q: AccessTokenTTL = %v, want 5m", dpop, resp.AccessTokenTTL)
		}
		if resp.IssueRefreshToken || resp.IssueIDToken || resp.IDToken != "" {
			t.Errorf("dpop=%q: refresh/id_token must not be issued: %+v", dpop, resp)
		}
		if resp.GrantID != idjagGrantID || resp.GrantSubject != idjagSubject {
			t.Errorf("dpop=%q: lineage = %q/%q, want the id_token's grant", dpop, resp.GrantID, resp.GrantSubject)
		}
	}
}

func TestIDJAG_ClientWithoutRASRegistrationStillIssued(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)
	disp := customgrant.New([]customgrant.Handler{f.h}, customgrant.WithMaxAccessTTL(time.Hour))
	form := url.Values{
		"grant_type":           {GrantType},
		"subject_token":        {f.idToken(t, idjagClientID, 10*time.Minute)},
		"subject_token_type":   {TokenTypeIDToken},
		"requested_token_type": {TokenTypeIDJAG},
		"audience":             {idjagAudience},
		"resource":             {"https://ras.example/api"},
		"scope":                {"chat.read"},
	}
	resp, err := disp.Dispatch(context.Background(), customgrant.DispatchInput{
		GrantType: GrantType,
		Client:    idpClient(),
		Form:      form,
	})
	if err != nil {
		t.Fatalf("Dispatch: %v (the RAS namespace must not be checked against the IdP client)", err)
	}
	if len(resp.Scope) != 1 || resp.Scope[0] != "chat.read" {
		t.Errorf("Scope = %v, want [chat.read]", resp.Scope)
	}
	seen := f.policy.last()
	if seen == nil || seen.Audience != idjagAudience || len(seen.Resource) != 1 || seen.Resource[0] != "https://ras.example/api" {
		t.Errorf("policy request = %+v", seen)
	}
}

func TestIDJAG_PolicyReceivesRequestVerbatim(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)
	req := f.request(t)
	req.Form["resource"] = []string{"HTTPS://RAS.example/API", "https://ras.example/other"}
	resp, err := f.h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	seen := f.policy.last()
	if seen.Subject != idjagSubject || seen.Client.ID != idjagClientID {
		t.Errorf("policy request = %+v", seen)
	}
	if len(seen.Resource) != 2 || seen.Resource[0] != "HTTPS://RAS.example/API" {
		t.Errorf("Resource = %v, want the request strings unnormalised", seen.Resource)
	}
	if len(seen.Scope) != 2 || seen.Scope[0] != "chat.read" {
		t.Errorf("Scope = %v, want the requested scope uncut by the client registration", seen.Scope)
	}
	c := decodeJWTPart(t, resp.AccessToken, 1)
	if arr, _ := c["resource"].([]any); len(arr) != 2 || arr[0] != "HTTPS://RAS.example/API" {
		t.Errorf("resource claim = %v, want both values verbatim", c["resource"])
	}
}

func TestIDJAG_SingleResourceClaimIsAString(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)
	req := f.request(t)
	req.Form["resource"] = []string{"https://ras.example/api"}
	resp, err := f.h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if c := decodeJWTPart(t, resp.AccessToken, 1); c["resource"] != "https://ras.example/api" {
		t.Errorf("resource claim = %v, want the single string", c["resource"])
	}
}

func TestIDJAG_EmailOmittedWhenDecisionHasNone(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)
	f.policy.decide = func(IDJAGRequest) (*IDJAGDecision, error) {
		return &IDJAGDecision{ClientID: idjagRASID}, nil
	}
	resp, err := f.h.Handle(context.Background(), f.request(t))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	c := decodeJWTPart(t, resp.AccessToken, 1)
	if _, ok := c["email"]; ok {
		t.Errorf("email present with an empty decision Email: %v", c["email"])
	}
	if _, ok := c["scope"]; ok {
		t.Errorf("scope present with an empty decision Scope: %v", c["scope"])
	}
}

func TestIDJAG_RequestedTokenTypeMatrix(t *testing.T) {
	t.Parallel()
	accessPolicy := func(context.Context, RequestView) (*Decision, error) {
		return nil, nil //nolint:nilnil // OP defaults
	}
	cases := []struct {
		name      string
		access    PolicyFunc
		requested []string
	}{
		{name: "idjag-only, requested_token_type absent", requested: nil},
		{name: "idjag-only, requested access_token", requested: []string{TokenTypeAccessToken}},
		{name: "unsupported type", access: accessPolicy, requested: []string{"urn:ietf:params:oauth:token-type:refresh_token"}},
	}
	for _, tc := range cases {
		f := newIDJAGFixture(t, tc.access)
		req := f.request(t)
		delete(req.Form, "requested_token_type")
		if tc.requested != nil {
			req.Form["requested_token_type"] = tc.requested
		}
		_, err := f.h.Handle(context.Background(), req)
		if got := wireCode(t, err); got != "invalid_request" {
			t.Errorf("%s: code = %q, want invalid_request", tc.name, got)
		}
		if f.policy.last() != nil {
			t.Errorf("%s: the ID-JAG policy ran", tc.name)
		}
	}
}

func TestIDJAG_NotConfiguredKeepsTX015(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)
	f.h.idjagPolicy = nil
	f.h.policy = func(context.Context, RequestView) (*Decision, error) {
		t.Error("access-token policy ran for an id-jag request")
		return nil, nil //nolint:nilnil // unreachable
	}
	_, err := f.h.Handle(context.Background(), f.request(t))
	if got := wireCode(t, err); got != "invalid_request" {
		t.Errorf("code = %q, want invalid_request", got)
	}
}

func TestIDJAG_UnauthenticatedClientRejected(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*store.Client){
		func(c *store.Client) { c.TokenEndpointAuthMethod = "none" },
		func(c *store.Client) { c.PublicClient = true },
	} {
		f := newIDJAGFixture(t, nil)
		req := f.request(t)
		mutate(req.Client)
		_, err := f.h.Handle(context.Background(), req)
		if got := wireCode(t, err); got != "invalid_client" {
			t.Errorf("code = %q, want invalid_client", got)
		}
		if f.policy.last() != nil {
			t.Error("policy ran for an unauthenticated client")
		}
	}
}

func TestIDJAG_RequestShapeRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(map[string][]string)
	}{
		{name: "audience missing", mutate: func(f map[string][]string) { delete(f, "audience") }},
		{name: "audience repeated", mutate: func(f map[string][]string) { f["audience"] = []string{idjagAudience, "https://other.example"} }},
		{name: "actor_token", mutate: func(f map[string][]string) {
			f["actor_token"] = []string{"x"}
			f["actor_token_type"] = []string{TokenTypeAccessToken}
		}},
		{name: "subject_token_type access_token", mutate: func(f map[string][]string) { f["subject_token_type"] = []string{TokenTypeAccessToken} }},
		{name: "subject_token_type jwt", mutate: func(f map[string][]string) { f["subject_token_type"] = []string{TokenTypeJWT} }},
		{name: "subject_token missing", mutate: func(f map[string][]string) { delete(f, "subject_token") }},
	}
	for _, tc := range cases {
		f := newIDJAGFixture(t, nil)
		req := f.request(t)
		tc.mutate(req.Form)
		_, err := f.h.Handle(context.Background(), req)
		if got := wireCode(t, err); got != "invalid_request" {
			t.Errorf("%s: code = %q, want invalid_request", tc.name, got)
		}
		if f.policy.last() != nil {
			t.Errorf("%s: policy ran", tc.name)
		}
	}
}

func TestIDJAG_SubjectTokenRejected(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)

	otherAud := f.request(t)
	otherAud.Form["subject_token"] = []string{f.idToken(t, "another-client", 10*time.Minute)}
	if _, err := f.h.Handle(context.Background(), otherAud); wireCode(t, err) != "invalid_grant" {
		t.Errorf("id_token for another client: %v, want invalid_grant", err)
	}

	// A subject with no consent for this client (a pairwise sub misses
	// the grant the same way) cannot be vouched for.
	noGrant := f.request(t)
	noGrant.Client.ID = "unconsented-client"
	noGrant.Form["subject_token"] = []string{f.idToken(t, "unconsented-client", 10*time.Minute)}
	if _, err := f.h.Handle(context.Background(), noGrant); wireCode(t, err) != "invalid_grant" {
		t.Errorf("unconsented subject: %v, want invalid_grant", err)
	}
	if f.policy.last() != nil {
		t.Error("policy ran for a rejected subject_token")
	}
}

func TestIDJAG_PolicyOutcomeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		resource []string
		decide   func(IDJAGRequest) (*IDJAGDecision, error)
		want     string
	}{
		{name: "unknown audience", want: "invalid_target", decide: func(IDJAGRequest) (*IDJAGDecision, error) {
			return nil, ErrIDJAGUnknownAudience
		}},
		{name: "denied", want: "access_denied", decide: func(IDJAGRequest) (*IDJAGDecision, error) {
			return nil, ErrIDJAGDenied
		}},
		{name: "nil decision", want: "access_denied", decide: func(IDJAGRequest) (*IDJAGDecision, error) {
			return nil, nil //nolint:nilnil // the refusal under test
		}},
		{name: "other error", want: "server_error", decide: func(IDJAGRequest) (*IDJAGDecision, error) {
			return nil, errors.New("backend down")
		}},
		{name: "empty client_id", want: "server_error", decide: func(IDJAGRequest) (*IDJAGDecision, error) {
			return &IDJAGDecision{Scope: []string{"chat.read"}}, nil
		}},
		{
			name: "resource not requested", want: "server_error", resource: []string{"https://ras.example/api"},
			decide: func(IDJAGRequest) (*IDJAGDecision, error) {
				return &IDJAGDecision{ClientID: idjagRASID, Resource: []string{"https://ras.example/admin"}}, nil
			},
		},
		{
			name: "resource granted without request", want: "server_error",
			decide: func(IDJAGRequest) (*IDJAGDecision, error) {
				return &IDJAGDecision{ClientID: idjagRASID, Resource: []string{"https://ras.example/api"}}, nil
			},
		},
		{
			name: "resource requested none granted", want: "invalid_target", resource: []string{"https://ras.example/api"},
			decide: func(IDJAGRequest) (*IDJAGDecision, error) {
				return &IDJAGDecision{ClientID: idjagRASID}, nil
			},
		},
	}
	for _, tc := range cases {
		f := newIDJAGFixture(t, nil)
		f.policy.decide = tc.decide
		req := f.request(t)
		if tc.resource != nil {
			req.Form["resource"] = tc.resource
		}
		_, err := f.h.Handle(context.Background(), req)
		if got := wireCode(t, err); got != tc.want {
			t.Errorf("%s: code = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestIDJAG_TTLCappedAtFiveMinutesNotBySubjectToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		stated time.Duration
		want   time.Duration
	}{
		{stated: 0, want: 5 * time.Minute},
		{stated: 2 * time.Minute, want: 2 * time.Minute},
		{stated: 10 * time.Minute, want: 5 * time.Minute},
	}
	for _, tc := range cases {
		f := newIDJAGFixture(t, nil)
		f.policy.decide = func(IDJAGRequest) (*IDJAGDecision, error) {
			return &IDJAGDecision{ClientID: idjagRASID, TTL: tc.stated}, nil
		}
		req := f.request(t)
		// The id_token expires in one minute; the ID-JAG is not bounded by it.
		req.Form["subject_token"] = []string{f.idToken(t, idjagClientID, time.Minute)}
		resp, err := f.h.Handle(context.Background(), req)
		if err != nil {
			t.Fatalf("stated %v: Handle: %v", tc.stated, err)
		}
		if resp.AccessTokenTTL != tc.want {
			t.Errorf("stated %v: AccessTokenTTL = %v, want %v", tc.stated, resp.AccessTokenTTL, tc.want)
		}
		c := decodeJWTPart(t, resp.AccessToken, 1)
		exp, _ := c["exp"].(float64)
		iat, _ := c["iat"].(float64)
		if time.Duration(exp-iat)*time.Second != tc.want {
			t.Errorf("stated %v: exp-iat = %vs, want %v", tc.stated, exp-iat, tc.want)
		}
	}
}

func TestIDJAG_CnfCarriesOneMethodFromTheBinding(t *testing.T) {
	t.Parallel()
	cert := fixtureLeafCert()
	cases := []struct {
		name string
		jkt  string
		mtls bool
		want map[string]any
	}{
		{name: "dpop", jkt: "dpop-jkt", want: map[string]any{"jkt": "dpop-jkt"}},
		{name: "mtls", mtls: true, want: map[string]any{"x5t#S256": mtls.Thumbprint(cert)}},
		{name: "dpop and mtls", jkt: "dpop-jkt", mtls: true, want: map[string]any{"jkt": "dpop-jkt"}},
	}
	for _, tc := range cases {
		f := newIDJAGFixture(t, nil)
		req := f.request(t)
		req.DPoPJKT = tc.jkt
		if tc.mtls {
			req.MTLSCert = cert
		}
		resp, err := f.h.Handle(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: Handle: %v", tc.name, err)
		}
		if resp.TokenType != "N_A" {
			t.Errorf("%s: TokenType = %q, want N_A", tc.name, resp.TokenType)
		}
		cnf, _ := decodeJWTPart(t, resp.AccessToken, 1)["cnf"].(map[string]any)
		if len(cnf) != len(tc.want) {
			t.Fatalf("%s: cnf = %v, want %v", tc.name, cnf, tc.want)
		}
		for k, v := range tc.want {
			if cnf[k] != v {
				t.Errorf("%s: cnf.%s = %v, want %v", tc.name, k, cnf[k], v)
			}
		}
	}
}

func TestIDJAG_IssuedAuditWaitsForTheWireLayer(t *testing.T) {
	t.Parallel()
	f := newIDJAGFixture(t, nil)
	resp, err := f.h.Handle(context.Background(), f.request(t))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	count := func() int {
		n := 0
		for _, ev := range f.emitter.events {
			if ev.Name == auditIDJAGIssued {
				n++
			}
		}
		return n
	}
	if count() != 0 {
		t.Fatal("token_exchange.idjag_issued emitted before the response was issued")
	}
	if resp.OnIssued == nil {
		t.Fatal("OnIssued is nil")
	}
	resp.OnIssued(context.Background(), false)
	if count() != 1 {
		t.Fatalf("token_exchange.idjag_issued count = %d, want 1", count())
	}
	for _, ev := range f.emitter.events {
		if ev.Name != auditIDJAGIssued {
			continue
		}
		if ev.ClientID != idjagClientID || ev.ActorID != idjagSubject || ev.Extras["audience"] != idjagAudience {
			t.Errorf("event = %+v", ev)
		}
	}
}
