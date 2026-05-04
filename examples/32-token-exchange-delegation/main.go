//go:build example

// Example 32-token-exchange-delegation demonstrates RFC 8693 OAuth 2.0
// Token Exchange in the canonical on-behalf-of (delegation) shape.
// Three actors live in one process:
//
//   - The OP (gated by [op.RegisterTokenExchange]) on :8090.
//   - Service A — the "exchanger". A confidential client that already
//     holds a user's access_token (issued for service-a's audience)
//     and wants to call service-b on the user's behalf with a
//     downscoped credential.
//   - Service B — the "resource server". A passive client whose only
//     purpose is to own the audience name; the example RS-side
//     verifier reads issuer / audience / sub / act off the JWT.
//
// What the round-trip proves:
//
//  1. Service A drives the authorization_code flow against the OP and
//     receives an access_token whose sub is "user-42" and aud is
//     service-a.
//  2. Service A POSTs that token back to /oidc/token under the
//     token-exchange grant_type, asks for audience=service-b and a
//     downscoped scope.
//  3. The OP runs structural checks (audience narrowing, scope
//     downscope, TTL ceiling) and then calls the supplied
//     [op.TokenExchangePolicy] for the business decision.
//  4. The OP mints a new access_token whose JWT claims include
//     act={"sub":"service-a"} (RFC 8693 §4.1), sub="user-42",
//     aud=["service-b"], and the narrowed scope.
//  5. The Service-B verifier inspects the act chain and prints
//     "User user-42 (acting via service-a) has api:read access to
//     service-b".
//
// Run with the example build tag:
//
//	go run -tags example ./examples/32-token-exchange-delegation
//
// The example is self-contained: a single binary stands up the OP on
// :8090, runs a self-verify probe in-process, and exits 0 on success.
// End-to-end runtime is well under five seconds.
//
// Why "act" matters: RFC 8693 §4.1 makes the act claim the
// delegation chain's primary auditing artifact. A resource server
// that ignores act sees a token whose sub is the original user and
// silently participates in delegation it cannot observe — see
// [ADR 0028] for the project's discussion of this posture. The
// Service-B verifier in this example explicitly walks the chain so
// the read pattern is observable next to the write.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Authentication: this example wires
//     [testkit.SubjectAuthenticator], which trusts whatever
//     subject the SPA submits. Production OPs run a real password /
//     WebAuthn / OIDC-federation primary factor here.
//   - Policy seam: the example policy admits every exchange between
//     the demo's two clients. Production embedders consult tenant
//     allowlists, rate-of-exchange budgets, and request-context risk
//     before returning nil.
//   - act-aware RS: a resource server that does not consume the act
//     chain is participating in delegation it cannot see. The
//     verifier in this example is the minimal read pattern; library
//     consumers should treat the chain as an audit primary, not an
//     advisory hint.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	// frontendID is the client that obtains the user's subject_token
	// via the authorization_code flow. Real deployments typically
	// have a SPA / mobile / first-party RP in this slot; the example
	// pins a confidential client purely so the auth-code flow has a
	// secret to bind. The frontend never performs the exchange; the
	// token it receives is what service-a presents as subject_token.
	frontendID     = "frontend"
	frontendSecret = "tx-frontend-secret-rotate-me"

	// serviceAID is the calling client — the one performing the
	// exchange. The OP authenticates it via client_secret_post. The
	// impersonation chain names this client as act.sub on the issued
	// token (the OP injects the calling client when no actor_token is
	// supplied, per RFC 8693 §1.3 and ADR 0028).
	serviceAID     = "service-a"
	serviceASecret = "tx-svc-a-secret-rotate-me"

	// serviceBID is the resource server's identifier. The OP never
	// authenticates this client for the exchange; service-b's role is
	// owning the audience name and parsing JWTs the OP issued for it.
	serviceBID = "service-b"

	// serviceAResource and serviceBResource are the RFC 8707 resource
	// indicators the example treats as the audience values. Token-
	// exchange's audience parameter feeds into the same allowlist as
	// /authorize's resource parameter; both must be absolute URIs the
	// client registered. Example clients register the URI form, so the
	// final aud claim on the issued JWT is also URI-shaped.
	serviceAResource = "https://api.service-a.example/"
	serviceBResource = "https://api.service-b.example/"

	// userSubject is the end-user the subject_token was issued to.
	// The auth-code flow's [testkit.SubjectAuthenticator] echoes back
	// whatever subject the helper submits; we pin a fixed value so the
	// final assertion has something stable to read.
	userSubject = "user-42"

	// rpRedirectURI is the URL the OP redirects to after the
	// authorization-code round-trip. The example never actually
	// listens on this host — the helper inspects the redirect's
	// query parameters directly, mirroring the scenariokit pattern.
	rpRedirectURI = "https://service-a.example.invalid/callback"

	// scopeFull is the original access_token's scope set; scopeNarrow
	// is what service-a downscopes to when calling service-b. The
	// OP enforces RequestedScope ⊆ subject_token scope structurally;
	// the policy may narrow further.
	scopeFull   = "openid api:read api:write"
	scopeNarrow = "api:read"

	tokenExchangeGrantType   = "urn:ietf:params:oauth:grant-type:token-exchange"
	subjectTokenTypeAT       = "urn:ietf:params:oauth:token-type:access_token"
	requestedTokenTypeAT     = "urn:ietf:params:oauth:token-type:access_token"
	tokenExchangeMaxLifetime = 5 * time.Minute
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("token-exchange example failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

// run boots the OP, runs the in-process self-verify probe, and (on
// success) opens a public listener on :8090 so an embedder can curl
// the discovery endpoint. The probe is the canonical assertion the
// example ships; the listener is convenience for ad-hoc inspection.
func run(logger *slog.Logger) error {
	probeIssuer, probeShutdown, err := startProbeOP(logger)
	if err != nil {
		return err
	}
	defer probeShutdown()

	if err := selfVerify(logger, probeIssuer); err != nil {
		fmt.Println("✗ self-verify: " + err.Error())
		return err
	}
	fmt.Println("✓ self-verify: token-exchange round-trip OK with act-chain verified")

	// The probe OP and its listener are torn down by the deferred
	// shutdown above. The public listener below is a fresh OP bound
	// to :8090 so an embedder running `go run -tags example ...` can
	// curl the discovery endpoint after the probe prints its summary.
	logger.Info("opening public listener", slog.String("addr", ":8090"))
	return runPublicListener(logger)
}

// startProbeOP boots an OP backed by an httptest.NewServer (so it
// uses an ephemeral port) wired with the token-exchange policy, the
// auth-code subject authenticator, and two static clients. The
// returned shutdown closure tears the server down deterministically.
//
// The provider's issuer is the httptest URL so the discovery
// document (and the iss claim on every issued token) match the
// listener the probe actually drives. Embedders running a real
// listener pass the public issuer to [buildProvider].
func startProbeOP(logger *slog.Logger) (issuer string, shutdown func(), err error) {
	// httptest.NewUnstartedServer reserves a port without serving so
	// we can read the listener address before constructing the OP.
	// op.WithIssuer rejects mismatched issuers at request time, so the
	// option needs the final URL the listener exposes.
	srv := httptest.NewUnstartedServer(nil)
	probeIssuer := "http://" + srv.Listener.Addr().String()
	provider, err := buildProvider(probeIssuer)
	if err != nil {
		srv.Close()
		return "", nil, fmt.Errorf("build provider: %w", err)
	}
	srv.Config.Handler = provider
	srv.Start()
	logger.Info("probe OP listening", slog.String("issuer", srv.URL))
	return srv.URL, srv.Close, nil
}

// runPublicListener boots a fresh OP on :8090 (the issuer the
// package banner advertises) and blocks until SIGINT. The block is
// short — examples run as one-shot demos — so the surface here is
// intentionally minimal.
func runPublicListener(logger *slog.Logger) error {
	const addr = ":8090"
	const issuer = "http://127.0.0.1:8090"
	provider, err := buildProvider(issuer)
	if err != nil {
		return fmt.Errorf("build provider: %w", err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           provider,
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("OP listening", slog.String("addr", addr))
	logger.Info("hint: curl http://127.0.0.1:8090/.well-known/openid-configuration | jq")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// buildProvider assembles the OP option list. The token-exchange
// policy admits every exchange between the two demo clients; a
// production embedder reads tenant / risk context off [req] before
// returning nil. The ephemeral keys are regenerated on every call so
// the probe and the public listener cannot share signing material.
func buildProvider(issuer string) (*op.Provider, error) {
	keys := devkeys.MustEphemeral("token-exchange-1")
	st := inmem.New()

	provider, err := op.New(
		// Issuer is whatever the listener actually serves. The probe
		// uses httptest's ephemeral URL; the public listener uses the
		// fixed :8090 binding the package banner advertises.
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// SubjectAuthenticator + AutoConsentDriver let the example
		// drive the auth-code flow programmatically: the helper POSTs
		// the desired subject onto /interaction; the consent screen
		// auto-approves every requested scope.
		op.WithAuthenticators(testkit.SubjectAuthenticator{}),
		op.WithInteractionDriver(testkit.AutoConsentDriver{}),
		op.WithStaticClients(
			op.ConfidentialClient{
				// frontend uses authorization_code + PKCE to obtain
				// the user's access_token for service-a's audience.
				// Real deployments could substitute a public SPA
				// client; the example pins confidential so the
				// auth-code flow has a fixed secret to bind.
				ID:           frontendID,
				Secret:       frontendSecret,
				AuthMethod:   op.AuthClientSecretPost,
				RedirectURIs: []string{rpRedirectURI},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"openid", "api:read", "api:write"},
				Resources:    []string{serviceAResource},
			},
			op.ConfidentialClient{
				// service-a is the exchanger. It authenticates via
				// client_secret_post when calling /token under the
				// token-exchange grant. Resources lists both
				// audiences so the OP's allowlist accepts the
				// downscoped audience=service-b on the exchange.
				ID:           serviceAID,
				Secret:       serviceASecret,
				AuthMethod:   op.AuthClientSecretPost,
				RedirectURIs: []string{rpRedirectURI},
				GrantTypes:   []string{tokenExchangeGrantType},
				Scopes:       []string{"openid", "api:read", "api:write"},
				Resources:    []string{serviceAResource, serviceBResource},
			},
			op.ConfidentialClient{
				// service-b only needs to exist as a registered
				// resource owner; the OP looks up audience names
				// against the union of registered Resources. The
				// client itself never visits /token in this example.
				ID:           serviceBID,
				Secret:       "tx-svc-b-secret-rotate-me",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{rpRedirectURI},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"api:read", "api:write"},
				Resources:    []string{serviceBResource},
			},
		),
		// The example's downscope policy: every exchange between
		// service-a and service-b is admitted with the OP-computed
		// defaults; the dispatcher caps the TTL at the global
		// access-token ceiling (1 h by default), and we narrow further
		// here to keep the chain short-lived.
		op.RegisterTokenExchange(downscopePolicy{
			maxTTL: tokenExchangeMaxLifetime,
		}),
		// Register the public scopes service-b serves so the auth-code
		// flow can request them. The default catalogue covers
		// openid / profile / email; api:* is example-specific.
		op.WithScope(op.PublicScope("api:read", "Read api resources on your behalf")),
		op.WithScope(op.PublicScope("api:write", "Write api resources on your behalf")),
	)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// downscopePolicy is the example's [op.TokenExchangePolicy]. The
// policy admits every exchange between the two demo clients and
// returns a [op.TokenExchangeDecision] capping the granted TTL at
// maxTTL — the OP would otherwise fall back to the global access-
// token ceiling, which is intentionally too long for short-lived
// service-mesh delegation.
type downscopePolicy struct {
	maxTTL time.Duration
}

func (p downscopePolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	// A nil decision means "use the OP-computed defaults"; a non-nil
	// decision narrows them. The example narrows TTL only — scope
	// and audience are left to the OP's structural intersection
	// against the subject_token's values.
	return &op.TokenExchangeDecision{GrantedTTL: p.maxTTL}, nil //nolint:exhaustruct // optional fields default to "no override"
}

// selfVerify drives the full round-trip: it obtains service-a's
// subject_token via the auth-code flow, exchanges it for a service-b-
// audience access_token, decodes the resulting JWT, and asserts the
// act chain. The function returns nil on success and a descriptive
// error otherwise; the caller prints the result with the canonical
// banner.
func selfVerify(logger *slog.Logger, issuer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	subjectToken, err := obtainSubjectToken(ctx, logger, issuer)
	if err != nil {
		return fmt.Errorf("obtain subject_token: %w", err)
	}
	logger.Info("obtained subject_token", slog.Int("len", len(subjectToken)))

	exchanged, err := postTokenExchange(ctx, logger, issuer, subjectToken)
	if err != nil {
		return fmt.Errorf("token-exchange: %w", err)
	}
	logger.Info("exchanged token", slog.Int("len", len(exchanged)))

	if err := serviceBVerify(logger, issuer, exchanged); err != nil {
		return fmt.Errorf("service-b verify: %w", err)
	}
	return nil
}

// obtainSubjectToken drives the auth-code flow against issuer and
// returns service-a's access_token. The flow:
//
//  1. GET /oidc/auth → 302 to /oidc/interaction/{uid}.
//  2. GET /oidc/interaction/{uid} → 200 JSON prompt + CSRF cookie.
//  3. POST {state_ref, values:{subject:"user-42"}} →
//     302 redirect to RP callback OR a consent prompt.
//  4. POST consent submission (when prompted) → final 302.
//  5. POST /oidc/token with grant_type=authorization_code → JSON
//     response carrying access_token.
//
// Cookies thread through a per-call jar so the OP's CSRF middleware
// observes the values minted at step 2 on the submission at step 3.
func obtainSubjectToken(ctx context.Context, logger *slog.Logger, issuer string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("cookie jar: %w", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	pkce := newPKCE("token-exchange-example-verifier-1234567890abcdefghi")

	authorizeQuery := url.Values{
		"client_id":             {frontendID},
		"response_type":         {"code"},
		"redirect_uri":          {rpRedirectURI},
		"scope":                 {scopeFull},
		"state":                 {"tx-example-state"},
		"nonce":                 {"tx-example-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
		"resource":              {serviceAResource},
	}

	authorizeResp, err := doGET(ctx, client, issuer+"/oidc/auth?"+authorizeQuery.Encode())
	if err != nil {
		return "", err
	}
	_ = authorizeResp.Body.Close()
	if authorizeResp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("/authorize: status=%d", authorizeResp.StatusCode)
	}
	loc, err := authorizeResp.Location()
	if err != nil {
		return "", fmt.Errorf("/authorize Location: %w", err)
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		return "", fmt.Errorf("/authorize redirected to path %s (full=%s), expected /oidc/interaction/", loc.Path, loc.String())
	}
	interactionURL := issuer + loc.Path

	finalRedirect, err := driveInteraction(ctx, client, interactionURL, issuer)
	if err != nil {
		return "", err
	}

	q := finalRedirect.Query()
	if errCode := q.Get("error"); errCode != "" {
		return "", fmt.Errorf("authorize callback error=%s desc=%s", errCode, q.Get("error_description"))
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("authorize callback missing code: %s", finalRedirect)
	}
	logger.Info("auth-code flow received code", slog.String("code", code[:8]+"..."))

	return exchangeAuthCode(ctx, issuer, code, pkce.Verifier)
}

// driveInteraction issues the GET /interaction probe, submits the
// subject step, optionally completes a consent prompt, and returns
// the final redirect URL pointing at rpRedirectURI. The function
// owns the CSRF cookie / header pair; callers see only the resolved
// callback URL.
func driveInteraction(ctx context.Context, client *http.Client, interactionURL, origin string) (*url.URL, error) {
	stepResp, err := doGET(ctx, client, interactionURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stepResp.Body.Close() }()
	if stepResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status=%d", interactionURL, stepResp.StatusCode)
	}
	step, err := decodeJSONBody(stepResp)
	if err != nil {
		return nil, fmt.Errorf("decode interaction prompt: %w", err)
	}
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		return nil, errors.New("interaction prompt missing state_ref")
	}
	csrf := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if csrf == nil {
		return nil, errors.New("interaction prompt missing __Host-oidc_csrf cookie")
	}

	postResp, err := postInteraction(ctx, client, interactionURL, origin, csrf, map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{testkit.SubjectFieldName: userSubject},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = postResp.Body.Close() }()
	finalResp, err := completeConsentIfPrompted(ctx, client, interactionURL, origin, csrf, postResp)
	if err != nil {
		return nil, err
	}
	defer func() { _ = finalResp.Body.Close() }()
	if finalResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(finalResp.Body)
		return nil, fmt.Errorf("final interaction status=%d body=%s", finalResp.StatusCode, string(body))
	}
	return finalResp.Location()
}

// completeConsentIfPrompted inspects prior for the consent envelope
// the [testkit.AutoConsentDriver] surfaces. When the envelope is a
// consent prompt, the helper extracts the requested scope list,
// approves every entry, and returns the next response (typically a
// 302 redirect back to the RP). When prior is already a redirect, it
// is returned unchanged so the caller's body-close path stays
// uniform.
func completeConsentIfPrompted(ctx context.Context, client *http.Client, interactionURL, origin string, csrf *http.Cookie, prior *http.Response) (*http.Response, error) {
	consent, env, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		return nil, fmt.Errorf("inspect consent prompt: %w", err)
	}
	if !consent {
		return prior, nil
	}
	stateRef, _ := env["state_ref"].(string)
	if stateRef == "" {
		return nil, errors.New("consent prompt missing state_ref")
	}
	// Per-step CSRF scope binding rotates the cookie at every step
	// boundary; pull the rotated value off prior so the consent POST
	// verifies against the right secret.
	if rotated := findCookie(prior.Cookies(), "__Host-oidc_csrf"); rotated != nil {
		csrf = rotated
	}
	approved := approvedScopesFromPrompt(env)
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"approved_scopes": approved},
	}
	return postInteraction(ctx, client, interactionURL, origin, csrf, body)
}

// approvedScopesFromPrompt walks the consent envelope's data.Scopes
// list and returns the names as a space-delimited string (the wire
// shape the consent submission expects).
func approvedScopesFromPrompt(env map[string]any) string {
	data, _ := env["data"].(map[string]any)
	scopesAny, _ := data["Scopes"].([]any)
	out := make([]string, 0, len(scopesAny))
	for _, s := range scopesAny {
		entry, _ := s.(map[string]any)
		name, _ := entry["Name"].(string)
		if name != "" {
			out = append(out, name)
		}
	}
	return strings.Join(out, " ")
}

// postInteraction submits a JSON envelope to /interaction/{uid}.
// The CSRF middleware enforces a (cookie, header) pair; the helper
// threads csrf onto both. body is marshalled verbatim, so callers
// supply either {state_ref, values:{...}} (subject step) or
// {state_ref, values:{approved_scopes:"..."}} (consent step).
func postInteraction(ctx context.Context, client *http.Client, interactionURL, origin string, csrf *http.Cookie, body map[string]any) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal interaction submission: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("build POST %s: %w", interactionURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(csrf)
	return client.Do(req)
}

// exchangeAuthCode posts to /oidc/token under the authorization_code
// grant and returns the access_token field. The frontend client
// authenticates via client_secret_post; the resulting access_token
// is bound to service-a's audience and carries sub=user-42, ready
// for service-a to present as subject_token at /oidc/token under
// the token-exchange grant.
func exchangeAuthCode(ctx context.Context, issuer, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rpRedirectURI},
		"code_verifier": {verifier},
		"client_id":     {frontendID},
		"client_secret": {frontendSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		issuer+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build /token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read /token body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("/token status=%d body=%s", resp.StatusCode, string(body))
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("decode /token body: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("/token response missing access_token: %s", string(body))
	}
	return decoded.AccessToken, nil
}

// postTokenExchange posts the RFC 8693 exchange request to /token.
// service-a authenticates with client_secret_post; the form sets
// audience=service-b and a downscoped scope. The helper returns the
// new access_token field. Errors include the OP's wire envelope so
// negative-path debugging stays observable.
func postTokenExchange(ctx context.Context, logger *slog.Logger, issuer, subjectToken string) (string, error) {
	form := url.Values{
		"grant_type":           {tokenExchangeGrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {subjectTokenTypeAT},
		"requested_token_type": {requestedTokenTypeAT},
		"audience":             {serviceBResource},
		"scope":                {scopeNarrow},
		"client_id":            {serviceAID},
		"client_secret":        {serviceASecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		issuer+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build /token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read /token body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("/token status=%d body=%s", resp.StatusCode, string(body))
	}
	var decoded struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		Scope           string `json:"scope"`
		ExpiresIn       int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("decode /token body: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("/token response missing access_token: %s", string(body))
	}
	logger.Info("exchange response",
		slog.String("issued_token_type", decoded.IssuedTokenType),
		slog.String("scope", decoded.Scope),
		slog.Int64("expires_in", decoded.ExpiresIn))
	return decoded.AccessToken, nil
}

// serviceBVerify is the resource-server side of the round-trip. It
// decodes the JWT (without signature verification — the OP is the
// same process), asserts the issuer / audience / sub fields, walks
// the act chain, and prints the canonical chain summary line. A
// production RS would verify the signature against the OP's JWKS;
// the comment block on [decodeJWTClaims] explains why this example
// elides that step.
func serviceBVerify(logger *slog.Logger, issuer, accessToken string) error {
	claims, err := decodeJWTClaims(accessToken)
	if err != nil {
		return err
	}

	if got, _ := claims["iss"].(string); got != issuer {
		return fmt.Errorf("iss=%q want %q", got, issuer)
	}
	if got, _ := claims["sub"].(string); got != userSubject {
		return fmt.Errorf("sub=%q want %q", got, userSubject)
	}
	// RFC 8707 §2 normalises audience values: lowercase scheme + host,
	// trailing-slash stripped. The OP serves the canonical form, so
	// the RS-side check compares against the stripped variant.
	const wantAud = "https://api.service-b.example"
	if !audienceContains(claims["aud"], wantAud) {
		return fmt.Errorf("aud=%v does not contain %q", claims["aud"], wantAud)
	}
	if got, _ := claims["scope"].(string); got != scopeNarrow {
		return fmt.Errorf("scope=%q want %q", got, scopeNarrow)
	}
	act, ok := claims["act"].(map[string]any)
	if !ok {
		return fmt.Errorf("act claim absent on exchanged token; claims=%v", claims)
	}
	actSub, _ := act["sub"].(string)
	if actSub != serviceAID {
		return fmt.Errorf("act.sub=%q want %q (impersonation chain names the calling client)", actSub, serviceAID)
	}

	logger.Info("service-b accepted exchanged token",
		slog.String("sub", userSubject),
		slog.String("act.sub", serviceAID),
		slog.String("aud", wantAud),
		slog.String("scope", scopeNarrow))
	fmt.Printf("[service-b] User %s (acting via %s) has %s access to %s\n",
		userSubject, serviceAID, scopeNarrow, serviceBID)
	return nil
}

// decodeJWTClaims pulls the payload out of a compact JWS without
// verifying the signature. The example is single-process: the OP
// that signed the token is the same process verifying it, so the
// signature would only confirm what we already know. Production
// resource servers MUST verify against the OP's published JWKS via
// a real JWS verifier (go-jose, jose-jwt, ...).
func decodeJWTClaims(jws string) (map[string]any, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact JWS expected 3 parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWS payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("decode JWS claims: %w", err)
	}
	return claims, nil
}

// audienceContains reports whether aud (RFC 7519 §4.1.3 — string or
// []string) carries the supplied value. The function is tolerant of
// either wire shape so the RS-side check stays uniform across single-
// and multi-audience tokens.
func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// pkcePair bundles a verifier with its derived S256 challenge.
type pkcePair struct {
	Verifier  string
	Challenge string
}

// newPKCE returns the verifier-paired challenge. RFC 7636 §4.1
// requires the verifier to be 43..128 unreserved characters; the
// example uses a fixed value so the round-trip stays deterministic.
func newPKCE(verifier string) pkcePair {
	sum := sha256.Sum256([]byte(verifier))
	return pkcePair{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

// doGET issues a GET against rawURL with ctx propagation. It exists
// so the call sites stay short while still routing every request
// through a context-aware helper.
func doGET(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build GET %s: %w", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	return resp, nil
}

// decodeJSONBody reads resp.Body as a JSON object. Empty bodies map
// to an empty map; transport / decode errors propagate. The function
// does NOT close resp.Body — the caller owns the lifecycle.
func decodeJSONBody(resp *http.Response) (map[string]any, error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode body %q: %w", string(raw), err)
	}
	return out, nil
}

// findCookie returns the cookie matching name, or nil. Used to
// thread the OP's CSRF cookie between the GET / POST hops on
// /interaction/{uid}.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Compile-time confirmation that the example's policy satisfies the
// public seam. The variable is unused at runtime — the assignment is
// purely for linker-time verification.
var _ op.TokenExchangePolicy = downscopePolicy{}
