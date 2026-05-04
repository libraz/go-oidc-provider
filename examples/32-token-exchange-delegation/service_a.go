//go:build example

// service_a.go — exchanger-side actions for example
// 32-token-exchange-delegation.
//
// In a real deployment this code lives in service-a's binary: it
// drives the user's authorization_code flow to obtain a token bound
// to service-a's audience, then exchanges that token for a
// service-b-audience downscoped credential under RFC 8693. This file
// implements both halves end-to-end:
//
//   - obtainSubjectToken      — drives the GET /authorize → 302
//     /interaction → POST subject → POST consent → exchangeAuthCode
//     ladder, end-to-end programmatically (the auth-code flow).
//   - postTokenExchange       — POSTs the RFC 8693 exchange request.
//   - PKCE + interaction helpers stay scoped to this file because
//     they are service-a's machinery, not OP-side wiring.

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
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

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
