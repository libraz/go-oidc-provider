//go:build example

// probe.go — self-verify probe for example 30-custom-grant.
//
// The probe drives the wire round-trip against an httptest-hosted OP:
// it mints a service_token through client.go, POSTs it through the
// embedder-shaped client_secret_post auth, and asserts the issued
// access-token's iss / sub / aud / svc_id claims match what the
// handler in op.go promised. A regression in any of those surfaces
// fails the process before the public listener starts.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
)

// selfVerify runs an in-process round-trip of the custom-grant exchange
// against an httptest.NewServer-hosted OP. It is the example's
// regression contract: any change that breaks the exchange shape (the
// op.WithCustomGrant wiring, the BoundAccessToken contract, the
// dispatcher's audience / scope gates, the access-token verifier)
// fails the probe before the public listener starts.
func selfVerify() error {
	log.Print("[probe] starting in-process round-trip")

	keys := devkeys.MustEphemeral("custom-grant-probe")
	servicePriv, servicePub, err := newServiceKey()
	if err != nil {
		return fmt.Errorf("generate service key: %w", err)
	}

	provider, err := buildProvider(keys, servicePub)
	if err != nil {
		return fmt.Errorf("build provider: %w", err)
	}

	srv := httptest.NewServer(provider)
	defer srv.Close()

	serviceToken, err := signServiceToken(servicePriv, time.Now()) //nolint:forbidigo // demo only: production embedders sign service tokens through their own KMS / clock seam, the OP itself never reaches for time.Now()
	if err != nil {
		return fmt.Errorf("sign service token: %w", err)
	}

	at, err := exchangeServiceToken(srv.URL+tokenPath, serviceToken)
	if err != nil {
		return fmt.Errorf("exchange: %w", err)
	}
	// The OP-minted access token's "iss" claim is the configured
	// issuer (the const above), not the httptest server's ephemeral
	// URL — RFC 8414 §2 / OIDC Discovery 1.0 §3 require the discovery
	// document's issuer to be stable across host bindings.
	if err := assertAccessTokenShape(at, issuer); err != nil {
		return fmt.Errorf("verify access token: %w", err)
	}
	return nil
}

// exchangeServiceToken POSTs the custom-grant exchange and returns the
// access_token from the success response. Authentication is
// client_secret_post per the seeded ConfidentialClient.AuthMethod.
func exchangeServiceToken(endpoint, serviceToken string) (string, error) {
	form := url.Values{
		"grant_type":    []string{grantURN},
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
		"service_token": []string{serviceToken},
		"scope":         []string{"api:read"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("decode body: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("access_token missing: %s", string(body))
	}
	if decoded.TokenType != "Bearer" {
		return "", fmt.Errorf("token_type=%q want Bearer", decoded.TokenType)
	}
	return decoded.AccessToken, nil
}

// assertAccessTokenShape decodes the OP-minted access token's payload
// and confirms the iss / aud / sub claims look right. The probe does
// not verify the signature against the OP's JWKS — the same process
// just signed it — but it does inspect the cnf claim (expected absent
// since the demo presents no DPoP / mTLS credential) and the svc_id
// extra claim the handler stamped.
func assertAccessTokenShape(jwt, expectedIssuer string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("access_token is not a 3-segment JWS: got %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("base64 decode payload: %w", err)
	}
	var claims struct {
		Iss    string `json:"iss"`
		Sub    string `json:"sub"`
		Aud    any    `json:"aud"`
		SvcID  string `json:"svc_id"`
		Cnf    any    `json:"cnf"`
		Scope  string `json:"scope"`
		Client string `json:"client_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}
	if claims.Iss != expectedIssuer {
		return fmt.Errorf("iss=%q want %q", claims.Iss, expectedIssuer)
	}
	if claims.Sub != serviceSubject {
		return fmt.Errorf("sub=%q want %q", claims.Sub, serviceSubject)
	}
	if claims.SvcID != serviceSubject {
		return fmt.Errorf("svc_id=%q want %q", claims.SvcID, serviceSubject)
	}
	if claims.Client != clientID {
		return fmt.Errorf("client_id=%q want %q", claims.Client, clientID)
	}
	if !audienceMatches(claims.Aud, resourceAudience) {
		return fmt.Errorf("aud=%v want contains %q", claims.Aud, resourceAudience)
	}
	if claims.Cnf != nil {
		return fmt.Errorf("cnf=%v want nil (plain bearer request, no DPoP / mTLS)", claims.Cnf)
	}
	log.Printf("[probe] access_token sub=%q aud=%v iss=%q svc_id=%q",
		claims.Sub, claims.Aud, claims.Iss, claims.SvcID)
	return nil
}

// audienceMatches accepts either a single-string aud claim or a JSON
// array (RFC 7519 §4.1.3) and reports whether want appears in the set.
func audienceMatches(aud any, want string) bool {
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
