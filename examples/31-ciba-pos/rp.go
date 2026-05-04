//go:build example

// rp.go — POS-terminal-side Relying Party for example 31-ciba-pos.
//
// In a real CIBA deployment the POS terminal initiates the
// /bc-authorize POST, holds the auth_req_id, and polls /token until
// the user approves on a separate authentication device. This file
// drives the same wire shape against the in-process OP: the POST,
// the polling loop with §10.1 retry classification, the response
// decode, and the discovery-readiness probe the RP uses before its
// first request.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// postBackchannelAuthorize fires the CIBA Core §7.1 backchannel
// authentication request. The OP returns auth_req_id, expires_in,
// and interval; the demo only consumes auth_req_id because the
// HintResolver is deterministic and the polling loop uses its own
// cadence.
func postBackchannelAuthorize(ctx context.Context, logger *slog.Logger) (string, error) {
	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", loginHint)
	body := strings.NewReader(form.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+bcAuthorizePath, body)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	logger.Info("rp POST", slog.String("path", bcAuthorizePath), slog.String("login_hint", loginHint))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, string(raw))
	}
	var decoded struct {
		AuthReqID string `json:"auth_req_id"`
		ExpiresIn int64  `json:"expires_in"`
		Interval  int64  `json:"interval"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if decoded.AuthReqID == "" {
		return "", errors.New("auth_req_id missing from response")
	}
	return decoded.AuthReqID, nil
}

// pollToken drives the §10.1 token endpoint poll loop. The demo
// sleeps pollInterval between polls so the OP's slow_down detector
// does not engage; the loop returns the id_token of the first
// 200 OK response or an error if the loop times out / the OP
// returns a non-pending failure.
func pollToken(ctx context.Context, logger *slog.Logger, authReqID string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", cibaGrantURN)
	form.Set("auth_req_id", authReqID)
	encoded := form.Encode()

	for attempt := 1; ; attempt++ {
		idToken, retry, err := pollTokenOnce(ctx, logger, encoded, attempt)
		if err != nil {
			return "", err
		}
		if !retry {
			return idToken, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("context cancelled during sleep after attempt %d: %w", attempt, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// pollTokenOnce issues a single /token POST and classifies the
// response into one of three outcomes: a terminal success that yields
// an id_token (retry=false, idToken non-empty, err nil), a pending
// state that should retry (retry=true, idToken empty, err nil), or a
// terminal failure (err non-nil). Splitting the body of the loop
// keeps [pollToken] within the project's cognitive-complexity cap.
func pollTokenOnce(ctx context.Context, logger *slog.Logger, encodedForm string, attempt int) (idToken string, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+tokenPath, strings.NewReader(encodedForm))
	if err != nil {
		return "", false, fmt.Errorf("build poll #%d: %w", attempt, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("do poll #%d: %w", attempt, err)
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return "", false, fmt.Errorf("read poll #%d body: %w", attempt, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		token, err := decodeTokenResponse(raw, attempt)
		if err != nil {
			return "", false, err
		}
		logger.Info("rp poll succeeded", slog.Int("attempt", attempt))
		return token, false, nil
	case http.StatusBadRequest:
		wire := decodeWireError(raw)
		logger.Info("rp poll pending", slog.Int("attempt", attempt), slog.String("error", wire))
		if wire != "authorization_pending" && wire != "slow_down" {
			return "", false, fmt.Errorf("poll #%d returned terminal error %q: %s", attempt, wire, string(raw))
		}
		return "", true, nil
	default:
		return "", false, fmt.Errorf("poll #%d unexpected status=%d body=%s", attempt, resp.StatusCode, string(raw))
	}
}

// decodeTokenResponse parses the success-shape body the OP returns
// at /token. The caller already classified resp.StatusCode == 200, so
// the function only fails when the response is malformed.
func decodeTokenResponse(body []byte, attempt int) (string, error) {
	var decoded struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("decode poll #%d: %w", attempt, err)
	}
	if decoded.AccessToken == "" || decoded.IDToken == "" {
		return "", fmt.Errorf("poll #%d response missing tokens: %s", attempt, string(body))
	}
	return decoded.IDToken, nil
}

// decodeWireError pulls the OAuth 2.0 error code out of an RFC 6749
// §5.2 error envelope. The function silently returns "" on a malformed
// body; the caller treats an empty error as terminal.
func decodeWireError(body []byte) string {
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	return env.Error
}

// decodeIDTokenClaims pulls the sub and aud claims out of a JWS-
// formatted id_token without verifying the signature. The example is
// a single-process demo: the OP that signed the token is the same
// process that decodes it, so signature verification would only
// confirm what we already know. Production RPs MUST verify the
// signature against the OP's published JWKS.
func decodeIDTokenClaims(idToken string) (sub, aud string, err error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("id_token does not have three segments: got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
		// aud is either a single string or an array per RFC 7519 §4.1.3.
		// CIBA poll mode issues a single-audience token; the example
		// decodes the scalar shape and falls back to the array shape.
		Aud  any `json:"aud"`
		Auds []string
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("decode claims: %w", err)
	}
	switch v := claims.Aud.(type) {
	case string:
		aud = v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if aud != "" {
					aud += ","
				}
				aud += s
			}
		}
	}
	return claims.Sub, aud, nil
}

// waitForIssuer polls the discovery document until it returns 200 OK
// or ctx is cancelled. The OP boots in the same process as the RP, so
// the discovery probe doubles as a readiness gate before the
// /bc-authorize POST.
func waitForIssuer(ctx context.Context, iss string) error {
	endpoint := iss + "/.well-known/openid-configuration"
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout polling %s", endpoint)
		case <-tick.C:
		}
	}
}
