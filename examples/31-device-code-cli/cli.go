//go:build example

// cli.go — terminal-side CLI simulator for example 31-device-code-cli.
//
// This file holds everything that runs from the user's TV / IoT
// device: the §3.1 device_authorization POST, the §3.4 polling loop
// with §3.5 retry classification (authorization_pending / slow_down),
// the user_code panel render, and the post-success id_token claim
// decode. The CLI also waits for the OP listener's discovery document
// before its first request — that readiness gate is part of the CLI's
// startup ceremony, not the OP's wiring, so it is called from here.

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

	"github.com/libraz/go-oidc-provider/examples/internal/serve"
)

// authorizationResponse is the §3.2 device-authorization response
// envelope. Both the self-verify probe and the CLI flow decode the
// same shape.
type authorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// tokenResponse is the §3.4 success-shape body the OP returns on a
// poll that lands an approved record.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// runCLIFlow boots the OP on :8089, simulates the user's browser
// approval in a goroutine, and runs the CLI ceremony in the
// foreground. The function returns once the polling loop observes
// the access_token, the id_token has been decoded, and both have
// been printed.
func runCLIFlow(logger *slog.Logger) error {
	provider, st, err := buildProvider()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              opAddr,
		Handler:           provider,
		ReadHeaderTimeout: 10 * time.Second,
	}
	listenErr := make(chan error, 1)
	go func() {
		fmt.Printf("[op] listening on %s (issuer %s)\n", opAddr, issuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), demoPollTimeout)
	defer cancel()
	if err := serve.WaitForIssuer(ctx, issuer); err != nil {
		return fmt.Errorf("wait for issuer: %w", err)
	}

	authz, err := postDeviceAuthorization(ctx, issuer+deviceAuthPath)
	if err != nil {
		return fmt.Errorf("device_authorization: %w", err)
	}
	renderUserCodePanel(authz)

	// Simulate the user walking over to a phone, opening the
	// verification URI, signing in, and clicking "Allow" — after a
	// short delay so the polling loop observes at least one
	// authorization_pending response first.
	go simulateBrowserApproval(ctx, st, authz, logger)

	tok, err := pollToken(ctx, authz)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}
	fmt.Printf("[cli] access_token=%s... (truncated)\n", truncate(tok.AccessToken, 24))
	if tok.IDToken != "" {
		sub, aud, err := decodeIDTokenClaims(tok.IDToken)
		if err != nil {
			return fmt.Errorf("decode id_token: %w", err)
		}
		fmt.Printf("[cli] id_token sub=%s aud=%s\n", sub, aud)
	}

	select {
	case err := <-listenErr:
		if err != nil {
			return fmt.Errorf("op listener: %w", err)
		}
	default:
	}
	return nil
}

// postDeviceAuthorization fires the §3.1 request. The CLI presents
// only client_id (the public client has no secret) and the scopes
// it wants on the issued tokens.
func postDeviceAuthorization(ctx context.Context, endpoint string) (*authorizationResponse, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", "openid profile offline_access")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(raw))
	}
	var out authorizationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// pollToken drives the §3.4 polling loop. The loop honours the
// §3.5 wire codes: authorization_pending continues at the
// advertised interval, slow_down continues with the interval raised
// by five seconds, anything else terminates. The seed cadence comes
// from the OP's /device_authorization response so a CLI cannot
// accidentally undercut the advertised value.
//
// Five seconds is what §3.5 specifies, and matching it exactly is what
// keeps a client in step with the OP: an OP that raises its own bar by
// the same amount will never see a client that followed the
// instruction arrive early.
func pollToken(ctx context.Context, authz *authorizationResponse) (*tokenResponse, error) {
	interval := time.Duration(authz.Interval) * time.Second
	if interval <= 0 {
		interval = fallbackPollInterval
	}
	for attempt := 1; ; attempt++ {
		tok, retry, nextInterval, err := pollTokenOnce(ctx, issuer+tokenPath, authz.DeviceCode, attempt, interval)
		if err != nil {
			return nil, err
		}
		if !retry {
			return tok, nil
		}
		if nextInterval > 0 {
			interval = nextInterval
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled after attempt %d: %w", attempt, ctx.Err())
		case <-time.After(interval):
		}
	}
}

// postTokenOnce posts a single /token request with
// grant_type=device_code and returns the parsed success envelope.
// The self-verify probe uses this on the happy path; the CLI loop
// uses [pollTokenOnce] which classifies the §3.5 retry envelope.
func postTokenOnce(ctx context.Context, endpoint, deviceCode string) (*tokenResponse, error) {
	status, raw, err := doTokenPost(ctx, endpoint, deviceCode)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status=%d body=%s", status, string(raw))
	}
	var out tokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// pollTokenOnce posts a single /token request and classifies the
// response into a terminal success (retry=false, tok non-nil), a
// pending state that should retry (retry=true), or a terminal
// failure (err non-nil). The optional nextInterval value is non-
// zero only when the OP returned slow_down, and is the caller's
// current interval raised by the §3.5 increment. The caller passes
// its current value in because the ladder is cumulative: a second
// slow_down must raise the interval again rather than recompute the
// same value from a constant.
func pollTokenOnce(
	ctx context.Context,
	endpoint, deviceCode string,
	attempt int,
	current time.Duration,
) (tok *tokenResponse, retry bool, nextInterval time.Duration, err error) {
	status, raw, err := doTokenPost(ctx, endpoint, deviceCode)
	if err != nil {
		return nil, false, 0, fmt.Errorf("poll #%d: %w", attempt, err)
	}
	switch status {
	case http.StatusOK:
		var out tokenResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, false, 0, fmt.Errorf("poll #%d decode: %w", attempt, err)
		}
		fmt.Printf("[cli] poll #%d -> 200 OK\n", attempt)
		return &out, false, 0, nil
	case http.StatusBadRequest:
		wire := decodeWireError(raw)
		fmt.Printf("[cli] poll #%d -> %s\n", attempt, wire)
		switch wire {
		case "authorization_pending":
			return nil, true, 0, nil
		case "slow_down":
			// RFC 8628 §3.5: add five seconds to the polling
			// interval. Returning a positive duration here makes
			// the loop adopt it before the next poll.
			return nil, true, current + slowDownIncrement, nil
		default:
			return nil, false, 0, fmt.Errorf("poll #%d terminal error %q: %s", attempt, wire, string(raw))
		}
	default:
		return nil, false, 0, fmt.Errorf("poll #%d unexpected status=%d body=%s", attempt, status, string(raw))
	}
}

// doTokenPost is the shared HTTP plumbing for [postTokenOnce] and
// [pollTokenOnce]. It builds the form body, fires the request, and
// returns the response status and body bytes for the caller to
// classify. The body is closed before the helper returns so callers
// can branch on status without owning the io.Closer.
func doTokenPost(ctx context.Context, endpoint, deviceCode string) (int, []byte, error) {
	form := url.Values{}
	form.Set("grant_type", deviceCodeGrantURN)
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read body: %w", err)
	}
	return resp.StatusCode, raw, nil
}

// decodeWireError extracts the RFC 6749 §5.2 "error" field from a
// 400 response body. A malformed body collapses to "" so the caller
// treats the response as terminal.
func decodeWireError(body []byte) string {
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	return env.Error
}

// renderUserCodePanel prints the boxed display a TV / IoT device
// would render for the user. The shortcut URL with a pre-filled
// user_code is also printed; QR-code-capable devices render this
// value in machine-readable form so the user only scans.
func renderUserCodePanel(authz *authorizationResponse) {
	const width = 50
	border := "┌" + strings.Repeat("─", width-2) + "┐"
	footer := "└" + strings.Repeat("─", width-2) + "┘"
	visit := "  Visit: " + authz.VerificationURI
	code := "  Code:  " + authz.UserCode
	fmt.Println(border)
	fmt.Println(padLine(visit, width))
	fmt.Println(padLine(code, width))
	fmt.Println(footer)
	fmt.Printf("[cli] shortcut (pre-filled user_code): %s\n", authz.VerificationURIComplete)
	fmt.Printf("[cli] expires_in=%ds interval=%ds\n", authz.ExpiresIn, authz.Interval)
}

// padLine right-pads s with spaces to width-1 characters, then
// caps the line with a vertical box-drawing character on each side.
// The function counts runes (not bytes) so the box-drawing
// characters do not skew the alignment.
func padLine(s string, width int) string {
	const side = "│"
	runes := []rune(s)
	inner := width - 2
	if len(runes) > inner {
		runes = runes[:inner]
	}
	pad := inner - len(runes)
	return side + string(runes) + strings.Repeat(" ", pad) + side
}

// truncate shortens s to at most n runes for display. The function
// preserves rune boundaries so multi-byte tokens cannot display
// half a code point.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// decodeIDTokenClaims pulls the sub and aud claims out of a
// JWS-formatted id_token without verifying the signature. The
// example is a single-process demo: the OP that signed the token
// is the same process that decodes it, so signature verification
// would only confirm what we already know. Production CLI tools
// MUST verify the signature against the OP's published JWKS.
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
		// aud is either a single string or an array per RFC 7519
		// §4.1.3. The device-code grant issues a single-audience
		// id_token; the example decodes the scalar shape and falls
		// back to the array shape for forward compatibility.
		Aud any `json:"aud"`
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
