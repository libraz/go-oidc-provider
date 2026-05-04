//go:build example

// Example 30-device-code-cli demonstrates the RFC 8628
// device-authorization grant: an OP with [op.WithDeviceCodeGrant]
// enabled and an in-process simulated CLI client that drives the
// terminal-side ceremony — POST /device_authorization, render the
// user_code on stdout, poll /token honouring authorization_pending
// and slow_down, and decode the resulting id_token. The realistic
// use case is a TV / IoT / CLI tool that needs OAuth tokens but
// cannot host an HTTP listener for redirect-URI delivery, so the
// user authorises the device on a secondary device (phone /
// laptop) by typing a short user_code into a verification page.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/30-device-code-cli
//
// The example is self-contained: a single binary stands up the OP
// on :8089, runs an in-process self-verify probe against an
// httptest server first, then drives the user-facing CLI flow
// against the listener. End-to-end runtime is under five seconds.
//
// What the run prints, in order:
//
//  1. "self-verify: device-code round-trip OK" — the in-process
//     probe asserted POST /device_authorization → Approve →
//     POST /token (grant_type=device_code) yields an access_token.
//  2. "[op] listening on 127.0.0.1:8089" — the OP banner.
//  3. The boxed user_code panel the CLI would render on a TV
//     screen; alongside, the verification_uri_complete shortcut.
//  4. "[cli] poll #N -> authorization_pending" or
//     "[cli] poll #N -> 200 OK" — the polling loop. The first poll
//     observes the pending record while a goroutine simulates the
//     user approving the request on a second device.
//  5. "[cli] id_token sub=user-alice aud=cli-tool" — the decoded
//     claims confirming the round-trip.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Verification page: this example fakes the user's browser
//     approval by calling DeviceCodeStore.Approve directly. A real
//     deployment renders a verification page (mounted by the
//     embedder, not the library) that authenticates the user, asks
//     them to type the user_code, displays the requested scopes,
//     and calls Approve / Deny on the substore via an
//     embedder-owned handler.
//   - Brute-force lockout: the verification page is responsible
//     for IncrementUserCodeStrike + Deny("user_code_lockout") on
//     repeated mismatches; the library ships the substore method
//     but not the policy.
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
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr   = "127.0.0.1:8089"
	issuer   = "http://" + opAddr
	clientID = "cli-tool"

	// demoSubject is the OP-internal stable identifier the simulated
	// browser approval stamps on the device-code record. The id_token
	// "sub" claim mirrors this value.
	demoSubject = "user-alice"

	// deviceCodeGrantURN is the RFC 8628 §3.4 grant_type wire form.
	deviceCodeGrantURN = "urn:ietf:params:oauth:grant-type:device_code"

	// Default endpoint paths relative to the library default mount
	// prefix ("/oidc"). The CLI side uses these absolute paths to
	// build wire requests.
	deviceAuthPath = "/oidc/device_authorization"
	tokenPath      = "/oidc/token"

	// Demo cadence values. The CLI honours the OP's advertised
	// `interval` (5s by default per RFC 8628 §3.5 / ADR 0031 §Q3),
	// so the approval is scheduled to land between the first and
	// second poll and the timeout sits comfortably above one full
	// poll cycle. A real CLI MUST observe the advertised interval
	// or the OP escalates to slow_down and doubles its expectation
	// for every subsequent offence.
	demoApprovalDelay = 1500 * time.Millisecond
	demoPollTimeout   = 30 * time.Second

	// fallbackPollInterval is the cadence the CLI uses if the OP's
	// /device_authorization response carried a zero or missing
	// interval. The library default is 5s; mirroring it keeps a
	// demo that hits an unusual configuration from busy-spinning.
	fallbackPollInterval = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("device-code example failed", slog.String("err", err.Error()))
		fmt.Fprintf(os.Stderr, "✗ %s\n", err.Error())
		os.Exit(1)
	}
}

// run owns the example's two-phase shape: a self-verify probe
// against an httptest server (so a regression in the public API
// surfaces before any listener binds) followed by the user-facing
// CLI flow against a real :8089 listener. Errors propagate to
// main() which prints a single-line "✗ <reason>" and exits 1.
func run(logger *slog.Logger) error {
	if err := selfVerify(logger); err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	fmt.Println("✓ self-verify: device-code round-trip OK")
	return runCLIFlow(logger)
}

// buildProvider constructs a fresh [op.Provider] + paired
// [inmem.Store] for one example run. Both the self-verify probe
// and the CLI flow call this helper so they exercise an identical
// configuration path; the only difference between the two phases
// is the listener that sits in front of the handler.
func buildProvider() (http.Handler, *inmem.Store, error) {
	keys := devkeys.MustEphemeral("device-code-1")
	st := inmem.New()
	// Seed the user record so the access token's sub/profile claims
	// resolve cleanly. The simulated browser approval calls
	// DeviceCodeStore.Approve with this subject directly.
	st.PutUser(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Alice",
			"email": "alice@example.com",
		},
	})
	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithDeviceCodeGrant(),
		op.WithStaticClients(op.PublicClient{
			ID: clientID,
			// Device-code clients never visit /authorize so
			// RedirectURIs may stay empty. The grant set is
			// overridden so the registration only carries the
			// device_code URN — embedders that also need
			// authorization_code add it back here.
			GrantTypes: []string{deviceCodeGrantURN},
			Scopes:     []string{"openid", "profile", "offline_access"},
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, st, nil
}

// selfVerify drives an in-process round-trip against an httptest
// server. It:
//
//  1. Builds a fresh OP via [buildProvider].
//  2. POSTs /device_authorization with client_id=cli-tool.
//  3. Asserts 200 + non-empty device_code + non-empty user_code.
//  4. Calls DeviceCodeStore.Approve directly (the substore method
//     a verification page would invoke after the user clicks
//     "Allow").
//  5. POSTs /token with grant_type=device_code.
//  6. Asserts 200 + non-empty access_token.
//
// On any failure the function returns an error; main() prints
// "✗ self-verify: <reason>" and exits 1 before any listener
// binds.
func selfVerify(logger *slog.Logger) error {
	provider, st, err := buildProvider()
	if err != nil {
		return err
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authz, err := postDeviceAuthorization(ctx, srv.URL+deviceAuthPath)
	if err != nil {
		return fmt.Errorf("device_authorization: %w", err)
	}
	if authz.DeviceCode == "" || authz.UserCode == "" {
		return errors.New("device_authorization response missing device_code or user_code")
	}
	logger.Debug("self-verify authorized", slog.String("user_code", authz.UserCode))

	if err := st.DeviceCodes().Approve(ctx, authz.DeviceCode, demoSubject); err != nil {
		return fmt.Errorf("approve: %w", err)
	}

	tok, err := postTokenOnce(ctx, srv.URL+tokenPath, authz.DeviceCode)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	if tok.AccessToken == "" {
		return errors.New("token response missing access_token")
	}
	return nil
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
	if err := waitForIssuer(ctx, issuer); err != nil {
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

// simulateBrowserApproval drives the same store seam an authentication
// device's "approve" button would: it waits for [demoApprovalDelay] so
// the polling loop observes at least one authorization_pending response
// first, then calls [store.DeviceCodeStore.Approve]. Production
// embedders never call Approve from a goroutine — they reach it from
// the user's authenticated browser session.
func simulateBrowserApproval(ctx context.Context, st store.Store, authz *authorizationResponse, logger *slog.Logger) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(demoApprovalDelay):
	}
	if err := st.DeviceCodes().Approve(context.Background(), authz.DeviceCode, demoSubject); err != nil {
		logger.Warn("simulated approval failed", slog.String("err", err.Error()))
		return
	}
	fmt.Printf("[browser] user approved user_code=%s subject=%s\n", authz.UserCode, demoSubject)
}

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
// advertised interval, slow_down continues with a doubled
// interval, anything else terminates. The seed cadence comes from
// the OP's /device_authorization response so a CLI cannot
// accidentally undercut the advertised value.
func pollToken(ctx context.Context, authz *authorizationResponse) (*tokenResponse, error) {
	interval := time.Duration(authz.Interval) * time.Second
	if interval <= 0 {
		interval = fallbackPollInterval
	}
	for attempt := 1; ; attempt++ {
		tok, retry, nextInterval, err := pollTokenOnce(ctx, issuer+tokenPath, authz.DeviceCode, attempt)
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
// zero only when the OP returned slow_down, in which case the
// caller doubles its sleep before the next poll.
func pollTokenOnce(ctx context.Context, endpoint, deviceCode string, attempt int) (tok *tokenResponse, retry bool, nextInterval time.Duration, err error) {
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
			// Double the next sleep per RFC 8628 §3.5. The
			// caller seeded its interval from the §3.2 response;
			// returning a positive duration here makes the
			// loop adopt the doubled value before the next poll.
			return nil, true, fallbackPollInterval * 2, nil
		default:
			return nil, false, 0, fmt.Errorf("poll #%d terminal error %q: %s", attempt, wire, string(raw))
		}
	default:
		return nil, false, 0, fmt.Errorf("poll #%d unexpected status=%d body=%s", attempt, status, string(raw))
	}
}

// doTokenPost is the shared HTTP plumbing for [postTokenOnce] and
// [pollTokenOnce]. It builds the form body, fires the request, and
// returns the response + body bytes for the caller to classify.
// doTokenPost POSTs a single device-code /token request and returns
// the response status and body. The body is closed before the helper
// returns so callers can branch on status without owning the
// io.Closer.
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

// waitForIssuer polls the discovery document until it returns 200
// or ctx is cancelled. The OP boots in the same process as the
// CLI, so the discovery probe doubles as a readiness gate before
// the first /device_authorization POST.
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
