//go:build example

// Example 31-ciba-pos demonstrates a complete OpenID Connect Client-
// Initiated Backchannel Authentication Flow (CIBA Core 1.0) round-trip
// in poll mode: an OP with [op.WithCIBA] enabled, a [op.HintResolver]
// that maps a login_hint to a stable subject, and an in-process
// Relying Party that posts to /bc-authorize, simulates the embedder's
// authentication device approving the request, and polls /token until
// the OP issues an access_token + id_token.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/31-ciba-pos
//
// The example is self-contained: a single binary stands up the OP on
// :8080, drives the CIBA wire protocol against itself, decodes the
// resulting id_token, and exits 0. End-to-end runtime is under five
// seconds (one second between polls).
//
// What the run prints, in order:
//
//  1. "[op] listening on :8080" — the OP banner.
//  2. "[rp] POST /oidc/bc-authorize" — the relying party initiates
//     the backchannel request with login_hint=alice.
//  3. "[rp] auth_req_id=..." — the OP's response payload.
//  4. "[device] user approved auth_req_id=..." — the simulated
//     authentication device flips the record from Pending to Approved.
//     A real deployment fires this transition from a push notification
//     callback handler.
//  5. "[rp] poll #N -> 400 authorization_pending" or
//     "[rp] poll #N -> 200 OK" — the polling loop. The first poll
//     races the device approval and may land as authorization_pending;
//     the second poll observes the approved record and the OP issues
//     tokens.
//  6. "[rp] id_token sub=user-alice aud=ciba-poll-demo" — the decoded
//     id_token claims confirming the round-trip.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - HintResolver: the demo maps a single hardcoded login_hint to a
//     subject. Production resolvers query the embedder's user store
//     and MUST return [op.ErrUnknownCIBAUser] for unknown hints so the
//     OP emits unknown_user_id rather than login_required.
//   - Authentication device: the demo flips the record directly via
//     the substore's Approve method to keep the example single-binary.
//     Production embedders trigger Approve from the user's
//     authentication device callback (a push-notification handler, an
//     IVR confirmation endpoint, etc.) — never from the OP process.
//   - Client secret: high-entropy random secret rotated through the
//     embedder's secret manager in production.
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
	"os"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr       = ":8080"
	issuer       = "http://127.0.0.1" + opAddr
	clientID     = "ciba-poll-demo"
	clientSecret = "ciba-poll-demo-secret-rotate-me"

	// loginHint is the deterministic identifier the demo RP supplies
	// at /bc-authorize. The HintResolver maps it to demoSubject; any
	// other value resolves to op.ErrUnknownCIBAUser.
	loginHint   = "alice"
	demoSubject = "user-alice"

	cibaGrantURN = "urn:openid:params:grant-type:ciba"

	bcAuthorizePath = "/oidc/bc-authorize"
	tokenPath       = "/oidc/token"

	pollInterval = 1 * time.Second
	pollTimeout  = 10 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("ciba example failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	keys := devkeys.MustEphemeral("ciba-poll-1")

	st := inmem.New()

	resolver := op.HintResolverFunc(func(_ context.Context, _ op.HintKind, value string) (string, error) {
		if value == loginHint {
			return demoSubject, nil
		}
		return "", op.ErrUnknownCIBAUser
	})

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithCIBA(
			op.WithCIBAHintResolver(resolver),
			op.WithCIBAPollInterval(pollInterval),
		),
		op.WithStaticClients(op.ConfidentialClient{
			ID:         clientID,
			Secret:     clientSecret,
			AuthMethod: op.AuthClientSecretBasic,
			// CIBA clients never visit /authorize; RedirectURIs may be
			// empty. The grant set is overridden so the registration
			// only carries the CIBA URN — embedders that also need
			// authorization_code add it back here.
			GrantTypes: []string{cibaGrantURN},
			Scopes:     []string{"openid", "profile"},
		}),
	)
	if err != nil {
		return fmt.Errorf("ciba example: op.New: %w", err)
	}

	srv := &http.Server{
		Addr:              opAddr,
		Handler:           provider,
		ReadHeaderTimeout: 10 * time.Second,
	}
	listenErr := make(chan error, 1)
	go func() {
		logger.Info("op listening", slog.String("addr", opAddr), slog.String("issuer", issuer))
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

	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()
	if err := waitForIssuer(ctx, issuer); err != nil {
		return fmt.Errorf("ciba example: wait for issuer: %w", err)
	}

	authReqID, err := postBackchannelAuthorize(ctx, logger)
	if err != nil {
		return fmt.Errorf("ciba example: bc-authorize: %w", err)
	}
	logger.Info("rp received auth_req_id", slog.String("auth_req_id", authReqID))

	// Simulate the embedder's authentication device flipping the
	// record from Pending to Approved. A real deployment performs
	// this transition from the user's authentication device callback.
	if err := st.CIBARequests().Approve(ctx, authReqID, demoSubject); err != nil {
		return fmt.Errorf("ciba example: simulate device approve: %w", err)
	}
	logger.Info("device approved auth_req_id",
		slog.String("auth_req_id", authReqID),
		slog.String("subject", demoSubject))

	idToken, err := pollToken(ctx, logger, authReqID)
	if err != nil {
		return fmt.Errorf("ciba example: poll: %w", err)
	}

	sub, aud, err := decodeIDTokenClaims(idToken)
	if err != nil {
		return fmt.Errorf("ciba example: decode id_token: %w", err)
	}
	logger.Info("id_token decoded", slog.String("sub", sub), slog.String("aud", aud))

	select {
	case err := <-listenErr:
		if err != nil {
			return fmt.Errorf("ciba example: op listener: %w", err)
		}
	default:
	}
	return nil
}

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
