package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ApproveAllScopes is the canonical "approve every requested scope"
// payload tests submit to the built-in consent screen. Helper
// functions in this package use it as the default; tests that want
// to exercise scope dropping pass an explicit subset to
// [PostConsentApproval].
const ApproveAllScopes = ""

// IsConsentPrompt reports whether resp is a JSON envelope from the
// built-in [internal/authn/consent] screen. The test-side dispatcher
// branches on the result to decide whether the chain is complete or a
// consent submission is still pending.
//
// The function consumes resp.Body. Callers MUST treat the response as
// drained after the call; the function returns the parsed envelope so
// tests can read state_ref and the requested scope list without a
// second decode.
func IsConsentPrompt(resp *http.Response) (consent bool, envelope map[string]any, err error) {
	if resp == nil || resp.StatusCode != http.StatusOK {
		return false, nil, nil
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		return false, nil, nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("testkit: read consent response: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, nil, fmt.Errorf("testkit: decode consent response: %w", err)
	}
	if t, _ := out["type"].(string); t != "consent.scope" {
		return false, out, nil
	}
	return true, out, nil
}

// PostConsentApproval submits the built-in consent screen's
// approved_scopes form. csrf is the value of the __Host-oidc_csrf
// cookie attached to the prior /interaction response; stateRef is the
// state_ref the consent prompt embedded; origin is the Origin header
// the OP's CSRF middleware expects (typically the issuer URL).
//
// approved is the space-delimited approved-scope string. An empty
// string approves no scope (the chain rejects the submission unless
// no required scope was requested); pass [ApproveAllScopes] for the
// canonical "approve everything in the request" wire payload.
func PostConsentApproval(
	tb testing.TB,
	client *http.Client,
	interactionURL, origin, csrf, stateRef, approved string,
) *http.Response {
	tb.Helper()
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"approved_scopes": approved},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		tb.Fatalf("testkit: marshal consent submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("testkit: build consent request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("testkit: POST consent: %v", err)
	}
	return resp
}
