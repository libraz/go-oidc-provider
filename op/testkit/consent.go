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

// ApproveAllScopes is the empty approved-scopes payload.
//
// Deprecated: an empty submission records an approval of nothing, not
// an approval of everything — a consent screen the user answered by
// clearing every box is a decision the OP honours. Use
// [ApprovedScopesFrom] to build the payload that approves what the
// screen actually presented.
const ApproveAllScopes = ""

// ApprovedScopesFrom returns the approved-scopes payload that approves
// every scope the consent prompt presented, read out of the envelope
// [IsConsentPrompt] returned.
//
// Building the payload from the envelope rather than from the
// authorization request is what makes it an approval: the OP decides
// which scopes reach the screen, and a test that submits the request's
// scope list instead would approve entries the user was never shown.
// The member names are the ones the JSON driver writes for
// [interaction.ConsentScopePromptData]; the lowercase spellings are
// accepted too so a driver that adds tags later keeps working.
func ApprovedScopesFrom(tb testing.TB, envelope map[string]any) string {
	tb.Helper()
	data, _ := envelope["data"].(map[string]any)
	raw, _ := pick(data, "Scopes", "scopes").([]any)
	if len(raw) == 0 {
		tb.Fatalf("testkit: consent envelope presented no scopes: %v", envelope)
	}
	names := make([]string, 0, len(raw))
	for _, entry := range raw {
		switch v := entry.(type) {
		case string:
			names = append(names, v)
		case map[string]any:
			if name, ok := pick(v, "Name", "name").(string); ok && name != "" {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		tb.Fatalf("testkit: consent envelope carried %d scope rows but no names: %v", len(raw), envelope)
	}
	return strings.Join(names, " ")
}

// pick returns the first member present under any of keys. The JSON
// driver serialises the prompt payload without struct tags, so its
// members arrive exported; readers accept both spellings.
func pick(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}

// IsConsentPrompt reports whether resp is a JSON envelope from the
// built-in consent screen. The test-side dispatcher
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
	//nolint:gosec // G124: AddCookie serialises name=value only; Set-Cookie attributes never travel on a request.
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("testkit: POST consent: %v", err)
	}
	return resp
}
